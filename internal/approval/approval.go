package approval

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/RamazanKara/fencepost/internal/policy"
)

type Request struct {
	ID        string          `json:"id"`
	Time      int64           `json:"time"`
	Session   string          `json:"session"`
	Server    string          `json:"server"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	User      string          `json:"user,omitempty"`
	Groups    []string        `json:"groups,omitempty"`
	Client    string          `json:"client,omitempty"`
}

type Response struct {
	Decision string `json:"decision"`
}
type Address struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func Token() string { var b [32]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

func Signature(secret, data []byte) string {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write(data)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func Ask(ctx context.Context, config policy.Approval, request Request) string {
	timeout, _ := time.ParseDuration(config.Timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request.ID, request.Time = Token(), time.Now().Unix()
	data, err := json.Marshal(request)
	if err != nil || len(data) > 64<<10 {
		return "deny"
	}
	endpoint := config.WebhookURL
	var token, secret string
	if config.Mode == "local" {
		data, err := os.ReadFile(config.LocalFile)
		var address Address
		if err != nil || json.Unmarshal(data, &address) != nil || !loopbackURL(address.URL) || len(address.Token) != 64 {
			return "deny"
		}
		endpoint, token = address.URL+"/request", address.Token
	} else {
		secret = os.Getenv(config.HMACSecretEnv)
		if len(secret) < 32 {
			return "deny"
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return "deny"
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if secret != "" {
		req.Header.Set("X-Fencepost-Signature", Signature([]byte(secret), data))
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return "deny"
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 || response.StatusCode != 200 {
		return "deny"
	}
	if secret != "" && !hmac.Equal([]byte(response.Header.Get("X-Fencepost-Signature")), []byte(Signature([]byte(secret), append([]byte(request.ID+"\n"), body...)))) {
		return "deny"
	}
	var result Response
	if json.Unmarshal(body, &result) != nil {
		return "deny"
	}
	if result.Decision == "allow" || (token != "" && result.Decision == "always") {
		return result.Decision
	}
	return "deny"
}

func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.IsLoopback()
}

func Listen(address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || ipErr != nil || !ip.IsLoopback() {
		return nil, errors.New("listen address must be a literal loopback IP and port")
	}
	return net.Listen("tcp", address)
}

func Serve(ctx context.Context, address, filename string, out io.Writer) error {
	listener, err := Listen(address)
	if err != nil {
		return err
	}
	defer listener.Close()
	channel := New("http://"+listener.Addr().String(), Token())
	data, _ := json.Marshal(Address{channel.origin, channel.token})
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("approval descriptor already exists or cannot be created")
	}
	defer os.Remove(filename)
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	_, _ = io.WriteString(out, channel.origin+"/?token="+channel.token+"\n")
	server := &http.Server{Handler: channel, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func bearer(r *http.Request) string {
	if token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); token != "" {
		return token
	}
	return r.URL.Query().Get("token")
}
