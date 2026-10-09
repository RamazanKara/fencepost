package rulebundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

//go:embed public-key.txt
var publicKey string

//go:embed bundle.json
var bundled []byte

type Bundle struct {
	Version  uint64   `json:"version"`
	Patterns []string `json:"patterns"`
	compiled []*regexp.Regexp
}

type envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

var current atomic.Pointer[Bundle]

func init() {
	b, err := Verify(bundled, key())
	if err != nil {
		panic("invalid embedded rules bundle")
	}
	current.Store(b)
}

func key() ed25519.PublicKey {
	b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	return b
}

func strict(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}

func Verify(data []byte, public ed25519.PublicKey) (*Bundle, error) {
	var signed envelope
	if len(data) > 1<<20 || strict(data, &signed) != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, signed.Payload, signed.Signature) {
		return nil, errors.New("rules bundle signature verification failed")
	}
	var b Bundle
	if strict(signed.Payload, &b) != nil || b.Version == 0 || len(b.Patterns) == 0 || len(b.Patterns) > 256 {
		return nil, errors.New("invalid rules bundle")
	}
	for _, pattern := range b.Patterns {
		if len(pattern) == 0 || len(pattern) > 4096 {
			return nil, errors.New("invalid rules pattern size")
		}
		r, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errors.New("invalid rules expression")
		}
		b.compiled = append(b.compiled, r)
	}
	return &b, nil
}

func Version() uint64 { return current.Load().Version }

func Match(text string) bool {
	for _, r := range current.Load().compiled {
		if r.MatchString(text) {
			return true
		}
	}
	return false
}

func Path() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "fencepost", "rules.json"), nil
}

func Load() error {
	path, err := Path()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	b, err := Verify(data, key())
	if err != nil {
		return err
	}
	builtin, _ := Verify(bundled, key())
	if b.Version < builtin.Version {
		return errors.New("installed rules are older than embedded rules")
	}
	current.Store(b)
	return nil
}

func Update(ctx context.Context, endpoint, path string) (uint64, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return 0, errors.New("rules update requires an HTTPS bundle URL")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, errors.New("cannot fetch rules bundle")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("rules endpoint returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return 0, err
	}
	return install(path, data, key(), Version())
}

func install(path string, data []byte, public ed25519.PublicKey, minimum uint64) (uint64, error) {
	b, err := Verify(data, public)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return 0, err
	}
	guard, err := os.OpenFile(path+".updating", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, errors.New("another rules update is in progress; check for a stale .updating file after an interrupted update")
	}
	if err := guard.Close(); err != nil {
		_ = os.Remove(path + ".updating")
		return 0, err
	}
	defer os.Remove(path + ".updating")
	old, err := os.ReadFile(path)
	if err == nil {
		previous, err := Verify(old, public)
		if err != nil {
			return 0, err
		}
		if previous.Version > minimum {
			minimum = previous.Version
		}
		if b.Version == previous.Version && !bytes.Equal(old, data) {
			return 0, errors.New("rules version already has different content")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if b.Version < minimum {
		return 0, errors.New("rules rollback rejected")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".rules-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return 0, err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return 0, err
	}
	return b.Version, nil
}
