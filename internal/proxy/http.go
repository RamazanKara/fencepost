package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/approval"
	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/mcp"
	"github.com/RamazanKara/fencepost/internal/policy"
)

type HTTP struct {
	base     *Engine
	upstream string
	client   *http.Client
	headers  map[string]string
	mu       sync.Mutex
	sessions map[string]*Engine
}

func NewHTTP(p *policy.Policy, log *audit.Log, server, lockPath, upstream string, headers map[string]string) (*HTTP, error) {
	if !policy.SafeEndpoint(upstream) {
		return nil, errors.New("upstream must use HTTPS or literal loopback HTTP")
	}
	e, err := New(p, log, server, lockPath)
	if err != nil {
		return nil, err
	}
	return &HTTP{base: e, upstream: upstream, headers: headers, sessions: map[string]*Engine{}, client: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (h *HTTP) Close() { h.client.CloseIdleConnections() }

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != "" {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}
	if r.Method != "POST" && r.Method != "GET" && r.Method != "DELETE" {
		w.WriteHeader(405)
		return
	}
	e := h.base
	session := r.Header.Get("Mcp-Session-Id")
	if session != "" {
		h.mu.Lock()
		e = h.sessions[session]
		h.mu.Unlock()
		if e == nil {
			http.Error(w, "Unknown session", 404)
			return
		}
	}
	var message mcp.Message
	var request *Request
	var body []byte
	if r.Method == "POST" {
		data, err := io.ReadAll(io.LimitReader(r.Body, mcp.MaxMessage+1))
		if err != nil {
			http.Error(w, "Invalid body", 400)
			return
		}
		message, err = mcp.Parse(data)
		if err != nil {
			_ = e.record("request", "invalid", "", "deny", "framing", nil)
			http.Error(w, "Invalid MCP message", 400)
			return
		}
		if message.String("method") == "initialize" {
			if session != "" {
				http.Error(w, "Session already initialized", 400)
				return
			}
			e, err = New(h.base.Policy, h.base.Log, h.base.ServerName, h.base.lockPath)
			if err != nil {
				http.Error(w, "Pin baseline unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		request, err = e.Begin(r.Context(), message)
		if err != nil {
			writeFailure(w, message, -32600, "Fencepost could not accept this request.")
			return
		}
		denied, err := e.Check(request)
		if err != nil {
			writeFailure(w, message, -32603, "Fencepost audit unavailable.")
			return
		}
		if denied != nil {
			if message.Fields["id"] == nil {
				w.WriteHeader(202)
			} else {
				writeJSON(w, *denied)
			}
			return
		}
		body = request.Message.Raw
	}
	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, h.upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Invalid upstream", http.StatusBadGateway)
		return
	}
	copyHeaders(upstream.Header, r.Header)
	for key, value := range h.headers {
		upstream.Header.Set(key, value)
	}
	upstream.Header.Del("Content-Length")
	upstream.Header.Del("Accept-Encoding")
	if request != nil && message.String("method") != "" {
		upstream.Header.Set("Mcp-Method", message.String("method"))
	}
	response, err := h.client.Do(upstream)
	if err != nil {
		e.Forget(message)
		writeFailure(w, message, -32002, "Upstream server unavailable.")
		return
	}
	defer response.Body.Close()
	if id := response.Header.Get("Mcp-Session-Id"); id != "" && message.String("method") == "initialize" && response.StatusCode < 300 {
		h.mu.Lock()
		if len(h.sessions) >= 256 || h.sessions[id] != nil {
			h.mu.Unlock()
			e.Forget(message)
			http.Error(w, "Session unavailable", http.StatusServiceUnavailable)
			return
		}
		h.sessions[id] = e
		h.mu.Unlock()
	}
	if r.Method == "DELETE" && response.StatusCode < 300 {
		h.mu.Lock()
		delete(h.sessions, session)
		h.mu.Unlock()
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	w.Header().Del("ETag")
	if response.StatusCode == 202 || response.StatusCode == 204 {
		w.WriteHeader(response.StatusCode)
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		e.Forget(message)
		w.Header().Del("Location")
		w.WriteHeader(response.StatusCode)
		return
	}
	contentType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	switch contentType {
	case "text/event-stream":
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(response.StatusCode)
		err = relaySSE(response.Body, w, func(m mcp.Message) (mcp.Message, error) { return e.Server(m) })
		e.mu.Lock()
		pending := e.pending[message.ID()] != nil
		e.mu.Unlock()
		if (err != nil || pending) && r.Context().Err() == nil && message.Fields["id"] != nil {
			e.Forget(message)
			failure := Error(message, -32002, "Upstream stream disconnected or was invalid.")
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", failure.Raw)
		}
	case "application/json":
		data, err := io.ReadAll(io.LimitReader(response.Body, mcp.MaxMessage+1))
		if err != nil {
			e.Forget(message)
			writeFailure(w, message, -32002, "Upstream response interrupted.")
			return
		}
		m, err := mcp.Parse(data)
		if err == nil && m.String("method") == "" && message.Fields["id"] != nil && m.ID() != message.ID() {
			err = errors.New("upstream response ID mismatch")
		}
		if err == nil {
			m, err = e.Server(m)
		}
		if err != nil {
			e.Forget(message)
			writeFailure(w, message, -32603, "Invalid upstream response or audit unavailable.")
			return
		}
		writeJSON(w, m)
	default:
		e.Forget(message)
		writeFailure(w, message, -32603, "Unsupported upstream response type.")
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
	for _, name := range strings.Split(src.Get("Connection"), ",") {
		dst.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		dst.Del(name)
	}
}

func writeJSON(w http.ResponseWriter, m mcp.Message) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(m.Raw)
}

func writeFailure(w http.ResponseWriter, m mcp.Message, code int, text string) {
	if m.Fields["id"] == nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	writeJSON(w, Error(m, code, text))
}

// relaySSE retains comments, event IDs, retry values, and empty events. Only one
// event is buffered, so indefinite GET streams and progress events keep flowing.
func relaySSE(in io.Reader, out io.Writer, transform func(mcp.Message) (mcp.Message, error)) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), mcp.MaxMessage+1)
	scanner.Split(sseLine)
	var lines []string
	size := 0
	first := true
	flush := func() error {
		var data []string
		for _, line := range lines {
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(line[5:], " "))
			} else if line == "data" {
				data = append(data, "")
			}
		}
		var replacement []byte
		if len(data) > 0 && strings.TrimSpace(strings.Join(data, "\n")) != "" {
			m, err := mcp.Parse([]byte(strings.Join(data, "\n")))
			if err != nil {
				return err
			}
			m, err = transform(m)
			if err != nil {
				return err
			}
			replacement = m.Raw
		}
		written := false
		for _, line := range lines {
			if replacement != nil && (strings.HasPrefix(line, "data:") || line == "data") {
				if !written {
					if _, err := fmt.Fprintf(out, "data: %s\n", replacement); err != nil {
						return err
					}
					written = true
				}
			} else {
				if _, err := fmt.Fprintln(out, line); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
		if f, ok := out.(http.Flusher); ok {
			f.Flush()
		}
		lines, size = nil, 0
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		size += len(line) + 1
		if size > mcp.MaxMessage {
			return errors.New("SSE event exceeds limit")
		}
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
		} else {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(lines) > 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func sseLine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		if data[i] == '\r' && i+1 == len(data) && !atEOF {
			return 0, nil, nil
		}
		n := i + 1
		if data[i] == '\r' && n < len(data) && data[n] == '\n' {
			n++
		}
		return n, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func ServeHTTP(ctx context.Context, address string, h *HTTP) error {
	listener, err := approval.Listen(address)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer h.Close()
	host := listener.Addr().String()
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "Unexpected host", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})}
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
