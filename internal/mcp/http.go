package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("MCP HTTP status %d", e.Status) }

type httpTransport struct {
	client  *http.Client
	url     string
	headers map[string]string
	mu      sync.Mutex
	session string
}

func newHTTP(endpoint string, headers map[string]string) (*httpTransport, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid MCP HTTP URL")
	}
	return &httpTransport{url: endpoint, headers: headers, client: &http.Client{
		Transport:     http.DefaultTransport.(*http.Transport).Clone(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("MCP redirects are not followed") },
	}}, nil
}

func headerValue(value string) string {
	unsafe := strings.TrimSpace(value) != value || (strings.HasPrefix(value, "=?base64?") && strings.HasSuffix(value, "?="))
	for _, c := range value {
		if c < 32 || c > 126 {
			unsafe = true
		}
	}
	if unsafe {
		return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
	}
	return value
}

func (h *httpTransport) request(ctx context.Context, method, version string, m Message, lastID string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, h.url, bytes.NewReader(m.Raw))
	if err != nil {
		return nil, errors.New("cannot construct MCP HTTP request")
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	if version == Latest && m.String("method") != "" {
		req.Header.Set("Mcp-Method", m.String("method"))
		var params map[string]json.RawMessage
		_ = json.Unmarshal(m.Fields["params"], &params)
		for _, key := range []string{"name", "uri"} {
			var value string
			if json.Unmarshal(params[key], &value) == nil {
				req.Header.Set("Mcp-Name", headerValue(value))
				break
			}
		}
	}
	if version != Latest {
		h.mu.Lock()
		session := h.session
		h.mu.Unlock()
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
	}
	resp, err := h.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("MCP HTTP connection failed")
	}
	if m.String("method") == "initialize" && resp.StatusCode == http.StatusOK {
		if session := resp.Header.Get("Mcp-Session-Id"); session != "" {
			for _, c := range session {
				if c < 33 || c > 126 {
					_ = resp.Body.Close()
					return nil, errors.New("invalid MCP session ID")
				}
			}
			h.mu.Lock()
			h.session = session
			h.mu.Unlock()
		}
	}
	return resp, nil
}

func (h *httpTransport) exchange(ctx context.Context, m Message, version string) (Message, error) {
	resp, err := h.request(ctx, http.MethodPost, version, m, "")
	if err != nil {
		return Message{}, err
	}
	lastID := ""
	for resumes := 0; ; resumes++ {
		if resp.StatusCode != http.StatusOK {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxMessage+1))
			_ = resp.Body.Close()
			if readErr == nil {
				if message, e := Parse(data); e == nil && message.Fields["error"] != nil {
					if message.Fields["id"] != nil && message.ID() != m.ID() {
						return Message{}, errors.New("MCP error response ID mismatch")
					}
					return message, nil
				}
			}
			return Message{}, &HTTPError{resp.StatusCode}
		}
		contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if contentType == "application/json" {
			data, err := io.ReadAll(io.LimitReader(resp.Body, MaxMessage+1))
			_ = resp.Body.Close()
			if err != nil {
				return Message{}, err
			}
			response, err := Parse(data)
			if err != nil {
				return Message{}, err
			}
			if response.ID() != m.ID() {
				return Message{}, errors.New("MCP response ID mismatch")
			}
			return response, nil
		}
		if contentType != "text/event-stream" {
			_ = resp.Body.Close()
			return Message{}, errors.New("unsupported MCP HTTP content type")
		}
		sse := newSSE(resp.Body)
		sse.id = lastID
		for {
			response, readErr := sse.next()
			if readErr != nil {
				err = readErr
				break
			}
			if response.String("method") != "" {
				if response.Fields["id"] != nil {
					if version == Latest {
						_ = resp.Body.Close()
						return Message{}, errors.New("modern MCP server sent a server-initiated request")
					}
					reject, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": response.Fields["id"], "error": map[string]any{"code": -32601, "message": "Client capability not supported"}})
					if e := h.notify(ctx, reject, version); e != nil {
						_ = resp.Body.Close()
						return Message{}, e
					}
				}
				continue
			}
			if response.ID() != m.ID() {
				_ = resp.Body.Close()
				return Message{}, errors.New("MCP SSE response ID mismatch")
			}
			_ = resp.Body.Close()
			return response, nil
		}
		_ = resp.Body.Close()
		lastID = sse.id
		if version == Latest || sse.id == "" || resumes >= 2 || !errors.Is(err, io.EOF) {
			return Message{}, err
		}
		timer := time.NewTimer(time.Duration(sse.retry) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Message{}, ctx.Err()
		case <-timer.C:
		}
		resp, err = h.request(ctx, http.MethodGet, version, Message{}, sse.id)
		if err != nil {
			return Message{}, err
		}
	}
}

func (h *httpTransport) notify(ctx context.Context, m Message, version string) error {
	resp, err := h.request(ctx, http.MethodPost, version, m, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return &HTTPError{resp.StatusCode}
	}
	return nil
}

func (h *httpTransport) close(version string) error {
	defer h.client.CloseIdleConnections()
	h.mu.Lock()
	session := h.session
	h.mu.Unlock()
	if version == Latest || session == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := h.request(ctx, http.MethodDelete, version, Message{}, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != 405 && resp.StatusCode != 404 {
		return &HTTPError{resp.StatusCode}
	}
	return nil
}
