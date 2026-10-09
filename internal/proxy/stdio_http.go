package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/mcp"
)

type StdioHTTP struct {
	ctx      context.Context
	cancel   context.CancelFunc
	in       *io.PipeWriter
	writes   sync.Mutex
	mu       sync.Mutex
	pending  map[string]chan mcp.Message
	contexts map[string]context.Context
	events   chan mcp.Message
	stream   bool
	done     chan struct{}
	once     sync.Once
}

func NewStdioHTTP(ctx context.Context, e *Engine, s clientconfig.Server) *StdioHTTP {
	ctx, cancel := context.WithCancel(ctx)
	input, in := io.Pipe()
	output, out := io.Pipe()
	h := &StdioHTTP{ctx: ctx, cancel: cancel, in: in, pending: map[string]chan mcp.Message{}, events: make(chan mcp.Message, 64), done: make(chan struct{})}
	h.contexts = map[string]context.Context{}
	e.requestContext = func(m mcp.Message) context.Context {
		h.mu.Lock()
		defer h.mu.Unlock()
		if request := h.contexts[m.ID()]; request != nil {
			return request
		}
		// A disconnected HTTP request may still be queued in the stdio pipe.
		expired, cancel := context.WithCancel(ctx)
		cancel()
		return expired
	}
	go func() {
		defer cancel()
		defer output.Close()
		reader := bufio.NewReader(output)
		for {
			m, err := mcp.ReadFrame(reader)
			if err != nil {
				return
			}
			h.mu.Lock()
			ch := h.pending[m.ID()]
			if m.String("method") != "" {
				ch = h.events
				if !h.stream {
					for _, active := range h.pending {
						ch = active
						break
					}
				}
			}
			if ch != nil {
				select {
				case ch <- m:
				default:
					h.mu.Unlock()
					return
				}
			}
			h.mu.Unlock()
		}
	}()
	go func() {
		defer close(h.done)
		defer out.Close()
		defer input.Close()
		_ = Stdio(ctx, e, s, input, out)
	}()
	return h
}

func (h *StdioHTTP) Close() {
	h.once.Do(func() { h.cancel(); _ = h.in.Close(); <-h.done })
}

func (h *StdioHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Mcp-Session-Id") != "" {
		http.Error(w, "Unknown session", 404)
		return
	}
	select {
	case <-h.ctx.Done():
		http.Error(w, "Upstream disconnected", http.StatusServiceUnavailable)
		return
	default:
	}
	if r.Method == "GET" {
		h.mu.Lock()
		if h.stream {
			h.mu.Unlock()
			http.Error(w, "Stream already open", http.StatusConflict)
			return
		}
		h.stream = true
		h.mu.Unlock()
		defer func() { h.mu.Lock(); h.stream = false; h.mu.Unlock() }()
		h.streamMessages(w, r, h.events, "")
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, mcp.MaxMessage+1))
	if err != nil {
		http.Error(w, "Invalid body", 400)
		return
	}
	m, err := mcp.Parse(data)
	if err != nil {
		http.Error(w, "Invalid MCP message", 400)
		return
	}
	var ch chan mcp.Message
	if m.Fields["id"] != nil && m.String("method") != "" {
		ch = make(chan mcp.Message, 64)
		h.mu.Lock()
		if h.pending[m.ID()] != nil || len(h.pending) >= 128 {
			h.mu.Unlock()
			http.Error(w, "Duplicate ID or busy", http.StatusConflict)
			return
		}
		h.pending[m.ID()] = ch
		h.contexts[m.ID()] = r.Context()
		h.mu.Unlock()
		defer func() { h.mu.Lock(); delete(h.pending, m.ID()); delete(h.contexts, m.ID()); h.mu.Unlock() }()
	}
	written := make(chan error, 1)
	go func() { h.writes.Lock(); defer h.writes.Unlock(); written <- mcp.WriteFrame(h.in, m) }()
	select {
	case err := <-written:
		if err != nil {
			http.Error(w, "Upstream unavailable", http.StatusBadGateway)
			return
		}
	case <-r.Context().Done():
		h.cancel()
		_ = h.in.Close()
		return
	case <-h.ctx.Done():
		http.Error(w, "Upstream disconnected", http.StatusServiceUnavailable)
		return
	}
	if ch == nil {
		w.WriteHeader(202)
		return
	}
	h.streamMessages(w, r, ch, m.ID())
}

func (h *StdioHTTP) streamMessages(w http.ResponseWriter, r *http.Request, ch <-chan mcp.Message, id string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	for {
		select {
		case m := <-ch:
			if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", m.Raw); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if id != "" && m.String("method") == "" && m.ID() == id {
				return
			}
		case <-r.Context().Done():
			return
		case <-h.ctx.Done():
			return
		}
	}
}
