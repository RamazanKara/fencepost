package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/RamazanKara/fencepost/internal/mcp"
)

type gatewayWriter struct {
	header http.Header
	status int
	body   *io.PipeWriter
	ready  chan struct{}
	once   sync.Once
}

func (w *gatewayWriter) Header() http.Header { return w.header }
func (w *gatewayWriter) WriteHeader(status int) {
	w.once.Do(func() { w.status = status; close(w.ready) })
}
func (w *gatewayWriter) Write(data []byte) (int, error) {
	w.WriteHeader(200)
	return w.body.Write(data)
}
func (w *gatewayWriter) Flush() { w.WriteHeader(200) }

// Gateway makes an HTTP config entry usable as a wrapped stdio command.
func Gateway(ctx context.Context, h *HTTP, in io.ReadCloser, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer h.Close()
	var mu, writes sync.Mutex
	var workers sync.WaitGroup
	session, version := "", mcp.Latest
	getStarted := false
	write := func(m mcp.Message) error { writes.Lock(); defer writes.Unlock(); return mcp.WriteFrame(out, m) }
	failures := make(chan error, 1)
	fail := func(err error) {
		select {
		case failures <- err:
		default:
		}
	}
	var exchange func(string, mcp.Message)
	exchange = func(method string, m mcp.Message) {
		defer workers.Done()
		reader, writer := io.Pipe()
		defer reader.Close()
		w := &gatewayWriter{header: http.Header{}, body: writer, ready: make(chan struct{})}
		r, _ := http.NewRequestWithContext(ctx, method, "http://fencepost/", bytes.NewReader(m.Raw))
		mu.Lock()
		if m.String("method") == "initialize" {
			version = mcp.Previous
		}
		r.Header.Set("MCP-Protocol-Version", version)
		if session != "" {
			r.Header.Set("Mcp-Session-Id", session)
		}
		mu.Unlock()
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		finished := make(chan struct{})
		go func() { defer close(finished); h.ServeHTTP(w, r); w.WriteHeader(200); _ = writer.Close() }()
		defer func() { _ = reader.Close(); <-finished }()
		select {
		case <-w.ready:
		case <-ctx.Done():
			return
		}
		mu.Lock()
		if id := w.header.Get("Mcp-Session-Id"); id != "" {
			session = id
		}
		startGET := session != "" && !getStarted && m.String("method") == "initialize"
		if startGET {
			getStarted = true
		}
		mu.Unlock()
		if startGET {
			workers.Add(1)
			go exchange("GET", mcp.Message{})
		}
		if w.status == 202 || w.status == 204 || (method == "GET" && w.status == 405) {
			return
		}
		if w.status < 200 || w.status >= 300 {
			if m.Fields["id"] != nil {
				_ = write(Error(m, -32002, "Upstream HTTP request failed."))
			}
			return
		}
		if w.header.Get("Content-Type") == "text/event-stream" {
			err := relaySSE(reader, io.Discard, func(response mcp.Message) (mcp.Message, error) { return response, write(response) })
			if err != nil && ctx.Err() == nil {
				fail(err)
			}
			return
		}
		data, err := io.ReadAll(io.LimitReader(reader, mcp.MaxMessage+1))
		if err == nil {
			var response mcp.Message
			response, err = mcp.Parse(data)
			if err == nil {
				err = write(response)
			}
		}
		if err != nil && ctx.Err() == nil {
			fail(err)
		}
	}
	frames := make(chan frame, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		r := bufio.NewReader(in)
		for {
			m, err := mcp.ReadFrame(r)
			select {
			case frames <- frame{message: m, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); _ = in.Close(); <-readDone; workers.Wait() }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case f := <-frames:
			if errors.Is(f.err, io.EOF) {
				return nil
			}
			if f.err != nil {
				return f.err
			}
			workers.Add(1)
			go exchange("POST", f.message)
		}
	}
}
