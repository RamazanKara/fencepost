package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type partialReader struct{ io.Reader }

func (r partialReader) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return r.Reader.Read(p)
}

func TestFraming(t *testing.T) {
	for _, size := range []int{0, 1, 128 << 10, 1 << 20} {
		m, err := Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "future/unknown", "extra": map[string]string{"payload": strings.Repeat("x", size)}})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := WriteFrame(&out, m); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(bufio.NewReader(partialReader{&out}))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Raw, m.Raw) {
			t.Fatal("unknown fields changed")
		}
	}
	for _, input := range []string{"[]\n", "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"}]\n", "not json\n", "{}\n", "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"x\"}\n", "{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"x\"}\n", "{\"jsonrpc\":\"2.0\",\"id\":true,\"method\":\"x\"}\n", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"error\":{}}\n", "{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":[]}\n", "{\"jsonrpc\":\"2.0\",\"method\":\"x\"}", "{\"jsonrpc\":\"2.0\",\"method\":\"\xff\"}\n", strings.Repeat("x", MaxMessage+1) + "\n"} {
		if _, err := ReadFrame(bufio.NewReader(strings.NewReader(input))); err == nil {
			t.Errorf("accepted invalid frame (length %d)", len(input))
		}
	}
	if _, err := ReadFrame(bufio.NewReader(strings.NewReader(""))); err != io.EOF {
		t.Fatalf("empty: %v", err)
	}
}

func TestMessageKinds(t *testing.T) {
	for _, input := range []string{`{"jsonrpc":"2.0","method":"notifications/future","unknown":42}`, `{"jsonrpc":"2.0","id":"request","result":{"opaque":true}}`, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"bad request"}}`} {
		if _, err := Parse([]byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := Parse([]byte(`{"jsonrpc":"2.0","id":"1","result":{}}`))
	b, _ := Parse([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if a.ID() == b.ID() {
		t.Fatal("string and numeric IDs collided")
	}
}

func TestSSE(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		input := "\ufeffdata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}" + ending + ending
		if _, err := newSSE(partialReader{strings.NewReader(input)}).next(); err != nil {
			t.Fatalf("line ending %q: %v", ending, err)
		}
	}
	input := ": comment\r\n\r\nid: resume\nretry: 12\ndata:\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\n" + "data: \"id\":1,\"result\":{}}\n\n"
	r := newSSE(partialReader{strings.NewReader(input)})
	m, err := r.next()
	if err != nil {
		t.Fatal(err)
	}
	if m.ID() != "n:1" || r.id != "resume" || r.retry != 12 {
		t.Fatalf("SSE metadata: %+v", r)
	}
	for _, input := range []string{"data: []\n\n", "data: nope\n\n", "data: " + strings.Repeat("x", MaxMessage) + "\n\n"} {
		if _, err := newSSE(strings.NewReader(input)).next(); err == nil {
			t.Fatal("accepted invalid SSE")
		}
	}
}

func TestStdioCorrelation(t *testing.T) {
	serverIn, clientIn := io.Pipe()
	clientOut, serverOut := io.Pipe()
	p := &stdio{in: clientIn, out: clientOut, pending: map[string]chan reply{}, done: make(chan struct{})}
	go p.read()
	t.Cleanup(func() {
		_ = serverIn.Close()
		_ = serverOut.Close()
		_ = clientIn.Close()
		_ = clientOut.Close()
		<-p.done
	})
	const count = 20
	go func() {
		r := bufio.NewReader(serverIn)
		messages := make([]Message, 0, count)
		for range count {
			m, err := ReadFrame(r)
			if err != nil {
				return
			}
			messages = append(messages, m)
		}
		for i := len(messages) - 1; i >= 0; i-- {
			n, _ := Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/unknown", "params": map[string]bool{"opaque": true}})
			_ = WriteFrame(serverOut, n)
			m, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": messages[i].Fields["id"], "result": map[string]any{"echo": messages[i].Fields["id"]}})
			_ = WriteFrame(serverOut, m)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": i, "method": "future/call"})
			r, err := p.exchange(ctx, m)
			if err != nil {
				t.Error(err)
				return
			}
			if r.ID() != m.ID() {
				t.Error("wrong correlation")
			}
		}()
	}
	wg.Wait()
}

func TestStdioTimeout(t *testing.T) {
	serverIn, clientIn := io.Pipe()
	clientOut, serverOut := io.Pipe()
	p := &stdio{in: clientIn, out: clientOut, pending: map[string]chan reply{}, done: make(chan struct{})}
	go p.read()
	defer func() {
		_ = clientIn.Close()
		_ = serverIn.Close()
		_ = clientOut.Close()
		_ = serverOut.Close()
		<-p.done
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	m, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "blocked"})
	if _, err := p.exchange(ctx, m); err == nil {
		t.Fatal("missing timeout")
	}
}

func TestRPCErrorHidesMessage(t *testing.T) {
	m, _ := Parse([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"credential-value","data":{"extension":true}}}`))
	_, err := m.Result()
	if strings.Contains(err.Error(), "credential") {
		t.Fatal("server error leaked")
	}
	if !json.Valid(m.Fields["error"]) {
		t.Fatal("error fields lost")
	}
}
