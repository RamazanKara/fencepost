package mcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
)

type reply struct {
	message Message
	err     error
}

type stdio struct {
	cmd     *exec.Cmd
	in      io.WriteCloser
	out     io.ReadCloser
	writes  sync.Mutex
	mu      sync.Mutex
	pending map[string]chan reply
	err     error
	done    chan struct{}
	waited  chan error
	legacy  bool
}

func startStdio(ctx context.Context, s clientconfig.Server) (*stdio, error) {
	cmd := exec.CommandContext(ctx, s.Command, s.Args...)
	cmd.Env, cmd.Dir, cmd.Stderr = clientconfig.CleanEnv(s.Env), s.Cwd, io.Discard
	cmd.WaitDelay = time.Second
	configureProcess(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.New("cannot create server stdin")
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return nil, errors.New("cannot create server stdout")
	}
	if err = cmd.Start(); err != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, errors.New("cannot start server command")
	}
	p := &stdio{cmd: cmd, in: in, out: out, pending: map[string]chan reply{}, done: make(chan struct{}), waited: make(chan error, 1)}
	go p.read()
	go func() { p.waited <- cmd.Wait() }()
	return p, nil
}

func (p *stdio) read() {
	defer close(p.done)
	r := bufio.NewReader(p.out)
	for {
		m, err := ReadFrame(r)
		if err != nil {
			p.mu.Lock()
			p.err = err
			for _, ch := range p.pending {
				ch <- reply{err: err}
			}
			p.pending = map[string]chan reply{}
			p.mu.Unlock()
			return
		}
		if m.String("method") != "" {
			if _, request := m.Fields["id"]; request {
				p.mu.Lock()
				legacy := p.legacy
				p.mu.Unlock()
				if !legacy {
					continue
				}
				response, _ := Encode(map[string]any{"jsonrpc": "2.0", "id": m.Fields["id"], "error": map[string]any{"code": -32601, "message": "Client capability not supported"}})
				_ = p.send(response)
			}
			continue
		}
		p.mu.Lock()
		if ch := p.pending[m.ID()]; ch != nil {
			ch <- reply{message: m}
			delete(p.pending, m.ID())
		}
		p.mu.Unlock()
	}
}

func (p *stdio) send(m Message) error {
	p.writes.Lock()
	defer p.writes.Unlock()
	return WriteFrame(p.in, m)
}

func (p *stdio) exchange(ctx context.Context, m Message) (Message, error) {
	ch := make(chan reply, 1)
	p.mu.Lock()
	if p.err != nil {
		err := p.err
		p.mu.Unlock()
		return Message{}, err
	}
	p.pending[m.ID()] = ch
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.pending, m.ID()); p.mu.Unlock() }()
	// Closing stdin on cancellation also interrupts a server that stops reading.
	written := make(chan error, 1)
	go func() { written <- p.send(m) }()
	select {
	case err := <-written:
		if err != nil {
			return Message{}, err
		}
	case <-ctx.Done():
		_ = p.in.Close()
		return Message{}, ctx.Err()
	}
	select {
	case r := <-ch:
		return r.message, r.err
	case <-ctx.Done():
		cancel, _ := Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": m.Fields["id"]}})
		go func() { _ = p.send(cancel) }()
		return Message{}, ctx.Err()
	}
}

func (p *stdio) close() error {
	_ = p.in.Close()
	select {
	case <-p.waited:
	case <-time.After(300 * time.Millisecond):
		_ = killProcess(p.cmd)
		<-p.waited
	}
	_ = p.out.Close()
	<-p.done
	return nil
}
