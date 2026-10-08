package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/mcp"
)

type frame struct {
	message  mcp.Message
	err      error
	upstream bool
}

func Stdio(ctx context.Context, e *Engine, s clientconfig.Server, in io.ReadCloser, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Command, s.Args...)
	cmd.Dir, cmd.Stderr, cmd.WaitDelay = s.Cwd, io.Discard, time.Second
	if s.Env == nil {
		cmd.Env = os.Environ()
	} else {
		cmd.Env = clientconfig.CleanEnv(s.Env)
	}
	mcp.ConfigureProcess(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return errors.New("cannot start upstream server")
	}
	err = Relay(ctx, e, in, out, stdin, stdout)
	_ = stdin.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(300 * time.Millisecond):
		_ = mcp.KillProcess(cmd)
		<-waited
	}
	_ = stdout.Close()
	return err
}

func Relay(ctx context.Context, e *Engine, in io.ReadCloser, out io.Writer, upIn io.WriteCloser, upOut io.ReadCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	frames := make(chan frame, 16)
	var readers, workers sync.WaitGroup
	for _, source := range []struct {
		r        io.Reader
		upstream bool
	}{{in, false}, {upOut, true}} {
		readers.Add(1)
		go func() {
			defer readers.Done()
			r := bufio.NewReader(source.r)
			for {
				m, err := mcp.ReadFrame(r)
				select {
				case frames <- frame{m, err, source.upstream}:
				case <-ctx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}()
	}
	var toClient, toServer sync.Mutex
	writeClient := func(m mcp.Message) error { toClient.Lock(); defer toClient.Unlock(); return mcp.WriteFrame(out, m) }
	writeServer := func(m mcp.Message) error { toServer.Lock(); defer toServer.Unlock(); return mcp.WriteFrame(upIn, m) }
	failures := make(chan error, 1)
	fail := func(err error) {
		select {
		case failures <- err:
		default:
		}
	}
	defer func() {
		cancel()
		_ = in.Close()
		_ = upIn.Close()
		_ = upOut.Close()
		readers.Wait()
		workers.Wait()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case f := <-frames:
			if f.err != nil {
				if f.upstream {
					for _, m := range e.Fail() {
						_ = writeClient(m)
					}
					return errors.New("upstream server disconnected")
				}
				if errors.Is(f.err, io.EOF) {
					return nil
				}
				_ = e.record("request", "invalid", "", "deny", "framing", nil)
				_ = writeClient(Error(mcp.Message{}, -32700, "Invalid MCP message."))
				return errors.New("invalid client frame")
			}
			if f.upstream {
				m, err := e.Server(f.message)
				if err != nil {
					_ = writeClient(Error(f.message, -32603, "Fencepost audit unavailable."))
					return err
				}
				if err := writeClient(m); err != nil {
					return err
				}
				continue
			}
			r, err := e.Begin(ctx, f.message)
			if err != nil {
				if f.message.Fields["id"] != nil {
					_ = writeClient(Error(f.message, -32600, "Fencepost could not accept this request."))
				}
				continue
			}
			process := func() {
				denied, err := e.Check(r)
				if err != nil {
					_ = writeClient(Error(r.Message, -32603, "Fencepost audit unavailable."))
					fail(err)
					return
				}
				if denied != nil {
					if r.Message.Fields["id"] != nil {
						if err := writeClient(*denied); err != nil {
							fail(err)
						}
					}
					return
				}
				if err := writeServer(r.Message); err != nil {
					fail(err)
				}
			}
			if r.method == "tools/call" {
				workers.Add(1)
				go func() { defer workers.Done(); process() }()
			} else {
				process()
			}
		}
	}
}
