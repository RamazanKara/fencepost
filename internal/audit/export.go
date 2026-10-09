package audit

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/policy"
)

type lineExporter struct {
	queue chan []byte
	done  chan struct{}
	mu    sync.Mutex
	err   error
}

func OpenConfigured(config policy.Audit, stdout io.Writer) (*Log, error) {
	if config.Syslog != "" {
		u, err := url.Parse(config.Syslog)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "tcp" && u.Scheme != "udp" && u.Scheme != "tls") {
			return nil, errors.New("syslog must be tcp://host:port, udp://host:port, or tls://host:port")
		}
		if _, _, err := net.SplitHostPort(u.Host); err != nil {
			return nil, errors.New("syslog requires host and port")
		}
	}
	var file *os.File
	var err error
	if config.ExportFile != "" {
		file, err = os.OpenFile(config.ExportFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
	}
	l, err := Open(config.Path, config.OTLPEndpoint)
	if err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}
	if !config.Stdout && file == nil && config.OTLPLogsEndpoint == "" && config.Syslog == "" {
		return l, nil
	}
	e := &lineExporter{queue: make(chan []byte, 256), done: make(chan struct{})}
	l.lines = e
	go func() {
		defer close(e.done)
		defer func() {
			if file != nil {
				_ = file.Close()
			}
		}()
		client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		for line := range e.queue {
			if config.Stdout {
				if _, err := stdout.Write(line); err != nil {
					e.failed()
				}
			}
			if config.ExportFile != "" {
				if file != nil {
					info, err := file.Stat()
					if err == nil && info.Size() > 0 && info.Size()+int64(len(line)) > config.MaxBytes {
						_ = file.Close()
						file = nil
						if err := rotate(config.ExportFile, config.Backups); err != nil {
							e.failed()
						}
					}
				}
				if file == nil {
					file, err = os.OpenFile(config.ExportFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						e.failed()
					}
				}
				if file != nil {
					if _, err := file.Write(line); err != nil {
						e.failed()
					}
				}
			}
			if config.OTLPLogsEndpoint != "" {
				record := map[string]any{"timeUnixNano": strconv.FormatInt(time.Now().UnixNano(), 10), "severityNumber": 9, "severityText": "INFO", "body": map[string]string{"stringValue": strings.TrimSpace(string(line))}}
				payload := map[string]any{"resourceLogs": []any{map[string]any{"resource": map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]string{"stringValue": "fencepost"}}}}, "scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "fencepost.audit"}, "logRecords": []any{record}}}}}}
				data, _ := json.Marshal(payload)
				resp, err := client.Post(config.OTLPLogsEndpoint, "application/json", bytes.NewReader(data))
				if err != nil {
					e.failed()
				} else {
					body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
					_ = resp.Body.Close()
					var result struct {
						PartialSuccess struct {
							Rejected string `json:"rejectedLogRecords"`
							Message  string `json:"errorMessage"`
						} `json:"partialSuccess"`
					}
					if resp.StatusCode != 200 || readErr != nil || len(body) > 4096 || (len(body) > 0 && json.Unmarshal(body, &result) != nil) || (result.PartialSuccess.Rejected != "" && result.PartialSuccess.Rejected != "0") || result.PartialSuccess.Message != "" {
						e.failed()
					}
				}
			}
			if config.Syslog != "" {
				if err := sendSyslog(config.Syslog, line); err != nil {
					e.failed()
				}
			}
		}
	}()
	return l, nil
}

func rotate(path string, backups int) error {
	if err := os.Remove(path + "." + strconv.Itoa(backups)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := backups - 1; i >= 1; i-- {
		if err := os.Rename(path+"."+strconv.Itoa(i), path+"."+strconv.Itoa(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(path, path+".1")
}

func sendSyslog(target string, line []byte) error {
	u, _ := url.Parse(target)
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	var conn net.Conn
	var err error
	if u.Scheme == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", u.Host, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial(u.Scheme, u.Host)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	message := fmt.Sprintf("<14>1 %s - fencepost - audit - %s", time.Now().UTC().Format(time.RFC3339Nano), bytes.TrimSpace(line))
	if u.Scheme == "udp" {
		if len(message) > 65507 {
			return errors.New("syslog datagram too large")
		}
	} else {
		message = strconv.Itoa(len(message)) + " " + message
	}
	_, err = io.WriteString(conn, message)
	return err
}

func (e *lineExporter) failed() {
	e.mu.Lock()
	e.err = errors.New("some audit lines were not exported")
	e.mu.Unlock()
}
func (e *lineExporter) send(line []byte) {
	select {
	case e.queue <- line:
	default:
		e.failed()
	}
}
func (e *lineExporter) close() error {
	close(e.queue)
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
		e.failed()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}
