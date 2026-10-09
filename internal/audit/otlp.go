package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type exporter struct {
	queue chan Event
	done  chan struct{}
	mu    sync.Mutex
	err   error
}

func newExporter(endpoint string) *exporter {
	e := &exporter{queue: make(chan Event, 256), done: make(chan struct{})}
	go func() {
		defer close(e.done)
		client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		for event := range e.queue {
			var trace [16]byte
			var span [8]byte
			_, _ = rand.Read(trace[:])
			_, _ = rand.Read(span[:])
			now := strconv.FormatInt(time.Now().UnixNano(), 10)
			attributes := []any{}
			for _, pair := range [][2]string{{"server", event.Server}, {"tool", event.Tool}, {"decision", event.Decision}, {"rule", event.Rule}, {"session", event.Session}} {
				attributes = append(attributes, map[string]any{"key": pair[0], "value": map[string]string{"stringValue": pair[1]}})
			}
			payload := map[string]any{"resourceSpans": []any{map[string]any{"resource": map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]string{"stringValue": "fencepost"}}}}, "scopeSpans": []any{map[string]any{"scope": map[string]string{"name": "fencepost.proxy"}, "spans": []any{map[string]any{"traceId": hex.EncodeToString(trace[:]), "spanId": hex.EncodeToString(span[:]), "name": "fencepost.decision", "kind": 1, "startTimeUnixNano": now, "endTimeUnixNano": now, "attributes": attributes}}}}}}}
			data, _ := json.Marshal(payload)
			response, err := client.Post(endpoint, "application/json", bytes.NewReader(data))
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
				_ = response.Body.Close()
				var result struct {
					PartialSuccess struct {
						Rejected json.Number `json:"rejectedSpans"`
						Message  string      `json:"errorMessage"`
					} `json:"partialSuccess"`
				}
				if response.StatusCode != http.StatusOK || readErr != nil || len(body) > 4096 || (len(body) > 0 && json.Unmarshal(body, &result) != nil) || (result.PartialSuccess.Rejected != "" && result.PartialSuccess.Rejected != "0") || result.PartialSuccess.Message != "" {
					err = errors.New("OTLP collector rejected span")
				}
			}
			if err != nil {
				e.failed()
			}
		}
	}()
	return e
}

func (e *exporter) failed() {
	e.mu.Lock()
	e.err = errors.New("some OTLP spans were not exported")
	e.mu.Unlock()
}
func (e *exporter) send(event Event) {
	select {
	case e.queue <- event:
	default:
		e.failed()
	}
}
func (e *exporter) close() error {
	close(e.queue)
	select {
	case <-e.done:
	case <-time.After(3 * time.Second):
		e.failed()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}
