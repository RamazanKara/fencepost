package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

const (
	Latest     = "2026-07-28"
	Previous   = "2025-11-25"
	MaxMessage = 16 << 20
)

// Message retains the original envelope, including extension fields and unknown methods.
type Message struct {
	Raw    json.RawMessage
	Fields map[string]json.RawMessage
}

var integer = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func Parse(data []byte) (Message, error) {
	if len(data) > MaxMessage {
		return Message{}, errors.New("MCP message exceeds 16 MiB")
	}
	if !utf8.Valid(data) {
		return Message{}, errors.New("MCP message is not UTF-8")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return Message{}, errors.New("expected one JSON-RPC object; MCP does not support batches")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return Message{}, errors.New("invalid JSON-RPC JSON")
	}
	m := Message{bytes.Clone(data), fields}
	if m.String("jsonrpc") != "2.0" {
		return Message{}, errors.New("expected JSON-RPC 2.0")
	}
	id, hasID := fields["id"]
	if hasID {
		var s string
		if !integer.Match(id) && (len(id) == 0 || id[0] != '"' || json.Unmarshal(id, &s) != nil) {
			return Message{}, errors.New("invalid JSON-RPC ID")
		}
	}
	_, result := fields["result"]
	_, rpcError := fields["error"]
	if method, hasMethod := fields["method"]; hasMethod {
		var name string
		if json.Unmarshal(method, &name) != nil || name == "" || result || rpcError {
			return Message{}, errors.New("invalid JSON-RPC request or notification")
		}
		if p, ok := fields["params"]; ok && (len(p) == 0 || p[0] != '{') {
			return Message{}, errors.New("MCP params must be an object")
		}
	} else {
		if result == rpcError || (result && !hasID) {
			return Message{}, errors.New("invalid JSON-RPC response")
		}
		if result && (len(fields["result"]) == 0 || fields["result"][0] != '{') {
			return Message{}, errors.New("MCP result must be an object")
		}
		if rpcError {
			var e struct {
				Code    json.RawMessage
				Message *string
			}
			if json.Unmarshal(fields["error"], &e) != nil || !integer.Match(e.Code) || e.Message == nil {
				return Message{}, errors.New("invalid JSON-RPC error")
			}
		}
	}
	return m, nil
}

func (m Message) String(key string) string {
	var s string
	_ = json.Unmarshal(m.Fields[key], &s)
	return s
}

func (m Message) ID() string {
	id := m.Fields["id"]
	if len(id) > 0 && id[0] == '"' {
		return "s:" + m.String("id")
	}
	return "n:" + string(id)
}

func Encode(value any) (Message, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return Message{}, err
	}
	return Parse(data)
}

func ReadFrame(r *bufio.Reader) (Message, error) {
	var data []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(data)+len(part) > MaxMessage+1 {
			return Message{}, errors.New("MCP message exceeds 16 MiB")
		}
		data = append(data, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) != 0 {
				return Message{}, io.ErrUnexpectedEOF
			}
			return Message{}, err
		}
		return Parse(bytes.TrimSuffix(data, []byte{'\n'}))
	}
}

func WriteFrame(w io.Writer, m Message) error {
	var compact bytes.Buffer
	if err := json.Compact(&compact, m.Raw); err != nil {
		return err
	}
	compact.WriteByte('\n')
	_, err := io.Copy(w, &compact)
	return err
}

type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Server error text can contain secrets, terminal controls, or attacker instructions.
func (e *RPCError) Error() string { return fmt.Sprintf("MCP server returned error %d", e.Code) }

func (m Message) Result() (json.RawMessage, error) {
	if raw, ok := m.Fields["error"]; ok {
		var e RPCError
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, errors.New("invalid MCP error code")
		}
		return nil, &e
	}
	return m.Fields["result"], nil
}
