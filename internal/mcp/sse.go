package mcp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

type sseReader struct {
	scanner *bufio.Scanner
	id      string
	retry   int
	first   bool
}

func newSSE(r io.Reader) *sseReader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), MaxMessage+1)
	scanner.Split(sseLine)
	return &sseReader{scanner: scanner, retry: 1000, first: true}
}

func sseLine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		if data[i] == '\r' && i+1 == len(data) && !atEOF {
			return 0, nil, nil
		}
		advance := i + 1
		if data[i] == '\r' && advance < len(data) && data[advance] == '\n' {
			advance++
		}
		return advance, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func (s *sseReader) next() (Message, error) {
	var data strings.Builder
	for {
		if !s.scanner.Scan() {
			if err := s.scanner.Err(); err != nil {
				return Message{}, err
			}
			return Message{}, io.EOF
		}
		text := s.scanner.Text()
		if len(text)+data.Len() > MaxMessage {
			return Message{}, errors.New("SSE event exceeds 16 MiB")
		}
		if s.first {
			text = strings.TrimPrefix(text, "\ufeff")
			s.first = false
		}
		if text == "" {
			if strings.TrimSpace(data.String()) == "" {
				data.Reset()
				continue
			}
			return Parse([]byte(data.String()))
		}
		field, value, _ := strings.Cut(text, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			data.WriteString(value)
			data.WriteByte('\n')
		case "id":
			if !strings.ContainsRune(value, 0) {
				s.id = value
			}
		case "retry":
			if ms, err := strconv.Atoi(value); err == nil && ms >= 0 {
				s.retry = ms
			}
		}
	}
}
