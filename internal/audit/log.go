package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/scan"
)

type Event struct {
	User       string          `json:"user,omitempty"`
	Groups     []string        `json:"groups,omitempty"`
	Client     string          `json:"client,omitempty"`
	Approver   string          `json:"approver,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Arguments  json.RawMessage `json:"arguments,omitempty"`
	Replayable bool            `json:"replayable,omitempty"`
	Time       string          `json:"time"`
	Session    string          `json:"session"`
	Kind       string          `json:"kind"`
	Server     string          `json:"server,omitempty"`
	Tool       string          `json:"tool,omitempty"`
	Method     string          `json:"method,omitempty"`
	Decision   string          `json:"decision,omitempty"`
	Rule       string          `json:"rule,omitempty"`
	Redactions map[string]int  `json:"redactions,omitempty"`
}

type entry struct {
	Sequence int64  `json:"sequence"`
	Previous string `json:"previous"`
	Event    Event  `json:"event"`
}

type Record struct {
	Entry json.RawMessage `json:"entry"`
	Hash  string          `json:"hash"`
}

type head struct {
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
}

type Log struct {
	file, checkpoint, guard *os.File
	mu                      sync.Mutex
	export                  *exporter
	lines                   *lineExporter
}

func Open(path, endpoint string) (*Log, error) {
	l := &Log{}
	unlock, err := lock(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(path + ".head"); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("audit log is missing but checkpoint exists")
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		if err := writeHead(path, head{Hash: strings.Repeat("0", 64)}); err != nil {
			return nil, err
		}
	}
	if _, err := verify(path, nil); err != nil {
		return nil, err
	}
	l.file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	l.checkpoint, err = os.OpenFile(path+".head", os.O_RDWR, 0600)
	if err != nil {
		_ = l.file.Close()
		return nil, err
	}
	l.guard, err = os.OpenFile(path+".writing", os.O_RDWR, 0600)
	if err != nil {
		_ = l.file.Close()
		_ = l.checkpoint.Close()
		return nil, err
	}
	if endpoint != "" {
		l.export = newExporter(endpoint)
	}
	return l, nil
}

func lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".writing", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { unlockFile(f); _ = f.Close() }, nil
}

func writeHead(path string, h head) error {
	return os.WriteFile(path+".head", headBytes(h), 0600)
}

func headBytes(h head) []byte {
	data, _ := json.Marshal(h)
	return append(data, bytes.Repeat([]byte{' '}, 256-len(data))...)
}

func readHead(path string) (head, error) {
	var h head
	data, err := os.ReadFile(path + ".head")
	if err != nil {
		return h, errors.New("audit checkpoint missing or unreadable")
	}
	if json.Unmarshal(data, &h) != nil || len(h.Hash) != 64 {
		return h, errors.New("invalid audit checkpoint")
	}
	return h, nil
}

func (l *Log) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := lockFile(l.guard); err != nil {
		return err
	}
	defer unlockFile(l.guard)
	var checkpoint [256]byte
	if _, err := l.checkpoint.ReadAt(checkpoint[:], 0); err != nil {
		return err
	}
	var h head
	if json.Unmarshal(checkpoint[:], &h) != nil || len(h.Hash) != 64 {
		return errors.New("invalid audit checkpoint")
	}
	info, err := l.file.Stat()
	if err != nil || info.Size() != h.Size {
		return errors.New("audit log size differs from checkpoint")
	}
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	for _, s := range []*string{&e.Server, &e.Tool, &e.Method, &e.Rule, &e.User, &e.Client, &e.Approver, &e.Reason} {
		*s, _ = scan.RedactSecrets("", *s)
		if len(*s) > 256 {
			*s = "[oversized identifier]"
		}
	}
	e.Groups = append([]string(nil), e.Groups...)
	for i := range e.Groups {
		e.Groups[i], _ = scan.RedactSecrets("", e.Groups[i])
	}
	data, _ := json.Marshal(entry{h.Sequence + 1, h.Hash, e})
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	line, _ := json.Marshal(Record{data, hash})
	line = append(line, '\n')
	if len(line) > 64<<10 {
		return errors.New("audit entry exceeds limit")
	}
	n, err := l.file.Write(line)
	if err != nil {
		return err
	}
	if _, err := l.checkpoint.WriteAt(headBytes(head{h.Sequence + 1, hash, h.Size + int64(n)}), 0); err != nil {
		return err
	}
	if l.export != nil && e.Kind == "decision" {
		l.export.send(e)
	}
	if l.lines != nil {
		l.lines.send(line)
	}
	return nil
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := errors.Join(l.file.Sync(), l.checkpoint.Sync(), l.file.Close(), l.checkpoint.Close(), l.guard.Close())
	if l.export != nil {
		err = errors.Join(err, l.export.close())
	}
	if l.lines != nil {
		err = errors.Join(err, l.lines.close())
	}
	return err
}

func Verify(path string, visit func(Event)) (int64, error) {
	unlock, err := lock(path)
	if err != nil {
		return 0, err
	}
	defer unlock()
	return verify(path, visit)
}

func verify(path string, visit func(Event)) (int64, error) {
	h, err := readHead(path)
	if err != nil {
		return 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	previous := strings.Repeat("0", 64)
	var sequence, size int64
	for {
		line, err := r.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil || len(line) > 64<<10 {
			return sequence, errors.New("incomplete or oversized audit line")
		}
		size += int64(len(line))
		var record Record
		var e entry
		if json.Unmarshal(line, &record) != nil || json.Unmarshal(record.Entry, &e) != nil {
			return sequence, errors.New("invalid audit line")
		}
		sum := sha256.Sum256(record.Entry)
		canonical, _ := json.Marshal(record)
		if record.Hash != hex.EncodeToString(sum[:]) || e.Previous != previous || e.Sequence != sequence+1 || !bytes.Equal(append(canonical, '\n'), line) {
			return sequence, fmt.Errorf("audit chain broken at line %d", sequence+1)
		}
		previous, sequence = record.Hash, e.Sequence
		if visit != nil {
			visit(e.Event)
		}
	}
	if sequence != h.Sequence || previous != h.Hash || size != h.Size {
		return sequence, errors.New("audit tail differs from checkpoint")
	}
	return sequence, nil
}

func Tail(path string, n int, out io.Writer) error {
	var events []Event
	_, err := Verify(path, func(e Event) {
		events = append(events, e)
		if len(events) > n {
			events = events[1:]
		}
	})
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := json.NewEncoder(out).Encode(e); err != nil {
			return err
		}
	}
	return nil
}

type Stats struct {
	Calls      map[string]int `json:"calls"`
	Denies     int            `json:"denies"`
	Redactions int            `json:"redactions"`
}

func Statistics(path string) (Stats, error) {
	s := Stats{Calls: map[string]int{}}
	_, err := Verify(path, func(e Event) {
		if e.Kind == "request" && e.Method == "tools/call" {
			s.Calls[e.Server+"/"+e.Tool]++
		}
		if e.Kind == "decision" && e.Decision == "deny" {
			s.Denies++
		}
		for _, count := range e.Redactions {
			s.Redactions += count
		}
	})
	return s, err
}
