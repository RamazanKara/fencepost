package audit

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
)

func TestChainProperties(t *testing.T) {
	property := func(input []uint8, offset uint16) bool {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		log, err := Open(path, "")
		if err != nil {
			t.Fatal(err)
		}
		count := 2 + len(input)%8
		for i := 0; i < count; i++ {
			if err := log.Write(Event{Time: "2026-10-09T00:00:00Z", Kind: "decision", Session: fmt.Sprint(i), Decision: "allow"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		visited := 0
		n, err := Verify(path, func(e Event) {
			if e.Session != fmt.Sprint(visited) {
				t.Errorf("event order: %s at %d", e.Session, visited)
			}
			visited++
		})
		if err != nil || n != int64(count) || visited != count {
			return false
		}
		// Reopening must extend the existing chain, including its checkpoint.
		log, err = Open(path, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Write(Event{Kind: "request"}); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		if n, err := Verify(path, nil); err != nil || n != int64(count+1) {
			return false
		}
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.SplitAfter(original, []byte{'\n'})
		index := int(offset) % len(original)
		edited := bytes.Clone(original)
		edited[index] ^= 1
		removed := bytes.Join(append(append([][]byte{}, lines[:1]...), lines[2:]...), nil)
		reordered := append([][]byte{}, lines...)
		reordered[0], reordered[1] = reordered[1], reordered[0]
		for _, changed := range [][]byte{edited, original[:index], removed, bytes.Join(reordered, nil), append(bytes.Clone(original), lines[0]...)} {
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(path, nil); err == nil {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 32, Rand: rand.New(rand.NewSource(3))}); err != nil {
		t.Fatal(err)
	}
}
