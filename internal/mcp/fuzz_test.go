package mcp

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzFraming(f *testing.F) {
	for _, s := range []string{"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n", "[]\n", "{}", "\xff\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMessage+2 {
			t.Skip()
		}
		m, err := ReadFrame(bufio.NewReader(partialReader{bytes.NewReader(data)}))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := WriteFrame(&out, m); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFrame(bufio.NewReader(&out)); err != nil {
			t.Fatal(err)
		}
	})
}
