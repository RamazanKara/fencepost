package rulebundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignatureAndRollback(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(version uint64, pattern string) []byte {
		payload, _ := json.Marshal(Bundle{Version: version, Patterns: []string{pattern}})
		data, _ := json.Marshal(envelope{Payload: payload, Signature: ed25519.Sign(private, payload)})
		return data
	}
	valid := signed(2, "(?i)override all safety")
	b, err := Verify(valid, pub)
	if err != nil || !b.compiled[0].MatchString("Override all safety") {
		t.Fatal(b, err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(valid, other); err == nil {
		t.Fatal("wrong signer accepted")
	}
	var e envelope
	_ = json.Unmarshal(valid, &e)
	e.Payload = append(e.Payload, ' ')
	tampered, _ := json.Marshal(e)
	for _, bad := range [][]byte{tampered, []byte(`{}`), signed(0, "x"), signed(2, "["), append(valid, []byte(`{}`)...)} {
		if _, err := Verify(bad, pub); err == nil {
			t.Fatal("invalid bundle accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "rules.json")
	if _, err := install(path, valid, pub, 1); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{signed(1, "x"), signed(2, "changed"), tampered} {
		if _, err := install(path, bad, pub, 1); err == nil {
			t.Fatal("unsafe update accepted")
		}
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(valid) {
		t.Fatal("failed update damaged rules")
	}
	if _, err := install(path, valid, pub, 1); err != nil {
		t.Fatal("idempotent update", err)
	}
	if _, err := install(path, signed(3, "new poisoning pattern"), pub, 1); err != nil {
		t.Fatal(err)
	}
}

func TestBundledRules(t *testing.T) {
	if Version() == 0 || !Match("Ignore previous instructions") {
		t.Fatal("built-in signed rules are inactive")
	}
}
