package pin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/mcp"
	"github.com/RamazanKara/fencepost/internal/scan"
)

func makeTool(description string) mcp.Tool {
	d, _ := json.Marshal(description)
	return mcp.Tool{"name": json.RawMessage(`"tool"`), "description": d, "inputSchema": json.RawMessage(`{"type":"object","properties":{"count":{"type":"number","default":1.0}}}`)}
}

func TestCanonical(t *testing.T) {
	for _, pair := range [][2]string{{`{"b":1.00,"a":[100,0.01,-0]}`, `{"a":[1e2,1e-2,0],"b":1}`}, {`{"n":9007199254740993}`, `{"n":9007199254740993.0}`}, {`{"s":"\u0061"}`, `{"s":"a"}`}} {
		a, err := Canonical([]byte(pair[0]))
		if err != nil {
			t.Fatal(err)
		}
		b, err := Canonical([]byte(pair[1]))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("%s != %s", a, b)
		}
	}
	a, _ := Canonical([]byte(`9007199254740993`))
	b, _ := Canonical([]byte(`9007199254740992`))
	if string(a) == string(b) {
		t.Fatal("rounded large number")
	}
	if _, err := Canonical([]byte(`{} {}`)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}

func TestToolFields(t *testing.T) {
	a := makeTool("description")
	original, _ := ToolHash(a)
	a["unknown"] = json.RawMessage(`{"future":true}`)
	same, _ := ToolHash(a)
	if same != original {
		t.Fatal("unknown field included in pin")
	}
	for _, key := range []string{"name", "description", "inputSchema", "outputSchema", "annotations"} {
		copy := makeTool("description")
		copy[key] = json.RawMessage(`{"changed":true}`)
		got, err := ToolHash(copy)
		if err != nil || got == original {
			t.Fatalf("%s not hashed", key)
		}
	}
}

func TestDeterministicLock(t *testing.T) {
	servers := []scan.Inventory{{Server: clientconfig.Server{Name: "z", Transport: "stdio", Command: "server", Env: map[string]string{"TOKEN": "private-token"}}, Catalog: mcp.Catalog{Tools: []mcp.Tool{makeTool("A private-token description.")}}}, {Server: clientconfig.Server{Name: "a", Transport: "http", URL: "https://example.invalid"}, Catalog: mcp.Catalog{Tools: []mcp.Tool{makeTool("A description.")}}}}
	lock, err := Snapshot(servers)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fencepost.lock")
	if err := Write(path, lock); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	servers[0], servers[1] = servers[1], servers[0]
	again, err := Snapshot(servers)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, again); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatal("nondeterministic YAML")
	}
	if strings.Contains(string(first), "private-token") {
		t.Fatal("lock leaked env value")
	}
	loaded, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(Compare(lock, loaded)) != 0 {
		t.Fatal("round trip drift")
	}
	servers = append(servers, servers[0])
	if _, err := Snapshot(servers); err == nil {
		t.Fatal("ambiguous server identity")
	}
}

func TestDriftAndTargetedUpdate(t *testing.T) {
	old := Lock{Version: 1, Servers: map[string]Server{"test": {strings.Repeat("a", 64), map[string]Tool{"changed": {strings.Repeat("b", 64), "old\nline"}, "removed": {strings.Repeat("c", 64), "gone"}}}}}
	now := Lock{Version: 1, Servers: map[string]Server{"test": {strings.Repeat("a", 64), map[string]Tool{"changed": {strings.Repeat("d", 64), "new\nline"}, "added": {strings.Repeat("e", 64), "added"}}}}}
	changes := Compare(old, now)
	if len(changes) != 3 {
		t.Fatalf("%+v", changes)
	}
	if !strings.Contains(changes[1].Diff, "--- a/test/changed/description\n+++ b/test/changed/description\n@@ -1,2 +1,2 @@\n-old\n-line") {
		t.Fatal(changes[1].Diff)
	}
	updated, err := Update(old, now, "test/changed")
	if err != nil {
		t.Fatal(err)
	}
	if len(Compare(updated, now)) != 2 || len(Compare(old, now)) != 3 {
		t.Fatal("update approved unrelated drift or mutated input")
	}
	updated, err = Update(updated, now, "test/removed")
	if err != nil {
		t.Fatal(err)
	}
	updated, err = Update(updated, now, "test/added")
	if err != nil {
		t.Fatal(err)
	}
	if len(Compare(updated, now)) != 0 {
		t.Fatal("targeted updates failed")
	}
	changed := now.Servers["test"]
	changed.LaunchHash = strings.Repeat("f", 64)
	now.Servers["test"] = changed
	if _, err := Update(old, now, "test/changed"); err == nil {
		t.Fatal("tool update accepted launch drift")
	}
	if changes := Compare(updated, now); len(changes) != 1 || changes[0].Kind != "changed launch spec" {
		t.Fatal(changes)
	}
	delete(now.Servers, "test")
	now.Servers["new"] = changed
	if len(Compare(updated, now)) != 2 {
		t.Fatal("server drift missing")
	}
}

func TestInvalidLock(t *testing.T) {
	for _, data := range []string{"version: 2\nservers: {}", "version: 1\nservers: {}\nextra: true", "version: 1\nservers: {}\n---\nversion: 1", "version: 1\nservers:\n  test:\n    launchHash: short\n    tools: {}"} {
		path := filepath.Join(t.TempDir(), "lock")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil {
			t.Fatal("accepted malformed lock")
		}
	}
}
