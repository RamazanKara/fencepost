package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/policy"
	"github.com/RamazanKara/fencepost/packs"
	"gopkg.in/yaml.v3"
)

func runOperatorCommands(args []string, out, errOut io.Writer) int {
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	policyPath, server, config := "fencepost.yaml", "filesystem", ""
	packNames := ""
	if command != "explain" {
		flags.StringVar(&policyPath, "policy", policyPath, "policy file")
	}
	if command == "init" {
		flags.StringVar(&server, "server", server, "exact MCP server name")
		flags.StringVar(&packNames, "pack", "", "comma-separated starter packs")
	}
	if command == "doctor" {
		flags.StringVar(&config, "config", "", "check only this client config")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(errOut, err); return 2 }
	if command == "explain" {
		if flags.NArg() != 2 {
			return fail(errors.New("usage: fencepost explain <policy> <toolcall.json>"))
		}
		p, err := policy.Read(flags.Arg(0))
		if err != nil {
			return fail(err)
		}
		data, err := os.ReadFile(flags.Arg(1))
		if err != nil {
			return fail(err)
		}
		var call struct {
			Server    string          `json:"server"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		d.DisallowUnknownFields()
		if d.Decode(&call) != nil || call.Server == "" || call.Name == "" {
			return fail(fmt.Errorf("%s: expected JSON with server, name, and optional arguments object", flags.Arg(1)))
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return fail(fmt.Errorf("%s: expected one JSON object", flags.Arg(1)))
		}
		var arguments map[string]any
		if len(call.Arguments) > 0 {
			d := json.NewDecoder(bytes.NewReader(call.Arguments))
			d.UseNumber()
			if d.Decode(&arguments) != nil || arguments == nil {
				return fail(fmt.Errorf("%s: arguments must be a JSON object", flags.Arg(1)))
			}
		}
		action, rule, rate := p.Match(call.Server, call.Name, arguments)
		reason := "first matching tool rule; all argument constraints passed"
		switch {
		case rule == "server":
			reason = "server is not configured"
		case rule == "default":
			reason = "no tool rule matched; using server default"
		case strings.Contains(rule, "/argument:"):
			reason = "argument constraint failed or required value is missing"
		}
		fmt.Fprintf(out, "%s: %s (%s).\n", strings.ToUpper(action), reason, rule)
		if action == "ask" {
			fmt.Fprintln(out, "Approval is required; this command does not request it.")
		}
		fmt.Fprintf(out, "Policy evaluation only: rate_limit=%d/minute, session_budget=%d (0 means unlimited). Live counters, approvals, and pins are checked by the proxy.\n", rate, p.SessionBudget)
		if action != "allow" {
			return 1
		}
		return 0
	}
	if flags.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	if command == "init" {
		if strings.TrimSpace(server) == "" {
			return fail(errors.New("--server must not be empty"))
		}
		value := map[string]any{
			"version": 1,
			"servers": map[string]any{server: map[string]any{
				"default": "deny",
				"tools": []any{map[string]any{"name": "read_file", "action": "allow",
					"arguments": []any{map[string]any{"path": "$.path", "path_prefix": []string{"./workspace"}}}}},
			}},
			"output": map[string]any{"redact_secrets": true, "max_bytes": 1048576, "injection": "warn"},
		}
		data, err := yaml.Marshal(value)
		if packNames != "" {
			serverSet := false
			flags.Visit(func(f *flag.Flag) { serverSet = serverSet || f.Name == "server" })
			if serverSet {
				return fail(errors.New("--server and --pack cannot be combined; edit server names in the composed policy"))
			}
			data, err = packs.Compose(packNames)
		}
		if err != nil {
			return fail(err)
		}
		f, err := os.OpenFile(policyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			return fail(fmt.Errorf("%s: already exists; choose another --policy path", policyPath))
		}
		if err != nil {
			return fail(err)
		}
		_, writeErr := f.Write(data)
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return fail(err)
		}
		fmt.Fprintf(out, "Wrote %s. Review server names and allowed arguments, and create workspace beside the policy before proxying.\n", policyPath)
		return 0
	}
	paths, err := clientconfig.DefaultPaths()
	if err != nil {
		return fail(err)
	}
	candidates := clientconfig.Candidates(paths)
	if config != "" {
		candidates = []string{config}
	}
	code, found := 0, 0
	check := func(path string, private bool) {
		if err := checkPermissions(path, private); err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", path, err)
			code = 2
		} else {
			fmt.Fprintf(out, "OK permissions: %s\n", path)
		}
	}
	seen := map[string]bool{}
	for _, path := range candidates {
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) && config == "" {
			fmt.Fprintf(out, "Absent: %s\n", path)
			continue
		}
		check(path, true)
		check(filepath.Dir(path), false)
		servers, err := clientconfig.Discover(paths, path)
		if err != nil {
			fmt.Fprintln(errOut, err)
			code = 2
			continue
		}
		found += len(servers)
		fmt.Fprintf(out, "OK config: %s (%d server(s))\n", path, len(servers))
	}
	if found == 0 {
		fmt.Fprintln(errOut, "No MCP servers discovered; provide --config or configure a supported client.")
		code = 2
	}
	p, err := policy.Read(policyPath)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	check(policyPath, false)
	check(filepath.Dir(policyPath), false)
	for _, path := range []string{p.Audit.Path, p.Audit.Path + ".head", p.Audit.Path + ".writing", p.Approval.LocalFile} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			check(path, true)
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err == nil {
				err = f.Close()
			}
			if err != nil {
				fmt.Fprintf(errOut, "%s: runtime file is not writable: %v\n", path, err)
				code = 2
			}
		}
	}
	for _, dir := range []string{filepath.Dir(p.Audit.Path), filepath.Dir(p.Approval.LocalFile)} {
		check(dir, false)
		f, err := os.CreateTemp(dir, ".fencepost-doctor-*")
		if err != nil {
			fmt.Fprintf(errOut, "%s: cannot create runtime files: %v\n", dir, err)
			code = 2
			continue
		}
		name := f.Name()
		if err := errors.Join(f.Close(), os.Remove(name)); err != nil {
			fmt.Fprintln(errOut, err)
			code = 2
		}
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(out, "Windows: effective read/create access checked; ACL ownership and access by other accounts were not verified.")
	}
	fmt.Fprintf(out, "Checked discovery, policy, and runtime file access; %d server(s).\n", found)
	return code
}

func checkPermissions(path string, private bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0022 != 0 {
			return errors.New("group/other write access; restrict permissions")
		}
		if private && !info.IsDir() && info.Mode().Perm()&0077 != 0 {
			return errors.New("private file is accessible by group/other; use mode 0600")
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}
