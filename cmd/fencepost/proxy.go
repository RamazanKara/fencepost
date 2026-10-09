package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/RamazanKara/fencepost/internal/approval"
	"github.com/RamazanKara/fencepost/internal/audit"
	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/policy"
	"github.com/RamazanKara/fencepost/internal/proxy"
)

func runProxyCommands(ctx context.Context, args []string, out, errOut io.Writer) (code int) {
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	policyPath, lockPath, config, server, listen, upstream, logPath := "fencepost.yaml", "fencepost.lock", "", "", "", "", "fencepost-audit.jsonl"
	write, n := false, 20
	subcommand := ""
	var filter audit.Filter
	var from, until string
	if command == "policy" || command == "log" {
		if len(args) < 2 {
			fmt.Fprintln(errOut, "A subcommand is required.")
			return 2
		}
		subcommand = args[1]
		args = append([]string{command}, args[2:]...)
	}
	if command != "log" {
		flags.StringVar(&policyPath, "policy", policyPath, "YAML policy file")
	}
	switch command {
	case "proxy":
		flags.StringVar(&server, "server", "", "server name in policy and lock")
		flags.StringVar(&listen, "listen", "", "loopback HTTP listen address")
		flags.StringVar(&upstream, "upstream", "", "Streamable HTTP upstream URL")
		flags.StringVar(&config, "config", "", "original client config for a wrapped server")
		flags.StringVar(&lockPath, "lock", lockPath, "pin baseline")
	case "wrap", "unwrap":
		flags.StringVar(&config, "config", "", "client config (otherwise discover)")
		flags.BoolVar(&write, "write", false, "apply the displayed diff")
		flags.StringVar(&lockPath, "lock", lockPath, "pin baseline")
	case "approve":
		flags.StringVar(&listen, "listen", "127.0.0.1:0", "loopback approval address")
	case "log":
		flags.StringVar(&logPath, "file", logPath, "JSONL audit log")
		flags.IntVar(&n, "n", 20, "tail line count")
		if subcommand == "query" {
			flags.StringVar(&filter.User, "user", "", "exact user")
			flags.StringVar(&filter.Server, "server", "", "exact server")
			flags.StringVar(&filter.Tool, "tool", "", "exact tool")
			flags.StringVar(&filter.Decision, "decision", "", "exact decision")
			flags.StringVar(&from, "from", "", "inclusive RFC3339 start")
			flags.StringVar(&until, "until", "", "inclusive RFC3339 end")
		}
	case "policy":
		if subcommand == "test" {
			flags.StringVar(&logPath, "file", logPath, "recorded JSONL audit log")
		}
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(errOut, err); return 2 }
	if command != "proxy" && flags.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	if command == "log" {
		switch subcommand {
		case "query":
			for _, v := range []struct {
				raw string
				dst *time.Time
			}{{from, &filter.From}, {until, &filter.Until}} {
				if v.raw != "" {
					parsed, err := time.Parse(time.RFC3339Nano, v.raw)
					if err != nil {
						return fail(errors.New("time filters require RFC3339"))
					}
					*v.dst = parsed
				}
			}
			if !filter.From.IsZero() && !filter.Until.IsZero() && filter.From.After(filter.Until) {
				return fail(errors.New("--from must not follow --until"))
			}
			if err := audit.Query(logPath, filter, out); err != nil {
				return fail(err)
			}
		case "verify":
			count, err := audit.Verify(logPath, nil)
			if err != nil {
				return fail(err)
			}
			fmt.Fprintf(out, "Verified %d audit entries.\n", count)
		case "tail":
			if n < 1 {
				return fail(errors.New("n must be positive"))
			}
			if err := audit.Tail(logPath, n, out); err != nil {
				return fail(err)
			}
		case "stats":
			stats, err := audit.Statistics(logPath)
			if err != nil {
				return fail(err)
			}
			if err := json.NewEncoder(out).Encode(stats); err != nil {
				return fail(err)
			}
		default:
			return fail(errors.New("use log tail, verify, stats, or query"))
		}
		return 0
	}
	if command == "wrap" || command == "unwrap" {
		p, err := clientconfig.DefaultPaths()
		if err != nil {
			return fail(err)
		}
		executable, err := os.Executable()
		if err != nil {
			return fail(err)
		}
		policyPath, err = filepath.Abs(policyPath)
		if err != nil {
			return fail(err)
		}
		lockPath, err = filepath.Abs(lockPath)
		if err != nil {
			return fail(err)
		}
		if command == "wrap" {
			if _, err := policy.Read(policyPath); err != nil {
				return fail(err)
			}
		}
		edits, err := clientconfig.PlanWrap(p, config, executable, policyPath, lockPath, command == "unwrap")
		if err != nil {
			return fail(err)
		}
		for _, edit := range edits {
			fmt.Fprint(out, clientconfig.Diff(edit))
		}
		if write {
			for _, edit := range edits {
				if err := clientconfig.Apply(edit, command == "unwrap"); err != nil {
					return fail(err)
				}
			}
		}
		fmt.Fprintf(out, "%d config(s); write=%t.\n", len(edits), write)
		return 0
	}
	p, err := policy.Read(policyPath)
	if err != nil {
		return fail(err)
	}
	if command == "policy" {
		if subcommand == "test" {
			count, err := audit.PolicyDiff(logPath, p, out)
			if err != nil {
				return fail(err)
			}
			fmt.Fprintf(errOut, "%d changed or unknown policy decisions. Rates, budgets, pins and approvals are not replayed.\n", count)
			return 0
		}
		if subcommand != "check" {
			return fail(errors.New("use policy check or test"))
		}
		fmt.Fprintln(out, "Policy is valid.")
		return 0
	}
	if command == "approve" {
		if err := approval.Serve(ctx, listen, p.Approval.LocalFile, out); err != nil {
			return fail(err)
		}
		return 0
	}
	s := clientconfig.Server{Name: server, Transport: "stdio", URL: upstream}
	if config != "" {
		if flags.NArg() != 0 || upstream != "" {
			return fail(errors.New("--config cannot be combined with command or --upstream"))
		}
		paths, err := clientconfig.DefaultPaths()
		if err != nil {
			return fail(err)
		}
		servers, err := clientconfig.Discover(paths, config)
		if err != nil {
			return fail(errors.New("cannot read wrapped server config"))
		}
		matches := 0
		for _, candidate := range servers {
			if candidate.Name == server {
				s = candidate
				matches++
			}
		}
		if matches != 1 {
			return fail(errors.New("--server must identify exactly one configured server"))
		}
		s, err = clientconfig.Resolve(s, os.LookupEnv)
		if err != nil {
			return fail(err)
		}
		if s.Env == nil {
			s.Env = map[string]string{}
		}
	} else if flags.NArg() > 0 {
		s.Command, s.Args = flags.Arg(0), flags.Args()[1:]
	}
	if s.Name == "" {
		if s.URL != "" {
			s.Name = "upstream"
		} else {
			return fail(errors.New("--server is required for stdio"))
		}
	}
	if (s.URL == "") == (s.Command == "") || (listen != "" && s.URL == "") {
		return fail(errors.New("choose a command after -- or an HTTP --upstream"))
	}
	if p.Audit.Stdout && listen == "" {
		return fail(errors.New("audit stdout is unavailable when stdout carries MCP frames"))
	}
	log, err := audit.OpenConfigured(p.Audit, out)
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			fmt.Fprintln(errOut, err)
			code = 2
		}
	}()
	if s.URL != "" {
		h, err := proxy.NewHTTP(p, log, s.Name, lockPath, s.URL, s.Headers)
		if err != nil {
			return fail(err)
		}
		if listen != "" {
			err = proxy.ServeHTTP(ctx, listen, h)
		} else {
			err = proxy.Gateway(ctx, h, os.Stdin, out)
		}
		if err != nil {
			return fail(err)
		}
		return 0
	}
	e, err := proxy.New(p, log, s.Name, lockPath)
	if err != nil {
		return fail(err)
	}
	if err := proxy.Stdio(ctx, e, s, os.Stdin, out); err != nil {
		return fail(err)
	}
	return 0
}
