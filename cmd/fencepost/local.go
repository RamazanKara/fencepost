package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/RamazanKara/fencepost/internal/console"
	"github.com/RamazanKara/fencepost/internal/report"
	"github.com/RamazanKara/fencepost/internal/rulebundle"
	"github.com/RamazanKara/fencepost/internal/vetting"
	"io"
)

func runLocal(ctx context.Context, args []string, out, errOut io.Writer) int {
	command := args[0]
	args = args[1:]
	if command == "rules" {
		if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
			fmt.Fprintln(out, "Usage: fencepost rules update --url HTTPS_BUNDLE_URL")
			return 0
		}
		if len(args) == 0 || args[0] != "update" {
			fmt.Fprintln(errOut, "usage: fencepost rules update --url https://publisher/rules.json")
			return 2
		}
		args = args[1:]
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(errOut)
	var network bool
	var endpoint, config string
	policyPath, lockPath, listen := "fencepost.yaml", "fencepost.lock", "127.0.0.1:0"
	switch command {
	case "vet":
		f.BoolVar(&network, "net", false, "allow network access to the server being vetted")
		f.StringVar(&lockPath, "lock", lockPath, "pinned package maintainer baseline")
	case "ui":
		f.StringVar(&listen, "listen", listen, "literal loopback IP and port")
		f.StringVar(&config, "config", "", "MCP client config")
		f.StringVar(&policyPath, "policy", policyPath, "local policy file")
		f.StringVar(&lockPath, "lock", lockPath, "pin baseline")
	case "rules":
		f.StringVar(&endpoint, "url", "", "HTTPS signed rules bundle URL (required; no automatic downloads)")
	}
	// Accept the natural spelling `vet package --net` as well as flags first.
	if command == "vet" && len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		args = append(append([]string{}, args[1:]...), args[0])
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(errOut, report.Safe(err.Error(), nil)); return 2 }
	if command == "vet" {
		if f.NArg() != 1 {
			return fail(errors.New("usage: fencepost vet <package or url> [--net]"))
		}
		r, err := vetting.Vet(ctx, f.Arg(0), network, lockPath)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(out, "%s: %s %s — %s\n", r.Package.Kind, report.Safe(r.Package.Name, nil), report.Safe(r.Package.Version, nil), r.Verdict)
		fmt.Fprintf(out, "Sandbox: %s\n", r.Sandbox)
		if r.Package.Registry != "" {
			fmt.Fprintf(out, "MCP registry: %s\n", report.Safe(r.Package.Registry, nil))
		}
		for _, reason := range r.Reasons {
			fmt.Fprintf(out, "- %s\n", report.Safe(reason, nil))
		}
		fmt.Fprintf(out, "%d tool(s); enumeration complete: %t; rules bundle: %d\n", len(r.Tools), r.Complete, rulebundle.Version())
		for _, tool := range r.Tools {
			fmt.Fprintf(out, "  %s\n", report.Safe(tool, nil))
		}
		fmt.Fprintln(out, "A trust report is a review aid, not a guarantee of safety.")
		if !r.Complete {
			return 2
		}
		if r.Verdict != "looks fine" {
			return 1
		}
		return 0
	}
	if f.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	if command == "ui" {
		if err := console.Serve(ctx, listen, console.Options{Config: config, Policy: policyPath, Lock: lockPath}, out); err != nil {
			return fail(err)
		}
		return 0
	}
	path, err := rulebundle.Path()
	if err != nil {
		return fail(err)
	}
	version, err := rulebundle.Update(ctx, endpoint, path)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(out, "Installed signed rules bundle %d. Restart running proxies and gateways to load it.\n", version)
	return 0
}
