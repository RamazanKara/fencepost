package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/pin"
	"github.com/RamazanKara/fencepost/internal/report"
	"github.com/RamazanKara/fencepost/internal/scan"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, "Usage: fencepost <scan|pin|verify> [options]\n\nscan    Audit configured MCP servers (--offline, --format table|json|sarif, --fail-on low|medium|high|critical)\npin     Record trusted definitions in fencepost.lock (--update server/tool)\nverify  Reconnect and detect lockfile drift\n\nAll commands accept --config file; otherwise discover installed client configs.")
		return 0
	}
	command := args[0]
	if command != "scan" && command != "pin" && command != "verify" {
		fmt.Fprintln(errOut, "Unknown command; use fencepost --help.")
		return 2
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	config := flags.String("config", "", "read only this config file")
	var offline bool
	format, failOn, update := "table", "medium", ""
	if command == "scan" {
		flags.BoolVar(&offline, "offline", false, "audit configuration without starting servers")
		flags.StringVar(&format, "format", "table", "table, json, or sarif")
		flags.StringVar(&failOn, "fail-on", "medium", "minimum failing severity: low, medium, high, critical")
	}
	if command == "pin" {
		flags.StringVar(&update, "update", "", "accept exactly one server/tool change")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errOut, "Unexpected positional arguments.")
		return 2
	}
	if command == "scan" && (scan.Rank(failOn) == 0 || (format != "table" && format != "json" && format != "sarif")) {
		fmt.Fprintln(errOut, "Invalid --format or --fail-on value.")
		return 2
	}
	paths, err := clientconfig.DefaultPaths()
	if err != nil {
		fmt.Fprintln(errOut, "Cannot resolve home or working directory.")
		return 2
	}
	servers, err := clientconfig.Discover(paths, *config)
	if err != nil {
		fmt.Fprintln(errOut, report.Safe(err.Error(), nil))
		return 2
	}
	var inventories []scan.Inventory
	connectionErrors := []scan.ConnectionError{}
	if command != "scan" || !offline {
		inventories, connectionErrors = scan.Collect(ctx, servers, 15*time.Second)
	}
	if command == "scan" {
		result := scan.Audit(servers, inventories)
		result.Errors = connectionErrors
		result = report.Clean(result, servers)
		switch format {
		case "table":
			err = report.Table(out, result, report.IsTTY(out))
		case "json":
			err = report.JSON(out, result)
		case "sarif":
			err = report.SARIF(out, result)
		}
		if err != nil {
			fmt.Fprintln(errOut, "Cannot write scan report.")
			return 2
		}
		if len(connectionErrors) > 0 {
			return 2
		}
		for _, f := range result.Findings {
			if scan.Rank(f.Severity) >= scan.Rank(failOn) {
				return 1
			}
		}
		return 0
	}
	if len(connectionErrors) > 0 {
		for _, e := range connectionErrors {
			fmt.Fprintf(errOut, "%s: %s\n", report.Safe(e.Server, servers), e.Message)
		}
		return 2
	}
	if command == "pin" && len(servers) == 0 {
		fmt.Fprintln(errOut, "No configured servers to pin.")
		return 2
	}
	current, err := pin.Snapshot(inventories)
	if err != nil {
		fmt.Fprintln(errOut, report.Safe(err.Error(), servers))
		return 2
	}
	const lockPath = "fencepost.lock"
	if command == "pin" {
		if update != "" {
			var old pin.Lock
			old, err = pin.Read(lockPath)
			if err == nil {
				current, err = pin.Update(old, current, update)
			}
		} else {
			_, statErr := os.Stat(lockPath)
			if statErr == nil {
				err = errors.New("fencepost.lock already exists; use pin --update server/tool to accept a change")
			} else if !errors.Is(statErr, os.ErrNotExist) {
				err = statErr
			}
		}
		if err == nil {
			err = pin.Write(lockPath, current)
		}
		if err != nil {
			fmt.Fprintln(errOut, report.Safe(err.Error(), servers))
			return 2
		}
		fmt.Fprintf(out, "Wrote fencepost.lock (%d server(s)).\n", len(current.Servers))
		return 0
	}
	old, err := pin.Read(lockPath)
	if err != nil {
		fmt.Fprintln(errOut, report.Safe(err.Error(), servers))
		return 2
	}
	drift := pin.Compare(old, current)
	for _, change := range drift {
		name := change.Server
		if change.Tool != "" {
			name += "/" + change.Tool
		}
		fmt.Fprintf(out, "%s: %s\n", report.Safe(name, servers), change.Kind)
		if change.Diff != "" {
			fmt.Fprint(out, report.Safe(change.Diff, servers))
		}
	}
	if len(drift) > 0 {
		return 1
	}
	fmt.Fprintln(out, "No drift detected.")
	return 0
}
