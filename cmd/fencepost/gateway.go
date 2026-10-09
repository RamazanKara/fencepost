package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/RamazanKara/fencepost/internal/gateway"
)

func runGateway(ctx context.Context, args []string, out, errOut io.Writer) (code int) {
	flags := flag.NewFlagSet("gateway", flag.ContinueOnError)
	flags.SetOutput(errOut)
	filename := flags.String("config", "gateway.yaml", "gateway YAML configuration")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errOut, "unexpected positional arguments")
		return 2
	}
	c, base, err := gateway.ReadConfig(*filename)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	g, err := gateway.New(ctx, c, base, out, errOut)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	defer func() {
		if err := g.Close(); err != nil {
			fmt.Fprintln(errOut, err)
			code = 2
		}
	}()
	if err := gateway.Serve(ctx, g, errOut); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	return 0
}
