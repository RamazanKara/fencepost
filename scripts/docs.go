//go:build ignore

package main

import (
	"fmt"
	"github.com/RamazanKara/fencepost/internal/docsite"
	"os"
)

func main() {
	if err := docsite.Build(".", "site"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
