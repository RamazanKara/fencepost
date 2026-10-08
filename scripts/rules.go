//go:build ignore

package main

import (
	"github.com/RamazanKara/fencepost/internal/scan"
	"os"
)

func main() {
	if err := os.WriteFile("../../docs/rules.md", []byte(scan.RuleDocs()), 0644); err != nil {
		panic(err)
	}
}
