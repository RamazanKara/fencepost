//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if err := os.MkdirAll("bin", 0755); err != nil {
		panic(err)
	}
	for _, platform := range []string{"linux", "darwin", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "bin/fencepost-" + platform + "-" + arch
			if platform == "windows" {
				name += ".exe"
			}
			cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", name, "./cmd/fencepost")
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if key != "GOOS" && key != "GOARCH" && key != "CGO_ENABLED" {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "GOOS="+platform, "GOARCH="+arch, "CGO_ENABLED=0")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(name)
		}
	}
}
