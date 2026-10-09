//go:build ignore

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RamazanKara/fencepost/internal/version"
)

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build() error {
	release := len(os.Args) == 2 && os.Args[1] == "release"
	if len(os.Args) > 1 && !release {
		return fmt.Errorf("usage: go run scripts/build.go [release]")
	}
	dir := "bin"
	if release {
		dir = "dist"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	commit, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return fmt.Errorf("read release commit: %w", err)
	}
	revision := strings.TrimSpace(string(commit))
	status, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		return err
	}
	if len(status) != 0 {
		revision += "-dirty"
	}
	date := time.Now().UTC().Format(time.RFC3339)
	ldflags := "-s -w -X github.com/RamazanKara/fencepost/internal/version.Version=" + version.Current +
		" -X github.com/RamazanKara/fencepost/internal/version.Commit=" + revision +
		" -X github.com/RamazanKara/fencepost/internal/version.Date=" + date
	var names []string
	for _, platform := range []string{"linux", "darwin", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "fencepost-"
			if release {
				name += version.Current + "-"
			}
			name += platform + "-" + arch
			if platform == "windows" {
				name += ".exe"
			}
			names = append(names, name)
		}
	}
	if release {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			known := entry.Name() == "SHA256SUMS"
			for _, name := range names {
				known = known || entry.Name() == name
			}
			if !known || entry.IsDir() {
				return fmt.Errorf("dist contains unexpected file %q; start with an empty dist directory", entry.Name())
			}
		}
	}
	index := 0
	for _, platform := range []string{"linux", "darwin", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			path := filepath.Join(dir, names[index])
			index++
			cmd := exec.Command("go", "build", "-trimpath", "-ldflags="+ldflags, "-o", path, "./cmd/fencepost")
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.EqualFold(key, "GOOS") && !strings.EqualFold(key, "GOARCH") && !strings.EqualFold(key, "CGO_ENABLED") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "GOOS="+platform, "GOARCH="+arch, "CGO_ENABLED=0")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				return err
			}
			fmt.Println(path)
		}
	}
	if release {
		sort.Strings(names)
		var sums strings.Builder
		for _, name := range names {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(data), name)
		}
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0644); err != nil {
			return err
		}
		cmd := exec.Command("docker", "build", "--build-arg", "VERSION="+version.Current, "-t", "fencepost:"+version.Current, ".")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("binaries and SHA256SUMS are ready; Docker image build failed: %w", err)
		}
	}
	return nil
}
