package vetting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/mcp"
)

func environment(dir string) map[string]string {
	return map[string]string{"HOME": dir, "USERPROFILE": dir, "APPDATA": dir, "LOCALAPPDATA": dir, "TMP": dir, "TEMP": dir, "TMPDIR": dir, "XDG_CONFIG_HOME": dir, "XDG_CACHE_HOME": dir, "NPM_CONFIG_USERCONFIG": filepath.Join(dir, ".npmrc"), "NPM_CONFIG_CACHE": filepath.Join(dir, "cache"), "PIP_CONFIG_FILE": os.DevNull, "DOCKER_CONFIG": dir}
}

func command(ctx context.Context, dir, exe string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	cmd.Env = clientconfig.CleanEnv(environment(dir))
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	mcp.ConfigureProcess(cmd)
	var out limitedBuffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed (output withheld)", filepath.Base(exe))
	}
	if out.exceeded {
		return nil, errors.New("command output exceeded 16 MiB")
	}
	return out.data, nil
}

type limitedBuffer struct {
	data     []byte
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.data)+n > 16<<20 {
		b.exceeded = true
		return n, nil
	}
	b.data = append(b.data, p...)
	return n, nil
}

func npmCommand() (string, []string, error) {
	exe, err := exec.LookPath("npm")
	if err != nil {
		return "", nil, errors.New("npm is required to vet npm packages")
	}
	if runtime.GOOS == "windows" {
		node, err := exec.LookPath("node")
		if err != nil {
			return "", nil, err
		}
		cli := filepath.Join(filepath.Dir(exe), "node_modules", "npm", "bin", "npm-cli.js")
		if _, err := os.Stat(cli); err != nil {
			return "", nil, errors.New("cannot locate npm-cli.js beside npm")
		}
		return node, []string{cli}, nil
	}
	return exe, nil, nil
}

func prepare(ctx context.Context, m Metadata, dir string, network bool) (clientconfig.Server, func(), string, error) {
	s := clientconfig.Server{Name: m.Name, Source: "vet", Transport: "stdio", Cwd: dir, Env: environment(dir)}
	cleanup := func() {}
	if m.Kind == "http" {
		if !network {
			return s, cleanup, "remote HTTP requires --net", errors.New("server enumeration skipped: remote HTTP requires --net")
		}
		s.Transport, s.URL = "http", m.Entry
		return s, cleanup, "remote endpoint; server execution cannot be sandboxed locally", nil
	}
	if m.Kind == "oci" {
		name := "fencepost-vet-" + filepath.Base(dir)
		s.Command = "docker"
		s.Args = []string{"run", "--rm", "-i", "--name", name, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=256m", "--cpus=1", "--user=65534:65534", "--tmpfs=/tmp:rw,nosuid,nodev,size=64m"}
		if !network {
			s.Args = append(s.Args, "--network=none")
		}
		s.Args = append(s.Args, m.Image)
		cleanup = func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = command(ctx, dir, "docker", "rm", "-f", name)
		}
		return s, cleanup, "isolated OCI container; read-only root, no capabilities; network " + netLabel(network), nil
	}
	// Probe isolation before installing dependencies or starting package code.
	wrap, mode, err := sandbox(ctx, dir, network)
	if err != nil {
		return s, cleanup, mode, err
	}
	switch m.Kind {
	case "npm":
		pkgDir := filepath.Join(dir, "node_modules", filepath.FromSlash(m.Name))
		if m.Local != "" {
			pkgDir = filepath.Join(dir, "package")
			if err := copyPackage(m.Local, pkgDir); err != nil {
				return s, cleanup, mode, err
			}
		} else {
			exe, args, err := npmCommand()
			if err != nil {
				return s, cleanup, mode, err
			}
			args = append(args, "install", "--registry=https://registry.npmjs.org", "--ignore-scripts", "--no-audit", "--no-fund", "--no-bin-links", "--package-lock=false", "--prefix", dir, "--", m.Name+"@"+m.Version)
			if _, err := command(ctx, dir, exe, args...); err != nil {
				return s, cleanup, mode, err
			}
		}
		entry := filepath.Join(pkgDir, filepath.FromSlash(m.Entry))
		rel, err := filepath.Rel(pkgDir, entry)
		if m.Entry == "" || err != nil || !filepath.IsLocal(rel) {
			return s, cleanup, mode, errors.New("package must declare one local executable in bin")
		}
		resolved, err := filepath.EvalSymlinks(entry)
		if err != nil {
			return s, cleanup, mode, fmt.Errorf("package executable is unavailable: %w", err)
		}
		rel, err = filepath.Rel(pkgDir, resolved)
		if err != nil || !filepath.IsLocal(rel) {
			return s, cleanup, mode, errors.New("package executable escapes package directory")
		}
		s.Command, err = exec.LookPath("node")
		if err != nil {
			return s, cleanup, mode, err
		}
		s.Args = []string{entry}
	case "pypi":
		s.Command = "python"
		wheels := filepath.Join(dir, "wheels")
		target := filepath.Join(dir, "python")
		if _, err := command(ctx, dir, "python", "-m", "pip", "--isolated", "download", "--index-url", "https://pypi.org/simple", "--only-binary=:all:", "--dest", wheels, "--", m.Name+"=="+m.Version); err != nil {
			return s, cleanup, mode, err
		}
		if _, err := command(ctx, dir, "python", "-m", "pip", "--isolated", "install", "--no-index", "--only-binary=:all:", "--find-links", wheels, "--target", target, "--", m.Name+"=="+m.Version); err != nil {
			return s, cleanup, mode, err
		}
		entries, err := filepath.Glob(filepath.Join(target, "*.dist-info", "entry_points.txt"))
		if err != nil {
			return s, cleanup, mode, err
		}
		var entry string
		for _, file := range entries {
			parent := strings.ToLower(filepath.Base(filepath.Dir(file)))
			prefix := strings.ToLower(strings.ReplaceAll(m.Name, "-", "_")) + "-"
			if !strings.HasPrefix(parent, prefix) {
				continue
			}
			data, err := os.ReadFile(file)
			if err != nil {
				return s, cleanup, mode, err
			}
			section := false
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "[") {
					section = line == "[console_scripts]"
					continue
				}
				if section {
					_, value, ok := strings.Cut(line, "=")
					if ok {
						if entry != "" {
							return s, cleanup, mode, errors.New("PyPI package has multiple console entry points")
						}
						entry = strings.TrimSpace(value)
					}
				}
			}
		}
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$`).MatchString(entry) {
			return s, cleanup, mode, errors.New("PyPI package needs one simple console entry point")
		}
		module, function, _ := strings.Cut(entry, ":")
		s.Args = []string{"-I", "-c", "import sys, importlib; sys.path.insert(0, sys.argv[1]); sys.exit(getattr(importlib.import_module(sys.argv[2]), sys.argv[3])())", target, module, function}
	default:
		return s, cleanup, mode, errors.New("unsupported package kind")
	}
	s.Command, s.Args = wrap(s.Command, s.Args)
	return s, cleanup, mode, nil
}

func copyPackage(source, destination string) error {
	var total int64
	return filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if d.IsDir() && rel != "." && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("local fixture contains a symlink")
		}
		target := filepath.Join(destination, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("package contains a non-regular file")
		}
		total += info.Size()
		if total > 32<<20 {
			return errors.New("local package exceeds 32 MiB")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0600)
	})
}

func netLabel(allowed bool) string {
	if allowed {
		return "enabled (--net)"
	}
	return "disabled"
}

func sandbox(ctx context.Context, dir string, network bool) (func(string, []string) (string, []string), string, error) {
	plain := func(exe string, args []string) (string, []string) { return exe, args }
	if runtime.GOOS == "linux" {
		if exe, err := exec.LookPath("bwrap"); err == nil {
			args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--ro-bind", "/", "/", "--tmpfs", "/home", "--tmpfs", "/root", "--tmpfs", "/run", "--proc", "/proc", "--dev", "/dev", "--bind", dir, dir, "--chdir", dir}
			if network {
				args = append(args, "--share-net")
			}
			if _, err := command(ctx, dir, exe, append(append([]string{}, args...), "--", "true")...); err == nil {
				return func(cmd string, argv []string) (string, []string) {
					return exe, append(append(append([]string{}, args...), "--", cmd), argv...)
				}, "Linux namespaces via bubblewrap; home/root/run hidden, host root read-only; network " + netLabel(network), nil
			}
		}
		if exe, err := exec.LookPath("unshare"); err == nil {
			args := []string{"--user", "--map-root-user", "--mount", "--pid", "--fork", "--kill-child"}
			if !network {
				args = append(args, "--net")
			}
			if _, err := command(ctx, dir, exe, append(append([]string{}, args...), "--", "true")...); err == nil {
				return func(cmd string, argv []string) (string, []string) {
					return exe, append(append(append([]string{}, args...), "--", cmd), argv...)
				}, "Linux user/mount/PID namespaces; host filesystem still accessible; network " + netLabel(network), nil
			}
		}
	}
	mode := "best effort: temporary cwd/home and clean environment; no OS filesystem or process containment"
	if !network {
		return plain, mode, errors.New("network isolation unavailable; executable not started (use an isolated host, OCI image, or explicitly allow network with --net)")
	}
	return plain, mode + "; network enabled (--net)", nil
}

func imageMetadata(ctx context.Context, ref string) (Metadata, error) {
	m := Metadata{Kind: "oci", Name: ref, Reference: ref}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`).MatchString(ref) {
		return m, errors.New("invalid OCI reference")
	}
	m.Name, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(m.Name, ":"); i > strings.LastIndex(m.Name, "/") {
		m.Name = m.Name[:i]
	}
	dir, err := os.MkdirTemp("", "fencepost-image-")
	if err != nil {
		return m, err
	}
	defer os.RemoveAll(dir)
	if _, err := command(ctx, dir, "docker", "pull", ref); err != nil {
		return m, err
	}
	data, err := command(ctx, dir, "docker", "image", "inspect", ref)
	if err != nil {
		return m, err
	}
	var images []struct {
		ID      string    `json:"Id"`
		Created time.Time `json:"Created"`
		Config  struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal(data, &images) != nil || len(images) != 1 {
		return m, errors.New("invalid image metadata")
	}
	m.Image, m.Version, m.Published = images[0].ID, images[0].ID, images[0].Created
	labels := images[0].Config.Labels
	if who := labels["org.opencontainers.image.authors"]; who != "" {
		m.Maintainers = []string{who}
	}
	m.MCPName = labels["io.modelcontextprotocol.server.name"]
	return m, nil
}
