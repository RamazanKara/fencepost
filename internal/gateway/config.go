package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/policy"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string              `yaml:"listen"`
	PublicURL string              `yaml:"public_url"`
	Policy    policy.SourceConfig `yaml:"policy"`
	Lock      string              `yaml:"lock"`
	Auth      AuthConfig          `yaml:"auth"`
	Approval  InboxConfig         `yaml:"approval"`
	Servers   map[string]Upstream `yaml:"servers"`
}

type Upstream struct {
	URL     string            `yaml:"url"`
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`
	Headers map[string]string `yaml:"headers"`
	Cwd     string            `yaml:"cwd"`
}

func ReadConfig(filename string) (Config, string, error) {
	var c Config
	data, err := os.ReadFile(filename)
	if err != nil {
		return c, "", err
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if d.Decode(&c) != nil {
		return c, "", errors.New("invalid gateway configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, "", errors.New("gateway config must contain one YAML document")
	}
	base, err := filepath.Abs(filepath.Dir(filename))
	if err != nil {
		return c, "", err
	}
	return c, base, nil
}

func (c *Config) validate(base string) error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8787"
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || !policy.SafeEndpoint(c.PublicURL) || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("public_url must be an HTTPS origin (HTTP only on literal loopback)")
	}
	c.PublicURL = strings.TrimSuffix(c.PublicURL, "/")
	if c.Lock == "" {
		c.Lock = "fencepost.lock"
	}
	if !filepath.IsAbs(c.Lock) {
		c.Lock = filepath.Join(base, c.Lock)
	}
	if len(c.Servers) == 0 {
		return errors.New("gateway requires upstream servers")
	}
	validName := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for name, s := range c.Servers {
		if !validName.MatchString(name) || (s.Command == "") == (s.URL == "") {
			return errors.New("each server requires a URL-safe name and exactly one command or URL")
		}
		if s.URL != "" && !policy.SafeEndpoint(s.URL) {
			return errors.New("upstreams require HTTPS or literal loopback HTTP")
		}
		if s.Cwd != "" && !filepath.IsAbs(s.Cwd) {
			s.Cwd = filepath.Join(base, s.Cwd)
		}
		if s.Env == nil {
			s.Env = map[string]string{}
		}
		resolved, err := clientconfig.Resolve(clientconfig.Server{Name: name, Command: s.Command, Args: s.Args, Env: s.Env, Headers: s.Headers, Cwd: s.Cwd, URL: s.URL}, os.LookupEnv)
		if err != nil {
			return errors.New("cannot resolve upstream environment references")
		}
		s.Env, s.Headers, s.Args, s.Command, s.URL, s.Cwd = resolved.Env, resolved.Headers, resolved.Args, resolved.Command, resolved.URL, resolved.Cwd
		c.Servers[name] = s
	}
	if c.Approval.WebhookURL != "" && (!policy.SafeEndpoint(c.Approval.WebhookURL) || len(os.Getenv(c.Approval.HMACSecretEnv)) < 32) {
		return errors.New("approval webhook requires HTTPS and an HMAC environment secret of at least 32 bytes")
	}
	return nil
}
