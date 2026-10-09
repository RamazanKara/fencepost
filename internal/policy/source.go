package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

func readDirectory(dir string) (*Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	merged := map[string]any{}
	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != ".yaml" && filepath.Ext(entry.Name()) != ".yml") {
			continue
		}
		name := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return nil, fmt.Errorf("%s: %w", name, yamlError(err, "invalid YAML"))
		}
		if invalidNode(&node, false) != nil {
			return nil, fmt.Errorf("%s: null is only allowed inside enum values", name)
		}
		var fragment map[string]any
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&fragment); err != nil {
			return nil, fmt.Errorf("%s: invalid policy fragment", name)
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return nil, fmt.Errorf("%s: expected one document", name)
		}
		merge(merged, fragment)
	}
	data, err := yaml.Marshal(merged)
	if err != nil {
		return nil, err
	}
	base, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data, base)
	if err != nil {
		return nil, fmt.Errorf("%s (merged): %w", dir, err)
	}
	return p, nil
}

func merge(dst, src map[string]any) {
	for key, value := range src {
		old, ok := dst[key].(map[string]any)
		next, nested := value.(map[string]any)
		if ok && nested {
			merge(old, next)
		} else {
			dst[key] = value
		}
	}
}

type SourceConfig struct {
	Source       string `yaml:"source"`
	PublicKey    string `yaml:"public_key"`
	PollInterval string `yaml:"poll_interval"`
}

type Source struct {
	current    atomic.Pointer[Policy]
	mu         sync.Mutex
	config     SourceConfig
	base, etag string
	key        ed25519.PublicKey
	client     *http.Client
	interval   time.Duration
	digest     [32]byte
}

func LoadSource(ctx context.Context, config SourceConfig, base string) (*Source, error) {
	s := &Source{config: config, base: base, interval: time.Minute,
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if config.PollInterval != "" {
		var err error
		s.interval, err = time.ParseDuration(config.PollInterval)
		if err != nil || s.interval < time.Second {
			return nil, errors.New("policy poll_interval must be at least 1s")
		}
	}
	if strings.HasPrefix(config.Source, "https://") {
		key, err := base64.StdEncoding.DecodeString(config.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize || !SafeEndpoint(config.Source) {
			return nil, errors.New("remote policy requires HTTPS and a base64 ed25519 public_key")
		}
		s.key = key
	} else {
		if strings.Contains(config.Source, "://") || config.Source == "" {
			return nil, errors.New("policy source must be a file, directory, or signed HTTPS URL")
		}
		s.config.Source = absolute(base, config.Source)
	}
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Source) Current() *Policy { return s.current.Load() }

func (s *Source) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var p *Policy
	var err error
	etag := ""
	if s.key == nil {
		p, err = Read(s.config.Source)
	} else {
		req, err := http.NewRequestWithContext(ctx, "GET", s.config.Source, nil)
		if err != nil {
			return err
		}
		if s.etag != "" {
			req.Header.Set("If-None-Match", s.etag)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return errors.New("policy fetch failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotModified && s.Current() != nil {
			return nil
		}
		if resp.StatusCode != http.StatusOK {
			return errors.New("policy fetch returned unexpected status")
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil || len(data) > 1<<20 {
			return errors.New("policy response exceeds limit or is incomplete")
		}
		signature, err := base64.StdEncoding.DecodeString(resp.Header.Get("X-Fencepost-Signature"))
		if err != nil || !ed25519.Verify(s.key, data, signature) {
			return errors.New("policy signature verification failed")
		}
		p, err = Parse(data, s.base)
		if err != nil {
			return err
		}
		etag = resp.Header.Get("ETag")
	}
	if err != nil {
		return err
	}
	encoded, _ := yaml.Marshal(p)
	digest := sha256.Sum256(encoded)
	if s.Current() == nil || digest != s.digest {
		s.current.Store(p)
		s.digest = digest
	}
	s.etag = etag
	return nil
}

func (s *Source) Poll(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	defer s.client.CloseIdleConnections()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Refresh(ctx); err != nil {
				report(err)
			}
		}
	}
}
