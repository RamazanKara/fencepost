package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RamazanKara/fencepost/internal/approval"
	"github.com/RamazanKara/fencepost/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

type AuthConfig struct {
	Issuer           string            `yaml:"issuer"`
	ClientNames      map[string]string `yaml:"client_names"`
	BrowserClientID  string            `yaml:"browser_client_id"`
	BrowserSecretEnv string            `yaml:"browser_secret_env"`
	APIKeys          []APIKey          `yaml:"api_keys"`
}

type APIKey struct {
	Env             string `yaml:"env"`
	policy.Identity `yaml:",inline"`
}

type claims struct {
	jwt.RegisteredClaims
	Groups          []string `json:"groups"`
	ClientID        string   `json:"client_id"`
	AuthorizedParty string   `json:"azp"`
}

type signingKey struct {
	algorithm string
	key       any
}
type login struct {
	verifier string
	expires  time.Time
}
type browserSession struct {
	token   string
	expires time.Time
}
type staticKey struct {
	hash     [32]byte
	identity policy.Identity
}

type authenticator struct {
	config                          AuthConfig
	client                          *http.Client
	keysURL, authorizeURL, tokenURL string
	responseIssuer                  bool
	static                          []staticKey
	mu                              sync.Mutex
	keys                            map[string]signingKey
	refreshed                       time.Time
	logins                          map[string]login
	sessions                        map[string]browserSession
}

func newAuthenticator(ctx context.Context, config AuthConfig) (*authenticator, error) {
	a := &authenticator{config: config, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		keys: map[string]signingKey{}, logins: map[string]login{}, sessions: map[string]browserSession{}}
	for _, key := range config.APIKeys {
		secret := os.Getenv(key.Env)
		if len(secret) < 32 || key.User == "" || key.Client == "" {
			return nil, errors.New("API keys require an environment secret of at least 32 bytes, user and client")
		}
		a.static = append(a.static, staticKey{sha256.Sum256([]byte(secret)), key.Identity})
	}
	if config.Issuer == "" {
		if len(a.static) == 0 || config.BrowserClientID != "" {
			return nil, errors.New("authentication requires an issuer or API keys")
		}
		return a, nil
	}
	if !policy.SafeEndpoint(config.Issuer) {
		return nil, errors.New("issuer must use HTTPS or literal loopback HTTP")
	}
	var discovery struct {
		Issuer         string   `json:"issuer"`
		JWKS           string   `json:"jwks_uri"`
		Authorize      string   `json:"authorization_endpoint"`
		Token          string   `json:"token_endpoint"`
		Challenges     []string `json:"code_challenge_methods_supported"`
		ResponseIssuer bool     `json:"authorization_response_iss_parameter_supported"`
	}
	if err := a.getJSON(ctx, strings.TrimSuffix(config.Issuer, "/")+"/.well-known/openid-configuration", &discovery); err != nil {
		return nil, errors.New("OIDC discovery failed")
	}
	if discovery.Issuer != config.Issuer || !policy.SafeEndpoint(discovery.JWKS) {
		return nil, errors.New("OIDC issuer or JWKS endpoint mismatch")
	}
	a.keysURL, a.authorizeURL, a.tokenURL, a.responseIssuer = discovery.JWKS, discovery.Authorize, discovery.Token, discovery.ResponseIssuer
	if config.BrowserClientID != "" && (!policy.SafeEndpoint(a.authorizeURL) || !policy.SafeEndpoint(a.tokenURL) || !slices.Contains(discovery.Challenges, "S256")) {
		return nil, errors.New("browser sign-in requires secure authorization/token endpoints and PKCE S256")
	}
	if config.BrowserSecretEnv != "" && os.Getenv(config.BrowserSecretEnv) == "" {
		return nil, errors.New("browser client secret environment variable is empty")
	}
	if err := a.refresh(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *authenticator) getJSON(ctx context.Context, endpoint string, value any) error {
	r, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || resp.StatusCode != http.StatusOK {
		return errors.New("invalid issuer response")
	}
	return json.Unmarshal(data, value)
}

func (a *authenticator) refresh(ctx context.Context) error {
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E, Crv, X, Y string
			KeyOps                              []string `json:"key_ops"`
		}
	}
	if err := a.getJSON(ctx, a.keysURL, &set); err != nil {
		return errors.New("JWKS fetch failed")
	}
	keys := map[string]signingKey{}
	for _, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.KeyOps != nil && !slices.Contains(k.KeyOps, "verify")) {
			continue
		}
		decode := func(raw string) []byte { b, _ := base64.RawURLEncoding.DecodeString(raw); return b }
		var key any
		alg := ""
		switch k.Kty {
		case "RSA":
			n, e := new(big.Int).SetBytes(decode(k.N)), new(big.Int).SetBytes(decode(k.E))
			if n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
				continue
			}
			key, alg = &rsa.PublicKey{N: n, E: int(e.Int64())}, "RS256"
		case "EC":
			x, y := decode(k.X), decode(k.Y)
			if k.Crv != "P-256" || len(x) != 32 || len(y) != 32 {
				continue
			}
			parsed, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
			if err != nil {
				continue
			}
			key, alg = parsed, "ES256"
		case "OKP":
			x := decode(k.X)
			if k.Crv != "Ed25519" || len(x) != ed25519.PublicKeySize {
				continue
			}
			key, alg = ed25519.PublicKey(x), "EdDSA"
		}
		if key == nil || (k.Alg != "" && k.Alg != alg) {
			continue
		}
		if _, duplicate := keys[k.Kid]; duplicate {
			return errors.New("duplicate JWKS key ID")
		}
		keys[k.Kid] = signingKey{alg, key}
	}
	if len(keys) == 0 {
		return errors.New("JWKS contains no supported signing keys")
	}
	a.keys, a.refreshed = keys, time.Now()
	return nil
}

func (a *authenticator) validate(ctx context.Context, raw, audience string) (policy.Identity, time.Time, error) {
	invalid := errors.New("invalid access token")
	if a.config.Issuer == "" || len(raw) > 32<<10 {
		return policy.Identity{}, time.Time{}, invalid
	}
	c := &claims{}
	_, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		a.mu.Lock()
		defer a.mu.Unlock()
		key, ok := a.keys[kid]
		if time.Since(a.refreshed) > 5*time.Minute || (!ok && time.Since(a.refreshed) > 30*time.Second) {
			if err := a.refresh(ctx); err != nil {
				return nil, err
			}
			key, ok = a.keys[kid]
		}
		if !ok || key.algorithm != t.Method.Alg() {
			return nil, invalid
		}
		return key.key, nil
	}, jwt.WithValidMethods([]string{"RS256", "ES256", "EdDSA"}), jwt.WithIssuer(a.config.Issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || c.Subject == "" {
		return policy.Identity{}, time.Time{}, invalid
	}
	client := c.ClientID
	if client == "" {
		client = c.AuthorizedParty
	}
	if client == "" {
		return policy.Identity{}, time.Time{}, invalid
	}
	if name := a.config.ClientNames[client]; name != "" {
		client = name
	}
	return policy.Identity{User: c.Subject, Groups: c.Groups, Client: client}, c.ExpiresAt.Time, nil
}

func (a *authenticator) identity(r *http.Request, audience string, browser bool) (policy.Identity, error) {
	raw := ""
	values := r.Header.Values("Authorization")
	if len(values) == 1 {
		parts := strings.Fields(values[0])
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			raw = parts[1]
		}
	}
	if len(values) > 0 && raw == "" {
		return policy.Identity{}, errors.New("invalid authorization header")
	}
	if raw != "" {
		hash := sha256.Sum256([]byte(raw))
		for _, key := range a.static {
			if subtle.ConstantTimeCompare(hash[:], key.hash[:]) == 1 {
				return key.identity, nil
			}
		}
	}
	if raw == "" && browser {
		if cookie, err := r.Cookie("fencepost_session"); err == nil {
			a.mu.Lock()
			session := a.sessions[cookie.Value]
			a.mu.Unlock()
			if time.Now().Before(session.expires) {
				raw = session.token
			}
		}
	}
	if raw == "" {
		return policy.Identity{}, errors.New("authentication required")
	}
	identity, _, err := a.validate(r.Context(), raw, audience)
	return identity, err
}

func (a *authenticator) browser(w http.ResponseWriter, r *http.Request, base string) {
	if r.Method != "GET" || a.config.BrowserClientID == "" {
		http.NotFound(w, r)
		return
	}
	secure := strings.HasPrefix(base, "https://")
	setCookie := func(name, value string, age int) {
		http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: age})
	}
	now := time.Now()
	a.mu.Lock()
	for k, v := range a.logins {
		if !now.Before(v.expires) {
			delete(a.logins, k)
		}
	}
	for k, v := range a.sessions {
		if !now.Before(v.expires) {
			delete(a.sessions, k)
		}
	}
	a.mu.Unlock()
	if r.URL.Path == "/login" {
		state, verifier := approval.Token(), approval.Token()
		a.mu.Lock()
		if len(a.logins) >= 256 {
			a.mu.Unlock()
			http.Error(w, "Busy", http.StatusTooManyRequests)
			return
		}
		a.logins[state] = login{verifier, now.Add(5 * time.Minute)}
		a.mu.Unlock()
		setCookie("fencepost_login", state, 300)
		challenge := sha256.Sum256([]byte(verifier))
		u, _ := url.Parse(a.authorizeURL)
		q := u.Query()
		for k, v := range map[string]string{"response_type": "code", "client_id": a.config.BrowserClientID, "redirect_uri": base + "/callback", "scope": "openid", "resource": base + "/approvals", "state": state, "code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256"} {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return
	}
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("fencepost_login")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "Invalid sign-in state", 400)
		return
	}
	a.mu.Lock()
	l, ok := a.logins[state]
	delete(a.logins, state)
	a.mu.Unlock()
	setCookie("fencepost_login", "", -1)
	issuer := r.URL.Query().Get("iss")
	if !ok || !now.Before(l.expires) || (issuer != "" && issuer != a.config.Issuer) || (a.responseIssuer && issuer == "") || r.URL.Query().Get("code") == "" {
		http.Error(w, "Invalid sign-in response", 400)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {r.URL.Query().Get("code")}, "client_id": {a.config.BrowserClientID}, "redirect_uri": {base + "/callback"}, "resource": {base + "/approvals"}, "code_verifier": {l.verifier}}
	req, _ := http.NewRequestWithContext(r.Context(), "POST", a.tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if a.config.BrowserSecretEnv != "" {
		req.SetBasicAuth(url.QueryEscape(a.config.BrowserClientID), url.QueryEscape(os.Getenv(a.config.BrowserSecretEnv)))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		http.Error(w, "Sign-in failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 || resp.StatusCode != 200 || json.Unmarshal(data, &token) != nil || !strings.EqualFold(token.TokenType, "Bearer") {
		http.Error(w, "Sign-in failed", http.StatusUnauthorized)
		return
	}
	_, expires, err := a.validate(r.Context(), token.AccessToken, base+"/approvals")
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}
	id := approval.Token()
	a.mu.Lock()
	if len(a.sessions) >= 256 {
		a.mu.Unlock()
		http.Error(w, "Busy", http.StatusTooManyRequests)
		return
	}
	a.sessions[id] = browserSession{token.AccessToken, expires}
	a.mu.Unlock()
	setCookie("fencepost_session", id, max(1, int(time.Until(expires).Seconds())))
	http.Redirect(w, r, "/approvals", http.StatusSeeOther)
}
