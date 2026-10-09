package scan

import (
	"regexp"
	"strings"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/rulebundle"
)

func HiddenInstructions(text string) bool { return rulebundle.Match(stripInvisible(text)) }

var secretWord = regexp.MustCompile(`[A-Za-z0-9_+=.-]{24,}`)
var redactedValue = regexp.MustCompile(`^\[redacted:[a-z-]+\]$`)
var authorizationHeader = regexp.MustCompile(`(?i)\b(?:proxy-)?authorization[ \t]*:[ \t]*(?:Bearer|Basic)[ \t]+[a-z0-9._~+/-]+=*`)
var cookieHeader = regexp.MustCompile(`(?im)\b(?:set-)?cookie[ \t]*:[^\r\n]*`)
var urlCredential = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s?#]+@`)

// RedactSecrets shares FP005's token, sensitive-key, and entropy detectors.
func RedactSecrets(key, value string) (string, map[string]int) {
	hits := map[string]int{}
	replace := func(kind string) string {
		hits[kind]++
		return "[redacted:" + kind + "]"
	}
	if redactedValue.MatchString(value) {
		return value, hits
	}
	// Output and approval values are live data, including short credentials and
	// values resembling config references; config placeholder rules do not apply.
	if secretKey.MatchString(key) && strings.TrimSpace(value) != "" {
		return replace("secret"), hits
	}
	for _, detector := range []struct {
		pattern *regexp.Regexp
		kind    string
	}{{authorizationHeader, "authorization"}, {cookieHeader, "cookie"}} {
		value = detector.pattern.ReplaceAllStringFunc(value, func(header string) string {
			name, _, _ := strings.Cut(header, ":")
			return name + ": " + replace(detector.kind)
		})
	}
	value = urlCredential.ReplaceAllStringFunc(value, func(credential string) string {
		scheme, _, _ := strings.Cut(credential, "://")
		return scheme + "://" + replace("userinfo") + "@"
	})
	value = clientconfig.TokenPattern.ReplaceAllStringFunc(value, func(token string) string {
		kind := "secret"
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(lower, "gh"):
			kind = "github-token"
		case strings.HasPrefix(lower, "xox"):
			kind = "slack-token"
		case strings.HasPrefix(lower, "sk-"):
			kind = "api-key"
		case strings.HasPrefix(lower, "akia"), strings.HasPrefix(lower, "asia"):
			kind = "aws-key"
		case strings.HasPrefix(lower, "aiza"):
			kind = "google-key"
		case strings.HasPrefix(lower, "eyj"):
			kind = "jwt"
		case strings.HasPrefix(lower, "-----begin"):
			kind = "private-key"
		}
		return replace(kind)
	})
	if secret("", value) {
		return replace("secret"), hits
	}
	value = secretWord.ReplaceAllStringFunc(value, func(word string) string {
		if secret("", word) {
			return replace("secret")
		}
		return word
	})
	return value, hits
}
