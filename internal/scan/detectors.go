package scan

import (
	"regexp"
	"strings"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/rulebundle"
)

func HiddenInstructions(text string) bool { return rulebundle.Match(stripInvisible(text)) }

var secretWord = regexp.MustCompile(`[A-Za-z0-9_+=.-]{24,}`)

// RedactSecrets shares FP005's token, sensitive-key, and entropy detectors.
func RedactSecrets(key, value string) (string, map[string]int) {
	hits := map[string]int{}
	replace := func(kind string) string {
		hits[kind]++
		return "[redacted:" + kind + "]"
	}
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
	if len(hits) == 0 && secret(key, value) {
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
