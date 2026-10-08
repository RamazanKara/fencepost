package policy

import (
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var jsonPath = regexp.MustCompile(`^\$(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[(?:[0-9]+|\*)\])+$`)
var pathPart = regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_-]*)|\[([0-9]+|\*)\]`)

func parsePath(path string) ([]string, error) {
	if !jsonPath.MatchString(path) {
		return nil, errors.New("JSON paths use $.field, [index], and [*]")
	}
	var parts []string
	for _, m := range pathPart.FindAllStringSubmatch(path, -1) {
		if m[1] != "" {
			parts = append(parts, "."+m[1])
		} else {
			parts = append(parts, m[2])
		}
	}
	return parts, nil
}

func (a Argument) match(args map[string]any) bool {
	values := []any{args}
	for _, part := range a.parts {
		var next []any
		for _, value := range values {
			if strings.HasPrefix(part, ".") {
				object, ok := value.(map[string]any)
				child, found := object[part[1:]]
				if !ok || !found {
					return false
				}
				next = append(next, child)
			} else {
				array, ok := value.([]any)
				if !ok || len(array) == 0 {
					return false
				}
				if part == "*" {
					next = append(next, array...)
				} else {
					i, err := strconv.Atoi(part)
					if err != nil || i >= len(array) {
						return false
					}
					next = append(next, array[i])
				}
			}
		}
		values = next
	}
	for _, value := range values {
		if !a.matchValue(value) {
			return false
		}
	}
	return len(values) > 0
}

func (a Argument) matchValue(value any) bool {
	if a.Enum != nil {
		found := false
		for _, allowed := range a.Enum {
			found = found || reflect.DeepEqual(value, allowed)
		}
		if !found {
			return false
		}
	}
	if a.PathPrefix == nil && a.Host == nil && a.pattern == nil && a.MaxLength == nil {
		return true
	}
	s, ok := value.(string)
	if !ok || (a.MaxLength != nil && utf8.RuneCountInString(s) > *a.MaxLength) || (a.pattern != nil && !a.pattern.MatchString(s)) {
		return false
	}
	if a.PathPrefix != nil && !pathAllowed(s, a.PathPrefix) {
		return false
	}
	if a.Host != nil {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" || strings.ContainsAny(s, "\\\x00\r\n\t") {
			return false
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return false
			}
		}
		host, err := canonicalHost(u.Hostname())
		if err != nil {
			return false
		}
		for _, allowed := range a.Host {
			if host == allowed {
				return true
			}
		}
		return false
	}
	return true
}

var idn = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.VerifyDNSLength(true), idna.Transitional(false))

func canonicalHost(host string) (string, error) {
	if host == "" || strings.ContainsAny(host, "%/\\@[] \t\r\n") {
		return "", errors.New("invalid host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.String() != strings.ToLower(host) || ip.Is4In6() {
			return "", errors.New("noncanonical IP")
		}
		return ip.String(), nil
	}
	host, err := idn.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || host == "" {
		return "", errors.New("invalid DNS name")
	}
	host = strings.ToLower(host)
	// Browsers and fetch libraries can interpret numeric/hex final labels as IPv4.
	last := host[strings.LastIndex(host, ".")+1:]
	digits := true
	for _, c := range last {
		if c < '0' || c > '9' {
			digits = false
			break
		}
	}
	if digits || strings.HasPrefix(last, "0x") {
		return "", errors.New("ambiguous numeric host")
	}
	return host, nil
}

func SafeEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	ip, _ := netip.ParseAddr(u.Hostname())
	return u.Scheme == "https" || (u.Scheme == "http" && ip.IsLoopback())
}

func pathAllowed(raw string, roots []string) bool {
	if !filepath.IsAbs(raw) || strings.ContainsAny(raw, "%\x00") || strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, "//") {
		return false
	}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." || (runtime.GOOS == "windows" && part != filepath.VolumeName(raw) && (strings.Contains(part, ":") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " "))) {
			return false
		}
	}
	resolved, err := resolvePath(raw)
	if err != nil {
		return false
	}
	for _, root := range roots {
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		// The policy loader resolves existing roots. Refuse a later replacement
		// of that directory (or an ancestor) with a link to another location.
		if rel, err := filepath.Rel(root, resolvedRoot); err != nil || rel != "." {
			continue
		}
		relative, err := filepath.Rel(resolvedRoot, resolved)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return true
		}
	}
	return false
}

func resolvePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// A dangling symlink is not a new file; never treat its target as absent.
	if _, statErr := os.Lstat(path); statErr == nil {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolved, err = resolvePath(parent)
	return filepath.Join(resolved, filepath.Base(path)), err
}
