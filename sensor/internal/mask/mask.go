// Package mask hides secrets in command lines before they leave the host.
// The patterns follow ingest's rules (selenne_agents/alerting/rules.py), so a
// secret masked here is one the server would have flagged; on top of that,
// the value of any flag or variable whose name says it is a secret.
package mask

import (
	"regexp"
	"strings"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),                                        // AWS access key
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),          // private key
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),                                       // GitHub token
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),                                     // Slack token
	regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b`),                             // API secret key
	regexp.MustCompile(`\bsk_sel_[A-Za-z0-9_-]{16,}\b`),                                        // Selenne key
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), // JWT
	regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}`),                      // auth headers
	regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),                                               // user:password@ in URLs
}

// a flag or assignment naming a secret: --password x, -setcookie x, TOKEN=x
var secretName = regexp.MustCompile(`(?i)(?:pass(?:word|wd)?|secret|token|api[_-]?key|cookie|credential|private[_-]?key|auth)`)

func short(s string) string {
	if len(s) > 10 {
		return s[:4] + "…" + s[len(s)-2:]
	}
	return "…"
}

// Text masks every known secret pattern in s.
func Text(s string) string {
	for _, rx := range patterns {
		s = rx.ReplaceAllStringFunc(s, func(m string) string {
			if strings.HasPrefix(m, "://") { // keep the URL readable, hide the password
				user, _, _ := strings.Cut(m[3:], ":")
				return "://" + user + ":…@"
			}
			return short(m)
		})
	}
	return s
}

// Argv masks each argument, plus the value after (or in) any argument whose
// name says it is a secret: ["-setcookie", "45WT…"], ["--token=abc"], ["DB_PASSWORD=x"].
func Argv(argv []string) []string {
	out := make([]string, len(argv))
	hideNext := false
	for i, a := range argv {
		switch {
		case hideNext:
			out[i] = "…"
			hideNext = false
		case strings.Contains(a, "="):
			name, value, _ := strings.Cut(a, "=")
			if secretName.MatchString(name) && value != "" {
				out[i] = name + "=…"
			} else {
				out[i] = Text(a)
			}
		case strings.HasPrefix(a, "-") && secretName.MatchString(a):
			out[i] = a
			hideNext = true
		default:
			out[i] = Text(a)
		}
	}
	return out
}
