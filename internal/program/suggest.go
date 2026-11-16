package program

import (
	"regexp"
	"strings"
)

var genericSlugs = map[string]bool{
	"bounty": true, "bug-bounty": true, "bugbounty": true, "security": true,
	"info": true, "information": true, "resources": true, "docs": true,
	"report": true, "submit": true, "policy": true, "overview": true,
	"program": true, "index": true, "home": true, "bounties": true,
}

var uuidLike = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// SuggestName derives a workspace slug from a program URL without network
// access. It is a suggestion: --name always wins.
func SuggestName(raw string) string {
	if h, _, err := HackerOneHandle(raw); err == nil {
		return h
	}
	u, err := parseURL(raw)
	if err != nil {
		return "program"
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	candidate := ""
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.ToLower(strings.TrimSpace(parts[i]))
		if p == "" || genericSlugs[p] || uuidLike.MatchString(p) {
			continue
		}
		candidate = p
		break
	}
	if candidate == "" {
		host := strings.ToLower(u.Hostname())
		labels := strings.Split(host, ".")
		for _, l := range labels {
			if l != "" && l != "www" && l != "docs" {
				candidate = l
				break
			}
		}
	}
	candidate = strings.ToLower(regexp.MustCompile(`[^a-z0-9._-]+`).ReplaceAllString(candidate, "-"))
	candidate = strings.Trim(candidate, "-")
	if candidate == "" {
		return "program"
	}
	return candidate
}
