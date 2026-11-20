// Package strutil holds the small string helpers shared by kai's packages.
//
// One documented semantics per operation: these helpers used to be duplicated
// per package with subtly different behaviour (some dropped blank values, some
// kept them, some sorted the result), which made pack output depend on which
// copy a package happened to carry.
package strutil

import (
	"sort"
	"strings"
)

// Dash returns s, or an em dash when s is blank. Blank means empty after
// trimming, so a markdown table cell can never collapse.
func Dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// Unique drops blank values and returns the first occurrence of each remaining
// value in input order. This is the default dedupe: stable output, no surprises.
func Unique(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// UniqueGroups is Unique applied across several slices, in the order given.
func UniqueGroups(groups ...[]string) []string {
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	out := make([]string, 0, total)
	seen := make(map[string]struct{}, total)
	for _, g := range groups {
		for _, v := range g {
			if v == "" {
				continue
			}
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// UniqueSorted is Unique plus sort.Strings. Use it when the result is written
// to a file whose diff must stay stable across runs.
func UniqueSorted(in []string) []string {
	out := Unique(in)
	sort.Strings(out)
	return out
}
