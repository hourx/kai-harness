package program

import "testing"

func TestSuggestName(t *testing.T) {
	cases := map[string]string{
		"https://hackerone.com/anthropic?type=team": "anthropic",
		"temu": "temu",
		"https://docs.ticko.xyz/resources/ticko-bug-bounty":                 "ticko-bug-bounty",
		"https://immunefi.com/bug-bounty/beanstalk/information/":            "beanstalk",
		"https://cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be": "cantina",
	}
	for raw, want := range cases {
		if got := SuggestName(raw); got != want {
			t.Errorf("SuggestName(%q) = %q, want %q", raw, got, want)
		}
	}
}
