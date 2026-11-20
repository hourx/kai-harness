package audit

import "testing"

// The mainnet claim check used to compare a string against its own superstring,
// so it passed no matter what the brief said. These cases pin the real
// behaviour: it fails only on a contradiction with intake.
func TestFalseMainnetClaim(t *testing.T) {
	cases := []struct {
		name   string
		brief  string
		intake string
		want   bool
	}{
		{"contradiction", "mainnet testing is forbidden for this program", "Mainnet testing is allowed on testnet funds", true},
		{"intake agrees forbidden", "mainnet testing is forbidden", "Mainnet testing is forbidden", false},
		{"no intake verdict", "mainnet testing is forbidden", "", false},
		{"brief silent", "scope: *.example.com", "Mainnet testing is allowed", false},
	}
	for _, c := range cases {
		if got := falseMainnetClaim(c.brief, c.intake); got != c.want {
			t.Errorf("%s: falseMainnetClaim = %v, want %v", c.name, got, c.want)
		}
	}
}
