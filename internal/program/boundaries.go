package program

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Boundaries is the part of a program page that limits what may be tested and
// reported. It is deliberately separate from the score: a high payout does
// not make an out-of-scope target testable.
//
// Text fields are verbatim excerpts from the policy, not rewrites. Where the
// platform did not publish something, the field stays empty and the rendered
// document says so — an empty field must never be read as permission.
type Boundaries struct {
	TestingEnvironment string   `json:"testing_environment,omitempty"`
	MainnetTesting     string   `json:"mainnet_testing,omitempty"`
	PoCRequired        bool     `json:"poc_required"`
	KYCRequired        bool     `json:"kyc_required"`
	DepositRequired    bool     `json:"deposit_required"`
	RequiredHeaders    []string `json:"required_headers,omitempty"`
	InScopeText        string   `json:"in_scope_text,omitempty"`
	OutOfScopeText     string   `json:"out_of_scope_text,omitempty"`
	ProhibitedText     string   `json:"prohibited_text,omitempty"`
	EligibilityText    string   `json:"eligibility_text,omitempty"`
	DisclosureText     string   `json:"disclosure_text,omitempty"`
	SubmissionText     string   `json:"submission_text,omitempty"`
	SubmissionContact  []string `json:"submission_contact,omitempty"`
	ScopeIsStructured  bool     `json:"scope_is_structured,omitempty"`
	Notes              []string `json:"notes,omitempty"`
}

var (
	headerRE       = regexp.MustCompile(`(?i)\bX-[A-Za-z0-9][A-Za-z0-9-]{2,}\b`)
	noMainnetRE    = regexp.MustCompile(`(?i)(do\s+not\s+test|not\s+test|no\s+testing|testing\s+(?:on|against)|must\s+not\s+test)[^\n]{0,100}\b(mainnet|production|live\s+(?:system|service|deployment))`)
	mainnetAllowRE = regexp.MustCompile(`(?i)(mainnet.*(?:is|are) in scope|testing on mainnet (?:is )?allowed|in scope.*mainnet assets)`)
	pocRE          = regexp.MustCompile(`(?i)(poc|proof of concept)[^\n]{0,40}(required|must|always)|required[^\n]{0,40}(poc|proof of concept)`)
	kycRE          = regexp.MustCompile(`(?i)\bkyc\b|know your customer|identity verification|proof of identity`)
	depositRE      = regexp.MustCompile(`(?i)deposit (?:is )?required`)
	hintRE         = regexp.MustCompile(`(?s)\{%[^%]*%\}`)
	emailRE        = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

// plain strips markdown/hint markup so keyword matching is not defeated by
// "Do **not** test" or GitBook "{% hint %}" blocks. Verbatim sections keep
// the original markup.
func plain(s string) string {
	s = hintRE.ReplaceAllString(s, " ")
	s = strings.NewReplacer("**", "", "__", "", "`", "", "\\", "").Replace(s)
	return s
}

// ExtractBoundaries reads the policy text. It never upgrades a missing rule to
// "allowed": absence of a phrase means "unknown", not permission.
func ExtractBoundaries(policy, confidence string) Boundaries {
	b := Boundaries{MainnetTesting: "unknown", TestingEnvironment: "unknown"}
	if strings.TrimSpace(policy) == "" {
		b.Notes = append(b.Notes, "no policy text was available — nothing can be assumed about scope or rules")
		return b
	}

	text := plain(policy)
	b.InScopeText = trimExcerpt(sections(policy, "in scope", "assets in scope", "scope"))
	b.OutOfScopeText = trimExcerpt(sectionByTitle(policy, "out of scope", "not in scope", "exclusions"))
	b.ProhibitedText = trimExcerpt(sectionByTitle(policy, "prohibited", "not eligible", "what we're not looking for", "ineligibility"))
	b.EligibilityText = trimExcerpt(sectionByTitle(policy, "eligibility", "who can participate", "requirements"))
	b.DisclosureText = trimExcerpt(sectionByTitle(policy, "disclosure", "responsible publication", "confidentiality"))
	b.SubmissionText = trimExcerpt(sectionByTitle(policy, "submission", "how to report", "submit a bug", "report triage", "submitting an eligible report"))

	// Many policies put contact and confidentiality rules inside bullets
	// instead of a heading. Fall back to keyword lines rather than report
	// "not published" when the text is clearly there.
	if b.SubmissionText == "" {
		b.SubmissionText = trimExcerpt(linesMatching(policy, "security@", "submit your report", "send your report", "report directly"))
	}
	if b.DisclosureText == "" {
		b.DisclosureText = trimExcerpt(linesMatching(policy, "confidential", "do not disclose", "no public disclosure", "public acknowledgment"))
	}
	if b.EligibilityText == "" {
		b.EligibilityText = trimExcerpt(linesMatching(policy, "first report", "not already known", "reproducible", "conflict of interest", "kyc"))
	}
	for _, e := range emailRE.FindAllString(policy, -1) {
		e = strings.ToLower(e)
		if strings.HasPrefix(e, "noreply") || strings.HasPrefix(e, "no-reply") {
			continue
		}
		found := false
		for _, x := range b.SubmissionContact {
			if x == e {
				found = true
			}
		}
		if !found {
			b.SubmissionContact = append(b.SubmissionContact, e)
		}
	}
	sort.Strings(b.SubmissionContact)

	for _, h := range headerRE.FindAllString(policy, -1) {
		name := strings.ToUpper(h)
		if name == "HTTP" || name == "HTML" || name == "HTTPS" {
			continue
		}
		found := false
		for _, existing := range b.RequiredHeaders {
			if existing == name {
				found = true
			}
		}
		if !found {
			b.RequiredHeaders = append(b.RequiredHeaders, name)
		}
	}
	sort.Strings(b.RequiredHeaders)

	b.PoCRequired = pocRE.MatchString(text)
	b.KYCRequired = kycRE.MatchString(text)
	b.DepositRequired = depositRE.MatchString(text)

	switch {
	case noMainnetRE.MatchString(text):
		b.MainnetTesting = "forbidden"
		if regexp.MustCompile(`(?i)testnet|local fork|foundry|simulated environment`).MatchString(text) {
			b.TestingEnvironment = "testnet-or-local-fork"
		}
	case mainnetAllowRE.MatchString(text):
		b.MainnetTesting = "explicitly-allowed"
		b.TestingEnvironment = "mainnet"
	}

	if b.MainnetTesting == "forbidden" {
		b.Notes = append(b.Notes, "do not send test traffic to mainnet/live services — use testnet or local forks")
	}
	if b.PoCRequired {
		b.Notes = append(b.Notes, "a working proof of concept is required for a payable report")
	}
	if b.KYCRequired {
		b.Notes = append(b.Notes, "identity/KYC is required to be eligible for a payout")
	}
	if b.DepositRequired {
		b.Notes = append(b.Notes, "a deposit is required to submit")
	}
	if len(b.RequiredHeaders) > 0 {
		b.Notes = append(b.Notes, "research headers required: "+strings.Join(b.RequiredHeaders, ", "))
	}
	if len(b.SubmissionContact) > 0 {
		b.Notes = append(b.Notes, "submit directly to "+strings.Join(b.SubmissionContact, ", ")+" — check the policy for third-party-platform restrictions")
	}
	if strings.EqualFold(confidence, "heuristic") {
		b.Notes = append(b.Notes, "these rules were extracted from page text — re-read policy.md before testing")
	}
	if b.OutOfScopeText == "" {
		b.Notes = append(b.Notes, "no out-of-scope section was found in the text — absence is not permission; check policy.md")
	}
	return b
}

func yesNotStated(v bool) string {
	if v {
		return "yes — stated in policy"
	}
	return "not stated in policy"
}

// linesMatching returns lines containing any of the given needles, with a
// small amount of surrounding context for list items.
func linesMatching(policy string, needles ...string) string {
	var out []string
	for _, line := range strings.Split(policy, "\n") {
		low := strings.ToLower(plain(line))
		for _, n := range needles {
			if strings.Contains(low, strings.ToLower(n)) {
				out = append(out, strings.TrimSpace(line))
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

// sectionByTitle returns the first section whose heading contains one of the
// given words, stopping at the next heading.
func sectionByTitle(policy string, words ...string) string {
	var capture bool
	var out []string
	for _, line := range strings.Split(policy, "\n") {
		if strings.HasPrefix(line, "## ") {
			if capture {
				break
			}
			low := strings.ToLower(strings.TrimPrefix(line, "## "))
			for _, w := range words {
				if strings.Contains(low, strings.ToLower(w)) {
					capture = true
					out = append(out, strings.TrimPrefix(line, "## "))
					break
				}
			}
			continue
		}
		if capture && strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	result := strings.Join(out, "\n")
	// A heading with no body is not a rule; do not dress it up as one.
	if !strings.Contains(result, "\n") {
		return ""
	}
	return result
}

func trimExcerpt(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 60 {
		lines = lines[:60]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// Markdown renders the boundaries as a standalone reference document.
func (b Boundaries) Markdown() string {
	var out strings.Builder
	out.WriteString("## Testing boundaries\n\n")
	fmt.Fprintf(&out, "| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&out, "| Mainnet / live testing | %s |\n", b.MainnetTesting)
	fmt.Fprintf(&out, "| Expected environment | %s |\n", b.TestingEnvironment)
	fmt.Fprintf(&out, "| PoC required | %s |\n", yesNotStated(b.PoCRequired))
	fmt.Fprintf(&out, "| KYC / identity | %s |\n", yesNotStated(b.KYCRequired))
	fmt.Fprintf(&out, "| Deposit | %s |\n", yesNotStated(b.DepositRequired))
	if len(b.RequiredHeaders) > 0 {
		fmt.Fprintf(&out, "| Required headers | `%s` |\n", strings.Join(b.RequiredHeaders, "`, `"))
	}
	if len(b.SubmissionContact) > 0 {
		fmt.Fprintf(&out, "| Report to | `%s` |\n", strings.Join(b.SubmissionContact, "`, `"))
	}
	out.WriteString("\n")

	textSection := func(title, text string) {
		out.WriteString("### " + title + "\n\n")
		if text == "" {
			if title == "In scope (verbatim)" && b.ScopeIsStructured {
				out.WriteString("Scope is published as structured assets — see `intake.json` and the host rules above.\n\n")
				return
			}
			out.WriteString("Not published in the page text. That is not permission — read `policy.md`.\n\n")
			return
		}
		out.WriteString("```text\n" + text + "\n```\n\n")
	}
	textSection("In scope (verbatim)", b.InScopeText)
	textSection("Out of scope (verbatim)", b.OutOfScopeText)
	textSection("Prohibited / not eligible (verbatim)", b.ProhibitedText)
	textSection("Eligibility (verbatim)", b.EligibilityText)
	textSection("Submission (verbatim)", b.SubmissionText)
	textSection("Disclosure (verbatim)", b.DisclosureText)

	if len(b.Notes) > 0 {
		out.WriteString("### Operator notes\n\n")
		for _, n := range b.Notes {
			fmt.Fprintf(&out, "- %s\n", n)
		}
		out.WriteString("\n")
	}
	return out.String()
}

// BoundariesMarkdown is the full handoff document for one program.
func (in *Intake) BoundariesMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Boundaries — %s\n\n", in.Name)
	fmt.Fprintf(&b, "Source: %s\n", in.URL)
	fmt.Fprintf(&b, "Fetched: %s · confidence: `%s` · platform: `%s`\n\n",
		in.FetchedAt.Format("2006-01-02 15:04 MST"), in.confidenceLabel(), in.Platform)

	b.WriteString("## Enforceable host rules\n\n")
	sc := in.Scope()
	if len(sc.In) == 0 {
		b.WriteString("None. `scope.txt` is empty and recon will refuse to run. ")
		b.WriteString("Add rules manually after reading `policy.md`, or rerun intake with `--trust-scope`.\n\n")
	} else {
		for _, r := range sc.In {
			fmt.Fprintf(&b, "- IN `%s`\n", r)
		}
		b.WriteString("\n")
	}
	for _, r := range sc.Out {
		fmt.Fprintf(&b, "- OUT `%s`\n", r)
	}
	if len(sc.Out) > 0 {
		b.WriteString("\n")
	}
	if len(sc.PathOnly) > 0 {
		b.WriteString("Path-restricted assets — deliberately NOT enabled as host rules:\n\n")
		for _, a := range sc.PathOnly {
			fmt.Fprintf(&b, "- `%s`\n", a.Identifier)
		}
		b.WriteString("\n")
	}
	if len(sc.NonWeb) > 0 {
		b.WriteString("In scope but not host-based:\n\n")
		for _, a := range sc.NonWeb {
			fmt.Fprintf(&b, "- `%s` (%s)%s\n", a.Identifier, a.Type, bountyMark(a))
		}
		b.WriteString("\n")
	}
	if len(sc.OutNonWeb) > 0 {
		b.WriteString("Out of scope, not host-based:\n\n")
		for _, a := range sc.OutNonWeb {
			fmt.Fprintf(&b, "- `%s` (%s)\n", a.Identifier, a.Type)
		}
		b.WriteString("\n")
	}
	if len(in.Candidates) > 0 && !in.TrustScope {
		fmt.Fprintf(&b, "%d host candidate(s) from prose are NOT enabled. Verify them in `intake.json`.\n\n", len(in.Candidates))
	}
	b.WriteString(in.Boundaries.Markdown())
	return b.String()
}
