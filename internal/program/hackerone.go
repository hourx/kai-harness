package program

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hourx/bountykit/internal/netx"
	"github.com/hourx/bountykit/internal/version"
)

const h1GraphQL = "https://hackerone.com/graphql"

// UserAgent identifies bountykit to public platform APIs.
func UserAgent() string {
	return "bountykit/" + version.Version + " (+https://github.com/hourx/bountykit)"
}

var h1HandleRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)

// HackerOneHandle extracts a program handle from a URL or a bare handle.
// It rejects anything that is not a public HackerOne team page.
func HackerOneHandle(raw string) (handle, canonical string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("empty program URL")
	}
	// "temu" is shorthand for the public team page. A dotted string is
	// treated as a hostname instead.
	if !strings.ContainsAny(raw, "/:. ") {
		if !h1HandleRE.MatchString(raw) {
			return "", "", fmt.Errorf("invalid HackerOne handle %q", raw)
		}
		return raw, "https://hackerone.com/" + raw, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	host := strings.ToLower(strings.TrimSuffix(u.Host, "."))
	if strings.HasPrefix(host, "www.") {
		host = strings.TrimPrefix(host, "www.")
	}
	if host != "hackerone.com" {
		return "", "", fmt.Errorf("expected a hackerone.com URL, got %q", host)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 2 {
		return "", "", fmt.Errorf("cannot find a program handle in %q", raw)
	}
	handle = parts[0]
	if !h1HandleRE.MatchString(handle) {
		return "", "", fmt.Errorf("invalid HackerOne handle %q", handle)
	}
	return handle, "https://hackerone.com/" + handle, nil
}

type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type gqlError struct {
	Message string `json:"message"`
}

type h1BountyRow struct {
	Name        *string `json:"name"`
	Low         *int    `json:"low"`
	Medium      *int    `json:"medium"`
	High        *int    `json:"high"`
	Critical    *int    `json:"critical"`
	LowMin      *int    `json:"low_minimum"`
	MediumMin   *int    `json:"medium_minimum"`
	HighMin     *int    `json:"high_minimum"`
	CriticalMin *int    `json:"critical_minimum"`
}

type h1Team struct {
	Handle         *string  `json:"handle"`
	Name           *string  `json:"name"`
	URL            *string  `json:"url"`
	Website        *string  `json:"website"`
	State          *string  `json:"state"`
	Submission     *string  `json:"submission_state"`
	Currency       *string  `json:"currency"`
	Policy         *string  `json:"policy"`
	OffersBounties *bool    `json:"offers_bounties"`
	Base           *int     `json:"base_bounty"`
	Minimum        *int     `json:"minimum_bounty"`
	TopLower       *int     `json:"top_bounty_lower_amount"`
	TopUpper       *int     `json:"top_bounty_upper_amount"`
	AvgLower       *int     `json:"average_bounty_lower_amount"`
	AvgUpper       *int     `json:"average_bounty_upper_amount"`
	Resolved       *int     `json:"resolved_report_count"`
	Reports90d     *int     `json:"reports_received_last_90_days"`
	ResponseEff    *float64 `json:"response_efficiency_percentage"`

	BountyTable *struct {
		Rows struct {
			Edges []struct {
				Node h1BountyRow `json:"node"`
			} `json:"edges"`
		} `json:"bounty_table_rows"`
	} `json:"bounty_table"`

	Metrics *struct {
		AvgCritical *float64 `json:"average_bounty_per_severity_critical"`
		AvgHigh     *float64 `json:"average_bounty_per_severity_high"`
		AvgMedium   *float64 `json:"average_bounty_per_severity_medium"`
		AvgLow      *float64 `json:"average_bounty_per_severity_low"`
		CountCrit   *int     `json:"report_count_per_severity_critical"`
		CountHigh   *int     `json:"report_count_per_severity_high"`
		CountMed    *int     `json:"report_count_per_severity_medium"`
		CountLow    *int     `json:"report_count_per_severity_low"`
	} `json:"profile_metrics_snapshot"`
}

type h1Asset struct {
	Identifier  *string `json:"asset_identifier"`
	Type        *string `json:"asset_type"`
	HumanType   *string `json:"human_asset_type"`
	Eligible    *bool   `json:"eligible_for_submission"`
	Bounty      *bool   `json:"eligible_for_bounty"`
	MaxSeverity *string `json:"max_severity"`
	Instruction *string `json:"instruction"`
}

const h1TeamQuery = `query($h:String!){ team(handle:$h){
  handle name url website state submission_state currency policy offers_bounties
  base_bounty minimum_bounty top_bounty_lower_amount top_bounty_upper_amount
  average_bounty_lower_amount average_bounty_upper_amount
  resolved_report_count reports_received_last_90_days response_efficiency_percentage
  bounty_table { bounty_table_rows(first:50){ edges { node {
    name low medium high critical low_minimum medium_minimum high_minimum critical_minimum
  } } } }
  profile_metrics_snapshot {
    average_bounty_per_severity_critical average_bounty_per_severity_high
    average_bounty_per_severity_medium average_bounty_per_severity_low
    report_count_per_severity_critical report_count_per_severity_high
    report_count_per_severity_medium report_count_per_severity_low
  }
} }`

const h1ScopeQuery = `query($h:String!,$n:Int,$after:String){ team(handle:$h){
  structured_scopes(first:$n, after:$after, archived:false){
    total_count
    pageInfo { hasNextPage endCursor }
    edges { node {
      asset_identifier asset_type human_asset_type eligible_for_submission
      eligible_for_bounty max_severity instruction
    } }
  }
} }`

type gqlTeamResponse struct {
	Data struct {
		Team *h1Team `json:"team"`
	} `json:"data"`
	Errors []gqlError `json:"errors"`
}

type gqlScopeResponse struct {
	Data struct {
		Team struct {
			StructuredScopes struct {
				TotalCount int `json:"total_count"`
				PageInfo   struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Edges []struct {
					Node h1Asset `json:"node"`
				} `json:"edges"`
			} `json:"structured_scopes"`
		} `json:"team"`
	} `json:"data"`
	Errors []gqlError `json:"errors"`
}

// FetchHackerOne reads the public directory data for one program.
func FetchHackerOne(ctx context.Context, c *netx.Client, handle string) (*Intake, error) {
	headers := map[string]string{"Origin": "https://hackerone.com", "Referer": "https://hackerone.com/" + handle}

	var tr gqlTeamResponse
	if err := gql(ctx, c, gqlRequest{Query: h1TeamQuery, Variables: map[string]any{"h": handle}}, headers, &tr); err != nil {
		return nil, err
	}
	if len(tr.Errors) > 0 {
		return nil, fmt.Errorf("HackerOne: %s", tr.Errors[0].Message)
	}
	if tr.Data.Team == nil {
		return nil, fmt.Errorf("HackerOne: program %q not found (private or does not exist)", handle)
	}
	t := tr.Data.Team
	in := &Intake{
		Platform:     "h1",
		Handle:       str(t.Handle),
		Name:         str(t.Name),
		URL:          str(t.URL),
		Website:      str(t.Website),
		State:        str(t.State),
		Submission:   str(t.Submission),
		Currency:     str(t.Currency),
		OffersBounty: t.OffersBounties != nil && *t.OffersBounties,
		Base:         num(t.Base),
		Minimum:      num(t.Minimum),
		TopLower:     num(t.TopLower),
		TopUpper:     num(t.TopUpper),
		AverageLower: num(t.AvgLower),
		AverageUpper: num(t.AvgUpper),
		Resolved:     num(t.Resolved),
		Reports90d:   num(t.Reports90d),
		ReportsKnown: true,
		ResponseEff:  flt(t.ResponseEff),
		Policy:       str(t.Policy),
		FetchedAt:    time.Now().UTC(),
	}
	if in.Name == "" {
		in.Name = in.Handle
	}
	if in.URL == "" {
		in.URL = "https://hackerone.com/" + handle
	}
	if in.Currency == "" {
		in.Currency = "USD"
	}
	in.Currency = strings.ToUpper(in.Currency)
	if t.BountyTable != nil {
		for _, e := range t.BountyTable.Rows.Edges {
			r := e.Node
			in.BountyRows = append(in.BountyRows, BountyRow{
				Name:     str(r.Name),
				Low:      num(r.Low),
				Medium:   num(r.Medium),
				High:     num(r.High),
				Critical: num(r.Critical),
				Minimums: [4]int{num(r.LowMin), num(r.MediumMin), num(r.HighMin), num(r.CriticalMin)},
			})
		}
	}
	if m := t.Metrics; m != nil {
		in.SeverityStats = map[string]SeverityStat{
			"critical": {Average: flt(m.AvgCritical), Count: num(m.CountCrit)},
			"high":     {Average: flt(m.AvgHigh), Count: num(m.CountHigh)},
			"medium":   {Average: flt(m.AvgMedium), Count: num(m.CountMed)},
			"low":      {Average: flt(m.AvgLow), Count: num(m.CountLow)},
		}
	}

	// Scope is paginated; a large program (Shopify has 34+) must not be
	// silently truncated at the first page.
	after := ""
	for page := 0; page < 10; page++ {
		var sr gqlScopeResponse
		vars := map[string]any{"h": handle, "n": 100}
		if after != "" {
			vars["after"] = after
		}
		if err := gql(ctx, c, gqlRequest{Query: h1ScopeQuery, Variables: vars}, headers, &sr); err != nil {
			return nil, err
		}
		if len(sr.Errors) > 0 {
			return nil, fmt.Errorf("HackerOne: %s", sr.Errors[0].Message)
		}
		sc := sr.Data.Team.StructuredScopes
		for _, e := range sc.Edges {
			a := e.Node
			in.Assets = append(in.Assets, Asset{
				Identifier:  str(a.Identifier),
				Type:        str(a.Type),
				HumanType:   str(a.HumanType),
				Eligible:    a.Eligible != nil && *a.Eligible,
				Bounty:      a.Bounty != nil && *a.Bounty,
				MaxSeverity: str(a.MaxSeverity),
				Instruction: str(a.Instruction),
			})
		}
		if !sc.PageInfo.HasNextPage || sc.PageInfo.EndCursor == "" {
			break
		}
		after = sc.PageInfo.EndCursor
	}
	in.Scorecard = in.Score()
	return in, nil
}

// gql posts one query with retries. Public endpoints return 429/5xx often
// enough that a single attempt gives a false "no data" result.
func gql(ctx context.Context, c *netx.Client, req gqlRequest, headers map[string]string, out any) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		status, body, err := c.PostJSON(ctx, h1GraphQL, req, 16<<20, headers)
		switch {
		case err != nil:
			last = err
		case status != 200:
			last = fmt.Errorf("GraphQL status %d", status)
		default:
			if jsonErr := json.Unmarshal(body, out); jsonErr == nil {
				return nil
			} else {
				last = jsonErr
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-time.After(time.Duration(attempt+1) * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("HackerOne GraphQL failed after 3 attempts: %w", last)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func num(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func flt(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}
