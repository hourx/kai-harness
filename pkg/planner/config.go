package planner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Defaults for a program that turns the planner on without tuning it.
const (
	defaultMaxSteps        = 12
	defaultMaxTokensPerDay = 200000
	defaultMaxRespTokens   = 1600
)

// Config is where the planner's endpoint and its budgets live. It is read from
// the workspace first and the environment second, so one box-level router can
// serve every workspace while a single program can still point somewhere else.
type Config struct {
	Endpoint      string `json:"endpoint"`
	Key           string `json:"key,omitempty"`
	Model         string `json:"model"`
	MaxSteps      int    `json:"max_steps,omitempty"`
	MaxTokens     int    `json:"max_tokens_per_day,omitempty"`
	MaxRespTokens int    `json:"max_response_tokens,omitempty"`
	Enabled       bool   `json:"enabled"`

	// Reason is why the planner is on or off, for the report. Source names where
	// the setting came from.
	Reason string `json:"-"`
	Source string `json:"-"`
}

// ConfigPath is where a workspace stores its planner settings (mode 0600).
func ConfigPath(pDir string) string { return filepath.Join(pDir, "state", "planner.json") }

// OffPath is the kill switch. Its existence alone disables the planner, so
// turning the model off is one file, not an edit.
func OffPath(pDir string) string { return filepath.Join(pDir, "state", "planner.off") }

// LoadConfig reads the workspace file, then the environment, then the kill
// switch. The order is deliberate: a kill switch beats everything, and a secret
// on the box beats one committed next to a program.
func LoadConfig(pDir string) Config {
	c := Config{
		MaxSteps:      defaultMaxSteps,
		MaxTokens:     defaultMaxTokensPerDay,
		MaxRespTokens: defaultMaxRespTokens,
		Enabled:       true,
		Source:        "defaults",
	}
	if b, err := os.ReadFile(ConfigPath(pDir)); err == nil {
		var file Config
		if json.Unmarshal(b, &file) == nil {
			mergeConfig(&c, file)
			c.Source = ConfigPath(pDir)
		}
	}
	if v := strings.TrimSpace(os.Getenv("KAI_PLANNER_ENDPOINT")); v != "" {
		c.Endpoint, c.Source = v, "environment"
	}
	if v := strings.TrimSpace(os.Getenv("KAI_PLANNER_KEY")); v != "" {
		c.Key, c.Source = v, "environment"
	}
	if v := strings.TrimSpace(os.Getenv("KAI_PLANNER_MODEL")); v != "" {
		c.Model, c.Source = v, "environment"
	}
	if v := strings.TrimSpace(os.Getenv("KAI_PLANNER_MAX_TOKENS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.MaxTokens = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("KAI_PLANNER_MAX_STEPS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.MaxSteps = n
		}
	}

	if strings.EqualFold(strings.TrimSpace(os.Getenv("KAI_PLANNER")), "off") {
		c.Enabled = false
		c.Reason = "KAI_PLANNER=off"
	}
	if _, err := os.Stat(OffPath(pDir)); err == nil {
		c.Enabled = false
		c.Reason = "the kill switch " + OffPath(pDir) + " exists"
	}
	if c.Enabled && (c.Endpoint == "" || c.Model == "") {
		c.Enabled = false
		c.Reason = "no planner endpoint or model configured"
	}
	return c
}

func mergeConfig(dst *Config, src Config) {
	if src.Endpoint != "" {
		dst.Endpoint = src.Endpoint
	}
	if src.Key != "" {
		dst.Key = src.Key
	}
	if src.Model != "" {
		dst.Model = src.Model
	}
	if src.MaxSteps > 0 {
		dst.MaxSteps = src.MaxSteps
	}
	if src.MaxTokens > 0 {
		dst.MaxTokens = src.MaxTokens
	}
	if src.MaxRespTokens > 0 {
		dst.MaxRespTokens = src.MaxRespTokens
	}
}

// Proposer turns a config into the proposer the seam will use, or nil when the
// planner is off. It is the one place that decides between a model and the
// deterministic floor.
func (c Config) Proposer() Proposer {
	if !c.Enabled {
		return nil
	}
	return LLM{
		Endpoint:  c.Endpoint,
		Key:       c.Key,
		Model:     c.Model,
		MaxTokens: c.MaxRespTokens,
	}
}

// usageLedger is the day's spend. It resets when the date rolls over, so a
// budget is per day without a scheduler rewriting anything.
type usageLedger struct {
	Day    string `json:"day"`
	Tokens int    `json:"tokens"`
	Calls  int    `json:"calls"`
}

// UsagePath is where the day's token spend is recorded.
func UsagePath(pDir string) string { return filepath.Join(pDir, "state", "planner-usage.json") }

func today(now time.Time) string { return now.UTC().Format("2006-01-02") }

// UsageToday reads the spend for the given day. A stale ledger reads as zero,
// because the day it describes is over.
func UsageToday(pDir string, now time.Time) (tokens, calls int) {
	b, err := os.ReadFile(UsagePath(pDir))
	if err != nil {
		return 0, 0
	}
	var u usageLedger
	if json.Unmarshal(b, &u) != nil || u.Day != today(now) {
		return 0, 0
	}
	return u.Tokens, u.Calls
}

// RecordUsage adds this call's spend to the day's ledger, starting a fresh one
// when the date has moved on.
func RecordUsage(pDir string, now time.Time, tokens int) error {
	tokens0, calls := UsageToday(pDir, now)
	u := usageLedger{Day: today(now), Tokens: tokens0 + tokens, Calls: calls + 1}
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(pDir, "state"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(UsagePath(pDir), append(b, '\n'), 0o600)
}
