package surface

import (
	"time"

	"github.com/hourx/kai-harness/internal/outcome"
)

// Outcome modifiers: the only ranking input that depends on history. Declared
// in one block so the whole feedback policy is readable at once.
const (
	findingLift   = 40
	siblingLift   = 20
	staleNegation = -20
	staleInfo     = -10
)

// ApplyOutcomes re-ranks the queue with the recorded outcome history and returns
// how many targets were dropped outright. Deterministic: the same items, the
// same log and the same surface timestamp always yield the same plan, so a
// difference between two runs means the surface or the history changed.
//
// Rules:
//   - a target classified *after* the last surface change is not worth a slot:
//     a negative or an informational is dropped, not merely demoted;
//   - a stale classification (the surface changed since) stays in the queue with
//     a penalty and a note, so a change can never hide untested work;
//   - a target that produced a finding is lifted, and so are its cluster
//     siblings — the same object root usually means the same bug;
//   - an unparseable timestamp counts as stale, so a corrupt log cannot hide
//     anything.
func ApplyOutcomes(p *Plan, tbl *outcome.Table, surfaceTS time.Time) int {
	if p == nil || tbl == nil || tbl.Len() == 0 {
		return 0
	}
	surfaceTS = surfaceTS.UTC()

	// Count which targets in each cluster already yielded a finding, then lift
	// their peers in a second pass, so the order of p.Items cannot change the
	// result. A target that produced the finding is not its own sibling.
	proven := map[string]map[string]bool{}
	for _, it := range p.Items {
		if r, ok := tbl.Last(it.Target); ok && outcome.Yields(r.Status) {
			if proven[it.Cluster] == nil {
				proven[it.Cluster] = map[string]bool{}
			}
			proven[it.Cluster][it.Target] = true
		}
	}

	kept := make([]Hypothesis, 0, len(p.Items))
	dropped := 0
	for _, it := range p.Items {
		r, ok := tbl.Last(it.Target)
		if !ok {
			if note, lift := siblingNote(it.Cluster, it.Target, proven); lift {
				it.Score += siblingLift
				it.Why = append(it.Why, note)
			}
			kept = append(kept, it)
			continue
		}
		if outcome.Yields(r.Status) {
			it.Score += findingLift
			if note, lift := siblingNote(it.Cluster, it.Target, proven); lift {
				it.Score += siblingLift
				it.Why = append(it.Why, note)
			}
			it.Why = append(it.Why, "produced a "+r.Status+" ("+r.TS+")")
			kept = append(kept, it)
			continue
		}
		stale := !outcome.Fresh(r, surfaceTS)
		if !stale {
			dropped++
			continue
		}
		if r.Status == outcome.StatusNegation {
			it.Score += staleNegation
		} else {
			it.Score += staleInfo
		}
		it.Why = append(it.Why, r.Status+" before the last surface change — retest only if the surface changed since")
		kept = append(kept, it)
	}
	p.Items = kept
	p.Clusters = filterClusters(p.Clusters, p.Items)
	return dropped
}

// siblingNote reports whether another target in the same cluster already
// produced a finding. The target that produced it is not its own sibling.
func siblingNote(cluster, target string, proven map[string]map[string]bool) (string, bool) {
	for t := range proven[cluster] {
		if t != target {
			return "cluster sibling produced a finding", true
		}
	}
	return "", false
}

// filterClusters keeps the derived cluster view consistent with the surviving
// items: dropped targets disappear from their cluster, and a cluster without at
// least two surviving members is no longer a cluster.
func filterClusters(clusters []Cluster, items []Hypothesis) []Cluster {
	live := make(map[string]bool, len(items))
	for _, it := range items {
		live[it.Target] = true
	}
	out := make([]Cluster, 0, len(clusters))
	for _, c := range clusters {
		keep := c.Targets[:0]
		for _, t := range c.Targets {
			if live[t] {
				keep = append(keep, t)
			}
		}
		if len(keep) > 1 {
			c.Targets = keep
			c.Count = len(keep)
			out = append(out, c)
		}
	}
	for i := range items {
		if len(items[i].Variants) == 0 {
			continue
		}
		var keep []string
		for _, v := range items[i].Variants {
			if live[v] {
				keep = append(keep, v)
			}
		}
		items[i].Variants = keep
	}
	return out
}

// ClusterOf returns the cluster key of a target, for callers outside this
// package that need to group outcomes the same way the plan does.
func ClusterOf(target string) string { return clusterKey(target) }
