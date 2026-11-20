package surface

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// QueuePath is where the ranked queue lives inside a program workspace.
func QueuePath(pDir string) string { return filepath.Join(pDir, "next.json") }

// LoadPlan reads the ranked queue written by `kai next`. A missing file returns
// an empty plan and no error: "not built yet" is a normal state, not a failure.
func LoadPlan(pDir string) (Plan, error) {
	var p Plan
	b, err := os.ReadFile(QueuePath(pDir))
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, nil
}
