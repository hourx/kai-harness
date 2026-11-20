package version

import (
	"fmt"
	"runtime/debug"
)

// Version is the release tag. Overridden at build time with
// -ldflags "-X github.com/hourx/kai-harness/pkg/version.Version=x.y.z".
var Version = "0.13.0"

// String returns the version plus the VCS revision when available.
func String() string {
	out := Version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return out
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return fmt.Sprintf("%s (%s)", out, s.Value[:7])
		}
	}
	return out
}
