// Package buildinfo exposes release metadata injected by the build pipeline.
package buildinfo

import "fmt"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns a stable, human-readable version description.
func String() string {
	return fmt.Sprintf("version=%s commit=%s build_date=%s", Version, Commit, BuildDate)
}
