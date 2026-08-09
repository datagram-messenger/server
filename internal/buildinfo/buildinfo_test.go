package buildinfo

import "testing"

func TestString(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() { Version, Commit, BuildDate = oldVersion, oldCommit, oldBuildDate })
	Version, Commit, BuildDate = "v1.2.3", "abc123", "2026-01-02T03:04:05Z"

	const want = "version=v1.2.3 commit=abc123 build_date=2026-01-02T03:04:05Z"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
