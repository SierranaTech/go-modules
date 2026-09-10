package obs

import "runtime/debug"

// Revision returns the git commit SHA the binary was built from, as
// recorded in Go's build info, or "" when it is unavailable (for example
// in `go test` or a `go run` build).
func Revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}
