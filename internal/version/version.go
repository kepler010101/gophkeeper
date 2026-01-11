// Package version holds build metadata.
package version

// Version is the build version string.
var Version = "dev"

// BuildDate is the build timestamp.
var BuildDate = "unknown"

// String returns a formatted version line.
func String() string {
	return "gophkeeper version=" + Version + " buildDate=" + BuildDate
}
