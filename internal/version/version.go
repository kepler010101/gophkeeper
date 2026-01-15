package version

// Version is the build version.
var Version = "dev"

// BuildDate is the build timestamp.
var BuildDate = "unknown"

// String formats version info.
func String() string {
	return "gophkeeper version=" + Version + " buildDate=" + BuildDate
}
