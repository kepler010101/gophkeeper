package version

import "testing"

func TestString(t *testing.T) {
	Version = "1.2.3"
	BuildDate = "2025-01-01T00:00:00Z"
	got := String()
	want := "gophkeeper version=1.2.3 buildDate=2025-01-01T00:00:00Z"
	if got != want {
		t.Fatalf("unexpected string: %s", got)
	}
}
