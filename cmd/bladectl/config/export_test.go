package config

// SetHostname replaces the hostname lookup for a test and returns a function restoring it
func SetHostname(name string) (restore func()) {
	previous := hostname
	hostname = func() (string, error) { return name, nil }
	return func() { hostname = previous }
}
