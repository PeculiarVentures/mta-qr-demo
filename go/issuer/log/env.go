package log

import "os"

func envPort() string {
	if p := os.Getenv("MTA_PORT"); p != "" {
		return p
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
