package filter

import (
	"context"
	"net"
	"net/http"
	"time"
)

// newHTTPClient returns an HTTP client that bypasses Docker's embedded DNS
// resolver (127.0.0.11) and goes directly to 8.8.8.8:53. This is required
// because the container maps port 53 to the host, which causes Docker's
// internal resolver to time out when the app tries to fetch external resources.
func newHTTPClient(timeout time.Duration) *http.Client {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	dialer := &net.Dialer{
		Timeout:  10 * time.Second,
		Resolver: resolver,
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
