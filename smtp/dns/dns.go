package dns

import (
	"context"
	"net"
	"time"
)

const timeout = 500 * time.Millisecond

var resolver = net.Resolver{}

// LookupIP replaces net.LookupIP
func LookupIP(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return resolver.LookupIP(ctx, "ip", host)
}

// LookupMX replaces net.LookupMX
func LookupMX(name string) ([]*net.MX, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return resolver.LookupMX(ctx, name)

}

// LookupAddr replaces net.LookupAddr
func LookupAddr(addr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return resolver.LookupAddr(ctx, addr)
}
