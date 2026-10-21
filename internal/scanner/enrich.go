package scanner

import (
	"context"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

func (o Options) resolver() DNSResolver {
	if o.Resolver != nil {
		return o.Resolver
	}
	return net.DefaultResolver
}

// resolveHost returns the forward addresses and reverse (PTR) names for a host.
func resolveHost(ctx context.Context, r DNSResolver, host string) (addrs, ptr []string) {
	if ip := net.ParseIP(host); ip != nil {
		addrs = []string{host}
	} else if a, err := r.LookupHost(ctx, host); err == nil {
		addrs = a
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		names, err := r.LookupAddr(ctx, a)
		if err != nil {
			continue
		}
		for _, n := range names {
			n = strings.TrimSuffix(strings.TrimSpace(n), ".")
			if n != "" && !seen[n] {
				seen[n] = true
				ptr = append(ptr, n)
			}
		}
	}
	sort.Strings(addrs)
	sort.Strings(ptr)
	return addrs, ptr
}

// applyJitter sleeps a random duration in [0, d) (unless d <= 0 or cancelled).
func applyJitter(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	wait := time.Duration(rand.Int63n(int64(d)))
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
}

// rateBurst derives a sensible token-bucket burst for a given rate.
func rateBurst(rate float64) int {
	if rate <= 0 {
		return 0
	}
	b := int(rate)
	if b < 1 {
		b = 1
	}
	return b
}

// hostGate caps the number of concurrent probes per host.
type hostGate struct {
	n    int
	mu   sync.Mutex
	sems map[string]chan struct{}
}

func newHostGate(n int) *hostGate {
	if n <= 0 {
		return &hostGate{}
	}
	return &hostGate{n: n, sems: map[string]chan struct{}{}}
}

func (g *hostGate) acquire(host string) {
	if g == nil || g.n <= 0 {
		return
	}
	g.mu.Lock()
	s := g.sems[host]
	if s == nil {
		s = make(chan struct{}, g.n)
		g.sems[host] = s
	}
	g.mu.Unlock()
	s <- struct{}{}
}

func (g *hostGate) release(host string) {
	if g == nil || g.n <= 0 {
		return
	}
	g.mu.Lock()
	s := g.sems[host]
	g.mu.Unlock()
	if s != nil {
		<-s
	}
}
