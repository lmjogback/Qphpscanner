package probe

import (
	"context"
	"sync"
	"time"
)

// Limiter gates outbound requests. Wait blocks until the next request may
// proceed, or the context is cancelled.
type Limiter interface {
	Wait(ctx context.Context) error
}

// NewRateLimiter returns a token-bucket Limiter capped at ratePerSec requests
// per second with the given burst. It returns a nil Limiter (no limiting) when
// ratePerSec <= 0.
func NewRateLimiter(ratePerSec float64, burst int) Limiter {
	if ratePerSec <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		interval: time.Duration(float64(time.Second) / ratePerSec),
		burst:    float64(burst),
		tokens:   float64(burst),
		last:     time.Now(),
	}
}

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	burst    float64
	tokens   float64
	last     time.Time
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := time.Now()
		if r.interval > 0 {
			r.tokens += float64(now.Sub(r.last)) / float64(r.interval)
			if r.tokens > r.burst {
				r.tokens = r.burst
			}
		}
		r.last = now
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - r.tokens) * float64(r.interval))
		r.mu.Unlock()

		if wait <= 0 {
			wait = r.interval
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
