package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// checkpoint records completed service results as NDJSON so a scan can resume.
// A nil-path checkpoint is a no-op (nothing is loaded or written).
type checkpoint struct {
	mu   sync.Mutex
	f    *os.File
	done map[string]ServiceResult
}

func jobKey(host string, port int) string {
	return host + "/" + strconv.Itoa(port)
}

func loadCheckpoint(path string) (*checkpoint, error) {
	c := &checkpoint{done: map[string]ServiceResult{}}
	if path == "" {
		return c, nil
	}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var r ServiceResult
			if json.Unmarshal([]byte(line), &r) == nil && r.Host != "" {
				c.done[jobKey(r.Host, r.Port)] = r
			}
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("checkpoint %q: %w", path, err)
	}
	c.f = f
	return c, nil
}

func (c *checkpoint) lookup(k string) (ServiceResult, bool) {
	if c == nil {
		return ServiceResult{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.done[k]
	return r, ok
}

func (c *checkpoint) record(r ServiceResult) {
	if c == nil || c.f == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, err := json.Marshal(r); err == nil {
		_, _ = c.f.Write(append(b, '\n'))
	}
}

func (c *checkpoint) close() {
	if c != nil && c.f != nil {
		_ = c.f.Close()
	}
}
