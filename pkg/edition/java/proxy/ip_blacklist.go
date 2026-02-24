package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

type ipBlacklistManager struct {
	mu   sync.RWMutex
	ips  map[string]struct{}
	log  logr.Logger
	urls []string
	sem  chan struct{}
}

func newIPBlacklistManager(log logr.Logger, urls []string) *ipBlacklistManager {
	return &ipBlacklistManager{
		ips:  make(map[string]struct{}),
		log:  log,
		urls: urls,
		sem:  make(chan struct{}, 1),
	}
}

func (b *ipBlacklistManager) SetIPSources(urls []string) {
	b.urls = urls
}

func (b *ipBlacklistManager) IsBlocked(ip string) bool {
	b.mu.RLock()
	_, ok := b.ips[ip]
	b.mu.RUnlock()
	return ok
}

func (b *ipBlacklistManager) fetchFromURL(url string) (map[string]struct{}, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	ips := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format is: IP \t number
		// We can just split by whitespace
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			ips[fields[0]] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

// Refresh fetches the blacklist from all configured URLs and updates the set of blocked IPs.
func (b *ipBlacklistManager) Refresh() error {
	select {
	case b.sem <- struct{}{}:
		defer func() { <-b.sem }()
	default:
		return nil
	}

	b.log.V(1).Info("refreshing IP blacklist", "sources", len(b.urls))
	allIPs := make(map[string]struct{})
	var lastErr error

	for _, url := range b.urls {
		ips, err := b.fetchFromURL(url)
		if err != nil {
			b.log.Error(err, "failed to fetch IP blacklist from URL", "url", url)
			lastErr = err
			continue
		}
		// Merge IPs from this URL
		for ip := range ips {
			allIPs[ip] = struct{}{}
		}
		b.log.V(1).Info("fetched IP blacklist from URL", "url", url, "count", len(ips))
	}

	if len(allIPs) == 0 && lastErr != nil {
		return fmt.Errorf("failed to load any IPs from blacklist sources: %w", lastErr)
	}

	b.mu.Lock()
	b.ips = allIPs
	b.mu.Unlock()

	b.log.Info("loaded IP blacklist", "totalIPs", len(allIPs), "sources", len(b.urls))
	return nil
}

// StartAutoRefresh starts a background goroutine that periodically refreshes the blacklist.
func (b *ipBlacklistManager) StartAutoRefresh(ctx context.Context, interval time.Duration) {
	if err := b.Refresh(); err != nil {
		b.log.Error(err, "failed to load initial IP blacklist")
	}

	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.log.V(1).Info("stopping IP blacklist refresh loop")
			return
		case <-ticker.C:
			if err := b.Refresh(); err != nil {
				b.log.Error(err, "failed to refresh IP blacklist")
			}
		}
	}
}
