package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

var (
	ipRegex = regexp.MustCompile(`\b(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-f0-9]{1,4}:){1,7}(?:[a-f0-9]{1,4}|:)|::(?:[a-f0-9]{1,4}:){0,6}[a-f0-9]{1,4})(?:\/\d{1,3})?`)
)

type IPExtractor struct {
	ips   map[netip.Addr]string
	cidrs map[netip.Prefix]string
}

func NewIPExtractor() *IPExtractor {
	return &IPExtractor{
		ips:   make(map[netip.Addr]string),
		cidrs: make(map[netip.Prefix]string),
	}
}

func (e *IPExtractor) CollectIPsAndCIDRs(text string, sourceURL string) {
	matches := ipRegex.FindAllString(strings.ToLower(text), -1)

	for _, match := range matches {
		// Handle CIDRs
		if strings.Contains(match, "/") {
			prefix, err := netip.ParsePrefix(match)
			// Skip if invalid or if we already have it
			if err != nil || e.cidrs[prefix] != "" {
				continue
			}
			e.cidrs[prefix] = sourceURL
			continue
		}

		// Handle Standalone IPs
		addr, err := netip.ParseAddr(match)
		if err != nil || e.ips[addr] != "" {
			continue
		}
		e.ips[addr] = sourceURL
	}
}

func (e *IPExtractor) GetResults() (ips map[netip.Addr]string, cidrs map[netip.Prefix]string) {
	ips = make(map[netip.Addr]string)

	for ip, source := range e.ips {
		// If the IP is NOT inside any of our CIDRs, add it to the final result
		if !e.isIPInAnyCIDR(ip) {
			ips[ip] = source
		}
	}
	cidrs = e.cidrs
	return ips, cidrs
}

func (e *IPExtractor) isIPInAnyCIDR(ip netip.Addr) bool {
	for cidr := range e.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

type ipBlacklistManager struct {
	ips   map[netip.Addr]string
	cidrs map[netip.Prefix]string
	log   logr.Logger
	urls  []string
	mu    sync.RWMutex
	sem   chan struct{}
}

func newIPBlacklistManager(log logr.Logger, urls []string) *ipBlacklistManager {
	return &ipBlacklistManager{
		ips:   make(map[netip.Addr]string),
		cidrs: make(map[netip.Prefix]string),
		log:   log,
		urls:  urls,
		sem:   make(chan struct{}, 1),
	}
}

func (b *ipBlacklistManager) SetIPSources(urls []string) {
	b.urls = urls
}

func (b *ipBlacklistManager) IsBlocked(ip string) (bool, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return true, ""
	}

	if src, ok := b.ips[parsedIP]; ok {
		return true, src
	}

	for cidr, src := range b.cidrs {
		if cidr.Contains(parsedIP) {
			return true, src
		}
	}

	return false, ""
}

// Refresh fetches the blacklist from all configured URLs and updates the set of blocked IPs.
func (b *ipBlacklistManager) Refresh() error {
	select {
	case b.sem <- struct{}{}:
		defer func() { <-b.sem }()
	default:
		return nil
	}

	b.log.Info("refreshing IP blacklist", "sources", len(b.urls))

	var (
		extractor = NewIPExtractor()
		client    = &http.Client{
			Timeout: 30 * time.Second,
		}
		lastErr error
	)

	for _, url := range b.urls {
		b.log.Info("fetching IP blacklist from URL", "url", url)
		resp, err := client.Get(url)
		if err != nil {
			b.log.Error(err, "failed to fetch IP blacklist from URL", "url", url, "error", err)
			lastErr = err
			continue
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			b.log.Error(err, "failed process IP blacklist from URL", "url", url, "error", err)
			lastErr = err
			continue
		}

		extractor.CollectIPsAndCIDRs(string(content), url)
	}

	if lastErr != nil {
		return fmt.Errorf("failed to load any IPs from blacklist sources: %w", lastErr)
	}

	allIPs, allCIDRs := extractor.GetResults()

	b.mu.Lock()
	b.ips = allIPs
	b.cidrs = allCIDRs
	b.mu.Unlock()

	b.log.Info("loaded IP blacklist", "totalIPs", len(allIPs), "totalCIDRs", len(allCIDRs), "sources", len(b.urls))
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
