package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

type ipBlacklistManager struct {
	mu    sync.RWMutex
	ips   map[string]string // value is source URL
	cidrs []cidrEntry
	log   logr.Logger
	urls  []string
	sem   chan struct{}
}

type cidrEntry struct {
	net    *net.IPNet
	source string
}

func newIPBlacklistManager(log logr.Logger, urls []string) *ipBlacklistManager {
	return &ipBlacklistManager{
		ips:  make(map[string]string),
		log:  log,
		urls: urls,
		sem:  make(chan struct{}, 1),
	}
}

func (b *ipBlacklistManager) SetIPSources(urls []string) {
	b.urls = urls
}

func (b *ipBlacklistManager) IsBlocked(ip string) (bool, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Check individual IPs first (fastest)
	if source, ok := b.ips[ip]; ok {
		return true, source
	}

	// Parse the IP address for CIDR checking
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, ""
	}

	// Check CIDR ranges
	for _, entry := range b.cidrs {
		if entry.net.Contains(parsedIP) {
			return true, entry.source
		}
	}

	return false, ""
}

func (b *ipBlacklistManager) fetchFromURL(url string) (map[string]struct{}, []*net.IPNet, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	ipv4Pattern := `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
	ipv6Pattern := `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])`
	cidrPattern := `(?:` + ipv4Pattern + `|` + ipv6Pattern + `)/[0-9]{1,3}`

	ipRegex := regexp.MustCompile(ipv4Pattern + `|` + ipv6Pattern)
	cidrRegex := regexp.MustCompile(cidrPattern)

	ips := make(map[string]struct{})
	var cidrs []*net.IPNet

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// First try to match CIDR notation
		if cidrMatch := cidrRegex.FindString(line); cidrMatch != "" {
			_, ipNet, err := net.ParseCIDR(cidrMatch)
			if err == nil {
				// Store CIDR block without expanding
				cidrs = append(cidrs, ipNet)
				continue
			}
		}

		// Then try to match individual IP addresses
		if ipMatch := ipRegex.FindString(line); ipMatch != "" {
			// Validate the IP
			if net.ParseIP(ipMatch) != nil {
				ips[ipMatch] = struct{}{}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return ips, cidrs, nil
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
	allIPs := make(map[string]string)
	var allCIDRs []cidrEntry
	var lastErr error

	for _, url := range b.urls {
		b.log.Info("fetching IP blacklist from URL", "url", url)
		ips, cidrs, err := b.fetchFromURL(url)
		if err != nil {
			b.log.Error(err, "failed to fetch IP blacklist from URL", "url", url)
			lastErr = err
			continue
		}
		// Merge IPs from this URL
		for ip := range ips {
			allIPs[ip] = url
		}
		// Merge CIDRs from this URL
		for _, cidr := range cidrs {
			allCIDRs = append(allCIDRs, cidrEntry{net: cidr, source: url})
		}
		b.log.V(1).Info("fetched IP blacklist from URL", "url", url, "ips", len(ips), "cidrs", len(cidrs))
	}

	if len(allIPs) == 0 && len(allCIDRs) == 0 && lastErr != nil {
		return fmt.Errorf("failed to load any IPs from blacklist sources: %w", lastErr)
	}

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
