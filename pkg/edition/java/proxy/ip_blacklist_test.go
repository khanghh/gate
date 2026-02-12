package proxy

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/go-logr/logr"
)

func TestIPBlacklistManager_IsBlocked(t *testing.T) {
	sources := []string{
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://raw.githubusercontent.com/scriptzteam/ProtonVPN-VPN-IPs/main/exit_ips.txt",
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/ips-list.txt",
		"https://check.torproject.org/torbulkexitlist",
		"https://cinsscore.com/list/ci-badguys.txt",
		"https://lists.blocklist.de/lists/all.txt",
		"https://blocklist.greensnow.co/greensnow.txt",
		"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
		"https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/output/vpn/ipv4.txt",
		"https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/output/datacenter/ipv4.txt",
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
		"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
		"https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/allive.txt",
		"https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/http_proxies.txt",
		"https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks4_proxies.txt",
		"https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks5_proxies.txt",
		"https://raw.githubusercontent.com/officialputuid/KangProxy/main/http/http.txt",
		"https://raw.githubusercontent.com/officialputuid/KangProxy/main/https/https.txt",
		"https://raw.githubusercontent.com/officialputuid/KangProxy/main/socks4/socks4.txt",
		"https://raw.githubusercontent.com/officialputuid/KangProxy/main/socks5/socks5.txt",
		"https://vakhov.github.io/fresh-proxy-list/http.txt",
		"https://vakhov.github.io/fresh-proxy-list/https.txt",
		"https://vakhov.github.io/fresh-proxy-list/socks4.txt",
		"https://vakhov.github.io/fresh-proxy-list/socks5.txt",
		"https://raw.githubusercontent.com/Coocoobau/vpn-ip-lists/main/nordvpn-ips.txt",
		"https://raw.githubusercontent.com/Coocoobau/vpn-ip-lists/main/protonvpn-ips.txt",
		"https://raw.githubusercontent.com/Coocoobau/vpn-ip-lists/main/windscribevpn-ips.txt",
		"https://raw.githubusercontent.com/scriptzteam/ProtonVPN-VPN-IPs/main/entry_ips.txt",
		"http://az0-vpnip-public.oooninja.com/ip.txt",
		"https://tcpshield.com/blocklist.txt",
	}
	manager := newIPBlacklistManager(logr.FromSlogHandler(slog.NewTextHandler(os.Stdout, nil)), sources)
	manager.Refresh()

	blocked, source := manager.IsBlocked("58.187.67.199")
	if !blocked {
		fmt.Println("not blocked")
	} else {
		fmt.Println("blocked by", source)
	}
}
