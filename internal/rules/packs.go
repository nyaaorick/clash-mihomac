package rules

import "sort"

// Bypass keeps local, private, and link-local traffic off proxies. It is
// always compiled in, after user rules.
var Bypass = []Rule{
	{Type: TypeDomainSuffix, Value: "localhost", Target: "DIRECT", Note: "localhost"},
	{Type: TypeDomainSuffix, Value: "local", Target: "DIRECT", Note: "mDNS (.local, OrbStack .orb.local)"},
	{Type: TypeDomainSuffix, Value: "docker.internal", Target: "DIRECT", Note: "Docker Desktop"},
	{Type: TypeIPCIDR, Value: "127.0.0.0/8", Target: "DIRECT", Note: "loopback"},
	{Type: TypeIPCIDR, Value: "10.0.0.0/8", Target: "DIRECT", Note: "private network"},
	{Type: TypeIPCIDR, Value: "172.16.0.0/12", Target: "DIRECT", Note: "private network"},
	{Type: TypeIPCIDR, Value: "192.168.0.0/16", Target: "DIRECT", Note: "private network (incl. Docker Desktop)"},
	{Type: TypeIPCIDR, Value: "100.64.0.0/10", Target: "DIRECT", Note: "CGNAT (Tailscale and similar VPNs)"},
	{Type: TypeIPCIDR, Value: "169.254.0.0/16", Target: "DIRECT", Note: "link-local"},
	{Type: TypeIPCIDR, Value: "198.19.249.0/24", Target: "DIRECT", Note: "OrbStack"},
	{Type: TypeIPCIDR, Value: "224.0.0.0/4", Target: "DIRECT", Note: "multicast"},
	{Type: TypeIPCIDR, Value: "::1/128", Target: "DIRECT", Note: "loopback"},
	{Type: TypeIPCIDR, Value: "fc00::/7", Target: "DIRECT", Note: "unique local"},
	{Type: TypeIPCIDR, Value: "fe80::/10", Target: "DIRECT", Note: "link-local"},
}

// Pack is a named group of rules: built in, or installed from a pack file.
type Pack struct {
	Name        string `yaml:"name,omitempty" json:"name,omitempty"`
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
	Author      string `yaml:"author,omitempty" json:"author,omitempty"`
	Description string `yaml:"description" json:"description"`
	Source      string `yaml:"source,omitempty" json:"source,omitempty"` // URL it was installed from
	Rules       []Rule `yaml:"rules" json:"rules"`
}

func suffixes(target string, domains ...string) []Rule {
	out := make([]Rule, len(domains))
	for i, d := range domains {
		out[i] = Rule{Type: TypeDomainSuffix, Value: d, Target: target}
	}
	return out
}

var packs = map[string]Pack{
	"bilibili": {
		Description: "Bilibili video and live streaming, direct",
		Rules: suffixes("DIRECT",
			"bilibili.com", "bilibili.cn", "bilivideo.com", "bilivideo.cn", "biliapi.com", "biliapi.net",
			"hdslb.com", "hdslb.net", "b23.tv", "biligame.com", "biligame.net", "acgvideo.com"),
	},
	"taobao": {
		Description: "Taobao, Tmall, Alipay, and Alibaba CDNs, direct",
		Rules: suffixes("DIRECT",
			"taobao.com", "tmall.com", "tmall.hk", "alicdn.com", "alipay.com", "alipayobjects.com",
			"alibaba.com", "1688.com", "mmstat.com", "tbcdn.cn", "taobaocdn.com", "alibabausercontent.com"),
	},
}

// PackNames lists the built-in packs in sorted order.
func PackNames() []string {
	names := make([]string, 0, len(packs))
	for n := range packs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Packs returns a copy of the built-in packs.
func Packs() map[string]Pack {
	out := make(map[string]Pack, len(packs))
	for k, v := range packs {
		v.Name = k
		out[k] = v
	}
	return out
}
