package vps

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVlessReality(t *testing.T) {
	link := VlessRealityLink("my node", "203.0.113.5", 443, "11111111-2222-3333-4444-555555555555", "PUBKEY", "ab12", "www.example.com")
	n, err := ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	p := n.Proxy
	ro := p["reality-opts"].(map[string]any)
	if n.Name != "my node" || p["type"] != "vless" || p["server"] != "203.0.113.5" || p["port"] != 443 || p["uuid"] != "11111111-2222-3333-4444-555555555555" ||
		p["flow"] != "xtls-rprx-vision" || p["servername"] != "www.example.com" || ro["public-key"] != "PUBKEY" || ro["short-id"] != "ab12" || p["tls"] != true || p["name"] != "my node" {
		t.Errorf("node = %+v", n)
	}
	if _, err := ParseLink("vless://u@h:1?security=reality"); err == nil {
		t.Error("reality link without a public key accepted")
	}
}

func TestParseVlessWebsocketTLSAndIPv6(t *testing.T) {
	n, err := ParseLink("vless://abc@[2001:db8::1]:8443?security=tls&sni=a.example.com&type=ws&host=cdn.example.com&path=%2Fws&fp=chrome#ws-node")
	if err != nil {
		t.Fatal(err)
	}
	ws := n.Proxy["ws-opts"].(map[string]any)
	if n.Server != "2001:db8::1" || n.Port != 8443 || ws["path"] != "/ws" || ws["headers"].(map[string]any)["Host"] != "cdn.example.com" || n.Proxy["servername"] != "a.example.com" {
		t.Errorf("node = %+v", n)
	}
	if _, err := ParseLink("vless://abc@h:1?type=kcp"); err == nil {
		t.Error("unsupported transport accepted")
	}
}

func TestParseVmessTrojanSSHysteria(t *testing.T) {
	vm := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vm","add":"vm.example.com","port":"443","id":"uuid-1","aid":"0","net":"ws","host":"h.example.com","path":"/p","tls":"tls"}`))
	n, err := ParseLink("vmess://" + vm)
	if err != nil || n.Name != "vm" || n.Port != 443 || n.Proxy["network"] != "ws" || n.Proxy["tls"] != true || n.Proxy["cipher"] != "auto" {
		t.Errorf("vmess = %+v, %v", n, err)
	}

	n, err = ParseLink("trojan://s3cret@t.example.com:443?sni=front.example.com&allowInsecure=1#tr")
	if err != nil || n.Proxy["password"] != "s3cret" || n.Proxy["sni"] != "front.example.com" || n.Proxy["skip-cert-verify"] != true {
		t.Errorf("trojan = %+v, %v", n, err)
	}

	sip002 := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa55")) + "@ss.example.com:8388#ss%20node"
	n, err = ParseLink(sip002)
	if err != nil || n.Name != "ss node" || n.Proxy["cipher"] != "aes-256-gcm" || n.Proxy["password"] != "pa55" || n.Port != 8388 {
		t.Errorf("ss sip002 = %+v, %v", n, err)
	}
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@1.2.3.4:443")) + "#old"
	n, err = ParseLink(legacy)
	if err != nil || n.Server != "1.2.3.4" || n.Proxy["cipher"] != "chacha20-ietf-poly1305" {
		t.Errorf("ss legacy = %+v, %v", n, err)
	}
	if _, err := ParseLink(strings.SplitN(sip002, "#", 2)[0] + "?plugin=obfs-local"); err == nil {
		t.Error("ss plugin accepted")
	}

	n, err = ParseLink("hysteria2://pw@h.example.com:443?sni=s.example.com&obfs=salamander&obfs-password=o#hy")
	if err != nil || n.Type != "hysteria2" || n.Proxy["obfs"] != "salamander" || n.Proxy["sni"] != "s.example.com" {
		t.Errorf("hysteria2 = %+v, %v", n, err)
	}
}

func TestParseLinkRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "hello", "http://example.com", "vless://", "vless://@h:1", "vless://u@h:0", "vless://u@h:99999", "trojan://h:1", "vmess://!!!", "ss://", "ss://abc", strings.Repeat("a", maxLinkBytes+1)} {
		if _, err := ParseLink(bad); err == nil {
			t.Errorf("accepted %q", truncate(bad, 30))
		}
	}
}

func TestNamesAreCleaned(t *testing.T) {
	n, err := ParseLink("trojan://pw@h.example.com:443#" + "bad%0Aname,with%00stuff" + strings.Repeat("x", 100))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(n.Name, "\n,\x00") || len([]rune(n.Name)) != maxNodeName {
		t.Errorf("name = %q", n.Name)
	}
	n, _ = ParseLink("trojan://pw@h.example.com:443")
	if n.Name != "trojan-h.example.com" {
		t.Errorf("default name = %q", n.Name)
	}
}

func TestParseSubscription(t *testing.T) {
	lines := "trojan://a@h1.example.com:443#same\ntrojan://b@h2.example.com:443#same\nbogus\n\nss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:x")) + "@h3.example.com:1#third\n"
	for name, body := range map[string]string{"plain": lines, "base64": base64.StdEncoding.EncodeToString([]byte(lines))} {
		nodes, errs := ParseSubscription([]byte(body))
		if len(nodes) != 3 || len(errs) != 1 || nodes[0].Name != "same" || nodes[1].Name != "same-2" || nodes[1].Proxy["name"] != "same-2" {
			t.Errorf("%s: nodes = %+v, errs = %v", name, nodes, errs)
		}
	}
	var many strings.Builder
	for i := 0; i < maxSubscriptionLinks+50; i++ {
		many.WriteString("trojan://p@h.example.com:443#n\n")
	}
	if nodes, errs := ParseSubscription([]byte(many.String())); len(nodes) != maxSubscriptionLinks || len(errs) != 1 {
		t.Errorf("limit: %d nodes, %d errs", len(nodes), len(errs))
	}
}
