// Package vps sets up and manages proxy servers over SSH, and imports
// their nodes into Clash Mihomac.
//
// Everything that touches a server goes through the SSH interface, so the
// setup logic is tested against a scripted fake server. Share links, key
// material and passwords are treated as secrets: they are redacted from
// every log and preview, and a password is never stored.
package vps

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Limits on imported data.
const (
	maxLinkBytes         = 8 << 10
	maxSubscriptionBytes = 1 << 20
	maxSubscriptionLinks = 500
	maxNodeName          = 60
)

// Node is a proxy node as mihomo's config describes it.
type Node struct {
	Name   string         `yaml:"name" json:"name"`
	Type   string         `yaml:"type" json:"type"`
	Server string         `yaml:"server" json:"server"`
	Port   int            `yaml:"port" json:"port"`
	Proxy  map[string]any `yaml:"proxy" json:"proxy"` // the full mihomo proxy entry
}

// ParseLink reads one share link: vless://, vmess://, trojan://, ss://,
// or hysteria2://.
func ParseLink(link string) (Node, error) {
	link = strings.TrimSpace(link)
	if len(link) > maxLinkBytes {
		return Node{}, errors.New("share link is too long")
	}
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok || rest == "" {
		return Node{}, fmt.Errorf("not a share link: %q", truncate(link, 40))
	}
	var n Node
	var err error
	switch strings.ToLower(scheme) {
	case "vless":
		n, err = parseVless(link)
	case "vmess":
		n, err = parseVmess(rest)
	case "trojan":
		n, err = parseTrojan(link)
	case "ss":
		n, err = parseSS(rest)
	case "hysteria2", "hy2":
		n, err = parseHysteria2(link)
	default:
		return Node{}, fmt.Errorf("unsupported link type %q (supported: vless, vmess, trojan, ss, hysteria2)", scheme)
	}
	if err != nil {
		return Node{}, err
	}
	n.Name = cleanName(n.Name)
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s-%s", n.Type, n.Server)
	}
	n.Proxy["name"] = n.Name
	return n, nil
}

// ParseSubscription reads a subscription body: share links one per line,
// optionally base64-encoded as a whole.
func ParseSubscription(body []byte) ([]Node, []error) {
	if len(body) > maxSubscriptionBytes {
		return nil, []error{errors.New("subscription is too large")}
	}
	text := strings.TrimSpace(string(body))
	if !strings.Contains(text, "://") {
		if dec, err := decodeBase64(text); err == nil {
			text = string(dec)
		}
	}
	var nodes []Node
	var errs []error
	seen := map[string]int{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(nodes)+len(errs) >= maxSubscriptionLinks {
			errs = append(errs, fmt.Errorf("only the first %d links are imported", maxSubscriptionLinks))
			break
		}
		n, err := ParseLink(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		if c := seen[n.Name]; c > 0 { // keep names unique
			n.Name = fmt.Sprintf("%s-%d", n.Name, c+1)
			n.Proxy["name"] = n.Name
		}
		seen[n.Name]++
		nodes = append(nodes, n)
	}
	return nodes, errs
}

func parseVless(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, fmt.Errorf("vless link: %w", err)
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Node{}, err
	}
	uuid := u.User.Username()
	if uuid == "" {
		return Node{}, errors.New("vless link has no user id")
	}
	q := u.Query()
	p := map[string]any{"type": "vless", "server": host, "port": port, "uuid": uuid, "udp": true}
	network := firstOf(q.Get("type"), "tcp")
	p["network"] = network
	if f := q.Get("flow"); f != "" {
		p["flow"] = f
	}
	switch q.Get("security") {
	case "tls":
		p["tls"] = true
		setIf(p, "servername", firstOf(q.Get("sni"), q.Get("peer")))
		setIf(p, "client-fingerprint", q.Get("fp"))
		if q.Get("allowInsecure") == "1" {
			p["skip-cert-verify"] = true
		}
		if alpn := q.Get("alpn"); alpn != "" {
			p["alpn"] = strings.Split(alpn, ",")
		}
	case "reality":
		p["tls"] = true
		setIf(p, "servername", q.Get("sni"))
		setIf(p, "client-fingerprint", firstOf(q.Get("fp"), "chrome"))
		pk := q.Get("pbk")
		if pk == "" {
			return Node{}, errors.New("vless reality link has no public key (pbk)")
		}
		ro := map[string]any{"public-key": pk}
		setIf(ro, "short-id", q.Get("sid"))
		p["reality-opts"] = ro
	}
	if err := transportOpts(p, network, q.Get("host"), q.Get("path"), q.Get("serviceName")); err != nil {
		return Node{}, err
	}
	return Node{Name: u.Fragment, Type: "vless", Server: host, Port: port, Proxy: p}, nil
}

func parseVmess(rest string) (Node, error) {
	raw, err := decodeBase64(strings.SplitN(rest, "#", 2)[0])
	if err != nil {
		return Node{}, errors.New("vmess link isn't valid base64")
	}
	var j struct {
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"`
		ID   string `json:"id"`
		Aid  any    `json:"aid"`
		Net  string `json:"net"`
		Host string `json:"host"`
		Path string `json:"path"`
		TLS  string `json:"tls"`
		SNI  string `json:"sni"`
		Scy  string `json:"scy"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return Node{}, fmt.Errorf("vmess link: %w", err)
	}
	port := anyInt(j.Port)
	if j.Add == "" || j.ID == "" || !validPort(port) {
		return Node{}, errors.New("vmess link is missing its server, port, or id")
	}
	p := map[string]any{"type": "vmess", "server": j.Add, "port": port, "uuid": j.ID, "alterId": anyInt(j.Aid),
		"cipher": firstOf(j.Scy, "auto"), "udp": true}
	network := firstOf(j.Net, "tcp")
	p["network"] = network
	if j.TLS == "tls" {
		p["tls"] = true
		setIf(p, "servername", firstOf(j.SNI, j.Host))
	}
	if err := transportOpts(p, network, j.Host, j.Path, j.Path); err != nil {
		return Node{}, err
	}
	return Node{Name: j.PS, Type: "vmess", Server: j.Add, Port: port, Proxy: p}, nil
}

func parseTrojan(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, fmt.Errorf("trojan link: %w", err)
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Node{}, err
	}
	pw := u.User.Username()
	if pw == "" {
		return Node{}, errors.New("trojan link has no password")
	}
	q := u.Query()
	p := map[string]any{"type": "trojan", "server": host, "port": port, "password": pw, "udp": true}
	setIf(p, "sni", firstOf(q.Get("sni"), q.Get("peer")))
	setIf(p, "client-fingerprint", q.Get("fp"))
	if q.Get("allowInsecure") == "1" {
		p["skip-cert-verify"] = true
	}
	network := firstOf(q.Get("type"), "tcp")
	if network != "tcp" {
		p["network"] = network
		if err := transportOpts(p, network, q.Get("host"), q.Get("path"), q.Get("serviceName")); err != nil {
			return Node{}, err
		}
	}
	return Node{Name: u.Fragment, Type: "trojan", Server: host, Port: port, Proxy: p}, nil
}

func parseSS(rest string) (Node, error) {
	body, frag, _ := strings.Cut(rest, "#")
	name, _ := url.PathUnescape(frag)
	body, query, _ := strings.Cut(body, "?")
	if query != "" && strings.Contains(query, "plugin=") {
		return Node{}, errors.New("shadowsocks links with plugins aren't supported; add that node to your config by hand")
	}
	var userinfo, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 { // SIP002: base64(userinfo)@host:port
		userinfo, hostport = body[:at], body[at+1:]
		if dec, err := decodeBase64(userinfo); err == nil && strings.Contains(string(dec), ":") {
			userinfo = string(dec)
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
	} else { // legacy: base64(method:password@host:port)
		dec, err := decodeBase64(strings.TrimSuffix(body, "/"))
		if err != nil {
			return Node{}, errors.New("shadowsocks link isn't valid")
		}
		at := strings.LastIndex(string(dec), "@")
		if at < 0 {
			return Node{}, errors.New("shadowsocks link has no server")
		}
		userinfo, hostport = string(dec)[:at], string(dec)[at+1:]
	}
	method, pw, ok := strings.Cut(userinfo, ":")
	if !ok || method == "" || pw == "" {
		return Node{}, errors.New("shadowsocks link has no cipher or password")
	}
	host, portStr, err := net.SplitHostPort(strings.TrimSuffix(hostport, "/"))
	if err != nil {
		return Node{}, errors.New("shadowsocks link has no valid server:port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !validPort(port) {
		return Node{}, errors.New("shadowsocks link has an invalid port")
	}
	p := map[string]any{"type": "ss", "server": host, "port": port, "cipher": method, "password": pw, "udp": true}
	return Node{Name: name, Type: "ss", Server: host, Port: port, Proxy: p}, nil
}

func parseHysteria2(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, fmt.Errorf("hysteria2 link: %w", err)
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Node{}, err
	}
	pw := u.User.Username()
	if v, ok := u.User.Password(); ok {
		pw += ":" + v
	}
	if pw == "" {
		return Node{}, errors.New("hysteria2 link has no password")
	}
	q := u.Query()
	p := map[string]any{"type": "hysteria2", "server": host, "port": port, "password": pw}
	setIf(p, "sni", q.Get("sni"))
	if q.Get("insecure") == "1" {
		p["skip-cert-verify"] = true
	}
	if o := q.Get("obfs"); o != "" {
		p["obfs"] = o
		setIf(p, "obfs-password", q.Get("obfs-password"))
	}
	return Node{Name: u.Fragment, Type: "hysteria2", Server: host, Port: port, Proxy: p}, nil
}

func transportOpts(p map[string]any, network, host, path, service string) error {
	switch network {
	case "tcp", "":
	case "ws":
		opts := map[string]any{}
		setIf(opts, "path", path)
		if host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		p["ws-opts"] = opts
	case "grpc":
		opts := map[string]any{}
		setIf(opts, "grpc-service-name", service)
		p["grpc-opts"] = opts
	default:
		return fmt.Errorf("transport %q isn't supported", network)
	}
	return nil
}

func hostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if host == "" || err != nil || !validPort(port) {
		return "", 0, errors.New("link has no valid server and port")
	}
	return host, port, nil
}

func validPort(p int) bool { return p > 0 && p < 65536 }

func setIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func firstOf(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func anyInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

// decodeBase64 accepts standard and URL-safe alphabets, with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

func cleanName(s string) string {
	if un, err := url.PathUnescape(s); err == nil {
		s = un
	}
	var b bytes.Buffer
	for _, r := range s {
		if unicode.IsControl(r) || r == ',' {
			continue
		}
		b.WriteRune(r)
	}
	name := strings.TrimSpace(b.String())
	if r := []rune(name); len(r) > maxNodeName {
		name = string(r[:maxNodeName])
	}
	return name
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// VlessRealityLink renders a share link for a VLESS+Reality node.
func VlessRealityLink(name, host string, port int, uuid, publicKey, shortID, sni string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	q.Set("security", "reality")
	q.Set("sni", sni)
	q.Set("fp", "chrome")
	q.Set("pbk", publicKey)
	q.Set("sid", shortID)
	q.Set("type", "tcp")
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuid, h, port, q.Encode(), url.PathEscape(name))
}
