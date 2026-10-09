package vps

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Modes a plan can have.
const (
	ModeInstall   = "install"   // a clean server
	ModeRepair    = "repair"    // an install of ours that is broken or partly missing
	ModeUpgrade   = "upgrade"   // update the proxy core, keep the config
	ModeReinstall = "reinstall" // remove ours, then install fresh with new credentials
)

// Where things live on the server.
const (
	binPath     = "/usr/local/bin/sing-box"
	binPrev     = "/usr/local/bin/sing-box.prev"
	confDir     = "/etc/sing-box"
	confPath    = "/etc/sing-box/config.json"
	unitPath    = "/etc/systemd/system/sing-box.service"
	bbrPath     = "/etc/sysctl.d/99-mihomac-bbr.conf"
	serviceName = "sing-box"
	tmpDir      = "/tmp/mihomac-install"
)

// DefaultSNI is the site Reality impersonates when the handshake doesn't
// come from one of our clients. It must support TLS 1.3 and HTTP/2.
const DefaultSNI = "www.microsoft.com"

// Release pins a proxy core version. SHA256 maps GOARCH to the checksum of
// the release's .tar.gz asset. A version with no pinned checksum can only
// be installed when the person supplies one: the installer never runs a
// download it can't verify.
type Release struct {
	Version string // without the leading v
	SHA256  map[string]string
}

// DefaultRelease is the sing-box version setup installs. Its checksums are
// deliberately unpinned: they have to be copied from the release page by a
// maintainer who has verified them, which can't be done from the cloud
// sandbox this project is developed in. Until then, setup asks for the
// checksum (--sha256) and refuses to run without one.
var DefaultRelease = Release{Version: "1.12.0", SHA256: map[string]string{}}

var (
	sha256RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE   = regexp.MustCompile(`^\d{1,2}\.\d{1,3}\.\d{1,3}$`)
	hostRE      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)
	sniRE       = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	proxyNameRE = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,40}$`)
)

// Creds are a node's credentials. They are secrets.
type Creds struct {
	UUID       string `json:"-"`
	PrivateKey string `json:"-"` // Reality private key (server side)
	PublicKey  string `json:"-"` // Reality public key (goes in the share link)
	ShortID    string `json:"-"`
}

// NewCreds generates fresh credentials.
func NewCreds() (Creds, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return Creds{}, err
	}
	u[6] = u[6]&0x0f | 0x40 // version 4
	u[8] = u[8]&0x3f | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Creds{}, err
	}
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return Creds{}, err
	}
	enc := base64.RawURLEncoding
	return Creds{
		UUID:       uuid,
		PrivateKey: enc.EncodeToString(key.Bytes()),
		PublicKey:  enc.EncodeToString(key.PublicKey().Bytes()),
		ShortID:    hex.EncodeToString(sid[:]),
	}, nil
}

// PublicFromPrivate derives the Reality public key from a private key.
func PublicFromPrivate(priv string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil {
		return "", errors.New("the Reality private key isn't valid base64")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// Options describe what to set up.
type Options struct {
	Mode    string
	Name    string // node name shown in the client
	Host    string // the server's address, for the share link
	Port    int
	SNI     string
	Release Release
	SHA256  string // overrides the pinned checksum
	Report  Report
	Creds   Creds // for repair and upgrade: the existing credentials
}

// Step is one thing the plan does on the server.
type Step struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Why   string `json:"why"`
	Cmd   string `json:"cmd"`            // run with sh -c
	File  string `json:"file"`           // for uploads: the path written
	Stdin []byte `json:"-"`              // for uploads: the content
	Undo  string `json:"undo,omitempty"` // run if a later step fails
}

// Plan is a full, reviewable list of what setup will do.
type Plan struct {
	Mode    string   `json:"mode"`
	Steps   []Step   `json:"steps"`
	Blocked []string `json:"blocked,omitempty"` // reasons the plan can't run
	Creds   Creds    `json:"-"`
	Link    string   `json:"-"` // the share link, once the plan has credentials
	Options Options  `json:"-"`
}

// Redactor hides secrets from anything shown or logged.
type Redactor struct{ secrets []string }

// NewRedactor redacts the given secrets (those shorter than 4 characters
// would mangle ordinary text and are ignored).
func NewRedactor(secrets ...string) *Redactor {
	r := &Redactor{}
	r.Add(secrets...)
	return r
}

// Add registers more secrets.
func (r *Redactor) Add(secrets ...string) {
	for _, s := range secrets {
		if len(s) >= 4 {
			r.secrets = append(r.secrets, s)
		}
	}
}

// Redact replaces every secret in s with bullets.
func (r *Redactor) Redact(s string) string {
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "••••")
	}
	return s
}

// Redactor returns one that hides this plan's credentials and share link.
func (p Plan) Redactor(extra ...string) *Redactor {
	r := NewRedactor(p.Creds.UUID, p.Creds.PrivateKey, p.Creds.ShortID, p.Link)
	r.Add(extra...)
	return r
}

// Validate checks options that end up in commands and files.
func (o Options) Validate() error {
	if !hostRE.MatchString(o.Host) {
		return fmt.Errorf("invalid server address %q", o.Host)
	}
	if o.Port < 1 || o.Port > 65535 {
		return fmt.Errorf("invalid port %d", o.Port)
	}
	if !sniRE.MatchString(o.SNI) {
		return fmt.Errorf("invalid SNI %q", o.SNI)
	}
	if !proxyNameRE.MatchString(o.Name) {
		return fmt.Errorf("node name %q must be 1-40 letters, digits, spaces, dots, dashes, or underscores", o.Name)
	}
	if !versionRE.MatchString(o.Release.Version) {
		return fmt.Errorf("invalid version %q", o.Release.Version)
	}
	if o.SHA256 != "" && !sha256RE.MatchString(strings.ToLower(o.SHA256)) {
		return errors.New("the checksum must be 64 hexadecimal characters")
	}
	switch o.Mode {
	case ModeInstall, ModeRepair, ModeUpgrade, ModeReinstall:
	default:
		return fmt.Errorf("unknown mode %q", o.Mode)
	}
	return nil
}

// ChooseMode suggests what to do about a server, given its pre-flight report.
func ChooseMode(r Report) string {
	switch {
	case !r.Ours.Any():
		return ModeInstall
	case r.Ours.Binary && r.Ours.Config && r.Ours.Unit && r.Ours.Active:
		return ModeUpgrade
	default:
		return ModeRepair
	}
}

// BuildPlan lists the steps for opts. It never touches the network.
func BuildPlan(o Options) (Plan, error) {
	if o.SNI == "" {
		o.SNI = DefaultSNI
	}
	if o.Port == 0 {
		o.Port = 443
	}
	if o.Release.Version == "" {
		o.Release = DefaultRelease
	}
	if err := o.Validate(); err != nil {
		return Plan{}, err
	}
	p := Plan{Mode: o.Mode, Options: o}
	r := o.Report

	for _, is := range r.Issues {
		if is.Severity == SevError && !(o.Mode == ModeReinstall && strings.Contains(is.Message, "Port")) {
			p.Blocked = append(p.Blocked, is.Message)
		}
	}
	needDownload := o.Mode == ModeInstall || o.Mode == ModeReinstall || o.Mode == ModeUpgrade || (o.Mode == ModeRepair && !r.Ours.Binary)
	sum := strings.ToLower(o.SHA256)
	if needDownload && sum == "" {
		sum = o.Release.SHA256[r.Arch]
		if sum == "" {
			p.Blocked = append(p.Blocked, fmt.Sprintf("No verified checksum is pinned for sing-box %s (%s). Download isn't allowed without one: pass the SHA-256 of the release asset %s (from the project's release page) and re-run.",
				o.Release.Version, r.Arch, assetName(o.Release.Version, r.Arch)))
		}
	}

	freshCreds := o.Mode == ModeInstall || o.Mode == ModeReinstall
	if freshCreds {
		c, err := NewCreds()
		if err != nil {
			return Plan{}, err
		}
		p.Creds = c
	} else {
		p.Creds = o.Creds
		if p.Creds.UUID == "" && o.Mode != ModeUpgrade {
			// Repair may need to rewrite the config; without the old
			// credentials it can't, and says so rather than inventing new ones.
			if !r.Ours.Config {
				p.Blocked = append(p.Blocked, "The previous config is gone, so its credentials can't be recovered. Use a reinstall to start fresh.")
			}
		}
	}
	if p.Creds.PublicKey != "" {
		p.Link = VlessRealityLink(o.Name, o.Host, o.Port, p.Creds.UUID, p.Creds.PublicKey, p.Creds.ShortID, o.SNI)
	}

	add := func(s Step) { p.Steps = append(p.Steps, s) }
	pkg := installPackagesCmd(r.PkgMgr)

	if o.Mode == ModeReinstall {
		add(Step{ID: "remove-old", Title: "Remove the previous Clash Mihomac install",
			Why: "Reinstalling starts clean with new credentials. Only files this tool created are removed; other software is left alone.",
			Cmd: fmt.Sprintf("systemctl disable --now %s 2>/dev/null; rm -f %s %s %s %s; rm -rf %s; systemctl daemon-reload", serviceName, unitPath, binPath, binPrev, bbrPath, confDir)})
	}
	if needDownload {
		add(Step{ID: "prereqs", Title: "Install download tools", Why: "curl, tar, and CA certificates are needed to fetch and unpack the proxy.", Cmd: pkg})
		add(Step{ID: "download", Title: fmt.Sprintf("Download sing-box %s", o.Release.Version),
			Why: "From the project's official GitHub release.",
			Cmd: fmt.Sprintf("mkdir -p %s && curl -fsSL --retry 3 --max-time 300 -o %s/sb.tar.gz %s", tmpDir, tmpDir, shq(downloadURL(o.Release.Version, r.Arch)))})
		add(Step{ID: "verify", Title: "Verify the download's SHA-256 checksum",
			Why: "Stops the install if the file isn't exactly the one that was checked.",
			Cmd: fmt.Sprintf("echo %s | sha256sum -c -", shq(sum+"  "+tmpDir+"/sb.tar.gz"))})
		undo := ""
		if o.Mode == ModeUpgrade {
			undo = fmt.Sprintf("[ -f %s ] && mv -f %s %s && systemctl restart %s", binPrev, binPrev, binPath, serviceName)
		}
		add(Step{ID: "install-binary", Title: "Install the sing-box binary",
			Why: "Keeps a copy of the previous binary so an upgrade can roll back.",
			Cmd: fmt.Sprintf("[ -f %s ] && cp -a %s %s; mkdir -p %s/x && tar -xzf %s/sb.tar.gz -C %s/x --strip-components=1 && install -m 0755 %s/x/sing-box %s",
				binPath, binPath, binPrev, tmpDir, tmpDir, tmpDir, tmpDir, binPath), Undo: undo})
	}

	needConfig := freshCreds || (o.Mode == ModeRepair && (!r.Ours.Config))
	if freshCreds || o.Mode == ModeRepair {
		add(Step{ID: "user", Title: "Create a service account", Why: "The proxy runs as an unprivileged 'sing-box' user, not root.",
			Cmd: "id sing-box >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sing-box"})
	}
	if needConfig && p.Creds.UUID != "" {
		cfg, err := ServerConfig(o.Port, o.SNI, p.Creds)
		if err != nil {
			return Plan{}, err
		}
		add(Step{ID: "config", Title: "Write the server config", File: confPath, Stdin: cfg,
			Why: fmt.Sprintf("A VLESS + Reality inbound on port %d with newly generated credentials, readable only by root and the service account.", o.Port),
			Cmd: uploadCmd(confPath, "root:sing-box", "0640", "027")})
	}
	if freshCreds || o.Mode == ModeRepair {
		add(Step{ID: "check-config", Title: "Validate the config", Why: "sing-box checks its own config before anything is started.",
			Cmd: fmt.Sprintf("%s check -c %s", binPath, confPath)})
		if freshCreds || !r.Ours.Unit {
			add(Step{ID: "unit", Title: "Install the systemd service", File: unitPath, Stdin: []byte(unitFile),
				Why: "Runs the proxy at boot and restarts it if it crashes, with systemd sandboxing.",
				Cmd: uploadCmd(unitPath, "root:root", "0644", "022") + " && systemctl daemon-reload"})
		}
	}
	if (freshCreds || o.Mode == ModeRepair) && r.BBRAvail && !r.BBRActive {
		add(Step{ID: "bbr", Title: "Enable BBR congestion control", File: bbrPath,
			Stdin: []byte("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"),
			Why:   "Improves throughput on lossy long-distance links.",
			Cmd:   uploadCmd(bbrPath, "root:root", "0644", "022") + " && sysctl --system >/dev/null"})
	}
	if freshCreds || o.Mode == ModeRepair {
		switch r.Firewall {
		case "ufw":
			add(Step{ID: "firewall", Title: fmt.Sprintf("Open port %d in ufw", o.Port), Why: "So clients can connect.", Cmd: fmt.Sprintf("ufw allow %d/tcp", o.Port)})
		case "firewalld":
			add(Step{ID: "firewall", Title: fmt.Sprintf("Open port %d in firewalld", o.Port), Why: "So clients can connect.",
				Cmd: fmt.Sprintf("firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload", o.Port)})
		}
	}
	if o.Mode == ModeUpgrade {
		add(Step{ID: "restart", Title: "Restart the service on the new binary", Why: "The upgrade takes effect on restart; if it doesn't come up, the previous binary is restored.",
			Cmd: fmt.Sprintf("systemctl restart %s", serviceName)})
	} else {
		add(Step{ID: "start", Title: "Enable and start the service", Why: "Starts the proxy now and at every boot.",
			Cmd: fmt.Sprintf("systemctl enable %s >/dev/null 2>&1; systemctl restart %s", serviceName, serviceName)})
	}
	add(Step{ID: "active", Title: "Check the service is running", Why: "Waits a moment, then asks systemd.",
		Cmd: fmt.Sprintf("sleep 2; systemctl is-active %s", serviceName)})
	add(Step{ID: "listening", Title: fmt.Sprintf("Check it is listening on port %d", o.Port), Why: "Confirms the port is open on the server itself.",
		Cmd: fmt.Sprintf("ss -ltn | grep -q ':%d ' && echo listening", o.Port)})
	if needDownload {
		add(Step{ID: "cleanup", Title: "Remove temporary files", Why: "Deletes the download.", Cmd: "rm -rf " + tmpDir})
	}
	return p, nil
}

func assetName(version, arch string) string {
	return fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", version, arch)
}

func downloadURL(version, arch string) string {
	return fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/%s", version, assetName(version, arch))
}

func installPackagesCmd(pm string) string {
	switch pm {
	case "apt-get":
		return "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates tar"
	case "dnf":
		return "dnf install -y -q curl ca-certificates tar"
	default:
		return "yum install -y -q curl ca-certificates tar"
	}
}

// uploadCmd writes stdin to path with the given owner and mode.
func uploadCmd(path, owner, mode, umask string) string {
	dir := path[:strings.LastIndex(path, "/")]
	return fmt.Sprintf("umask %s && mkdir -p %s && cat > %s && chown %s %s && chmod %s %s",
		umask, shq(dir), shq(path), owner, shq(path), mode, shq(path))
}

const unitFile = `[Unit]
Description=sing-box service (managed by Clash Mihomac)
After=network-online.target
Wants=network-online.target

[Service]
User=sing-box
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

// ServerConfig renders the sing-box server config for a VLESS+Reality node.
func ServerConfig(port int, sni string, c Creds) ([]byte, error) {
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "vless", "tag": "vless-in", "listen": "::", "listen_port": port,
			"users": []any{map[string]any{"uuid": c.UUID, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{
				"enabled": true, "server_name": sni,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": sni, "server_port": 443},
					"private_key": c.PrivateKey,
					"short_id":    []string{c.ShortID},
				},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// ParseServerConfig recovers a node's settings from a config written by
// ServerConfig.
func ParseServerConfig(data []byte) (port int, sni string, c Creds, err error) {
	var cfg struct {
		Inbounds []struct {
			Type       string `json:"type"`
			ListenPort int    `json:"listen_port"`
			Users      []struct {
				UUID string `json:"uuid"`
			} `json:"users"`
			TLS struct {
				ServerName string `json:"server_name"`
				Reality    struct {
					PrivateKey string   `json:"private_key"`
					ShortID    []string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err = json.Unmarshal(data, &cfg); err != nil {
		return 0, "", Creds{}, fmt.Errorf("read the server config: %w", err)
	}
	for _, in := range cfg.Inbounds {
		if in.Type != "vless" || len(in.Users) == 0 || in.TLS.Reality.PrivateKey == "" {
			continue
		}
		c = Creds{UUID: in.Users[0].UUID, PrivateKey: in.TLS.Reality.PrivateKey}
		if len(in.TLS.Reality.ShortID) > 0 {
			c.ShortID = in.TLS.Reality.ShortID[0]
		}
		if c.PublicKey, err = PublicFromPrivate(c.PrivateKey); err != nil {
			return 0, "", Creds{}, err
		}
		return in.ListenPort, in.TLS.ServerName, c, nil
	}
	return 0, "", Creds{}, errors.New("the server config has no VLESS + Reality inbound that Clash Mihomac created")
}

// Render shows the plan as a person would review it: every step with the
// exact command, and the content of every file it writes, with secrets hidden.
func (p Plan) Render() string {
	red := p.Redactor()
	var b strings.Builder
	fmt.Fprintf(&b, "Plan: %s on %s:%d (SNI %s), %d steps\n", p.Mode, p.Options.Host, p.Options.Port, p.Options.SNI, len(p.Steps))
	for _, why := range p.Blocked {
		fmt.Fprintf(&b, "  ✗ BLOCKED: %s\n", why)
	}
	for i, s := range p.Steps {
		fmt.Fprintf(&b, "\n%d. %s\n   %s\n   $ %s\n", i+1, s.Title, s.Why, red.Redact(s.Cmd))
		if s.File != "" {
			fmt.Fprintf(&b, "   writes %s:\n", s.File)
			for _, l := range strings.Split(strings.TrimRight(red.Redact(string(s.Stdin)), "\n"), "\n") {
				fmt.Fprintf(&b, "   | %s\n", l)
			}
		}
	}
	return b.String()
}
