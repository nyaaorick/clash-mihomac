package vps

import (
	"fmt"
)

// Machine actions. Each is previewed as a plan and runs only after the
// person confirms it.
const (
	ActionRestart = "restart"
	ActionRotate  = "rotate"
	ActionReboot  = "reboot"
)

// ActionPlan builds the plan for a service action on a machine. port and sni
// are the node's current settings (read from the server with ReadExisting);
// they matter for rotating credentials, which keeps the node's address
// and disguise and only replaces the secrets.
func ActionPlan(kind string, m Machine, port int, sni string) (Plan, error) {
	if port == 0 {
		port = m.NodePort
	}
	if port == 0 {
		port = 443
	}
	if sni == "" {
		sni = DefaultSNI
	}
	name := m.NodeName
	if name == "" {
		name = m.Name
	}
	opts := Options{Mode: kind, Name: name, Host: m.Host, Port: port, SNI: sni, Release: DefaultRelease}
	if !hostRE.MatchString(opts.Host) || !proxyNameRE.MatchString(opts.Name) || !sniRE.MatchString(opts.SNI) || port < 1 || port > 65535 {
		return Plan{}, fmt.Errorf("the machine's saved settings aren't valid for %s", kind)
	}
	p := Plan{Mode: kind, Options: opts}
	add := func(s Step) { p.Steps = append(p.Steps, s) }
	verify := func() {
		add(Step{ID: "active", Title: "Check the service is running", Why: "Waits a moment, then asks systemd.", Cmd: fmt.Sprintf("sleep 2; systemctl is-active %s", serviceName)})
		add(Step{ID: "listening", Title: fmt.Sprintf("Check it is listening on port %d", port), Why: "Confirms the port is open on the server itself.", Cmd: fmt.Sprintf("ss -ltn | grep -q ':%d ' && echo listening", port)})
	}

	switch kind {
	case ActionRestart:
		add(Step{ID: "restart", Title: "Restart the proxy service", Why: "Active connections through this node drop for a moment and reconnect.", Cmd: fmt.Sprintf("systemctl restart %s", serviceName)})
		verify()
	case ActionRotate:
		c, err := NewCreds()
		if err != nil {
			return Plan{}, err
		}
		p.Creds = c
		p.Link = VlessRealityLink(name, m.Host, port, c.UUID, c.PublicKey, c.ShortID, sni)
		cfg, err := ServerConfig(port, sni, c)
		if err != nil {
			return Plan{}, err
		}
		add(Step{ID: "backup", Title: "Keep a copy of the current config", Why: "So a failed rotation can be undone.",
			Cmd:  fmt.Sprintf("cp -a %s %s.prev", confPath, confPath),
			Undo: fmt.Sprintf("mv -f %s.prev %s && systemctl restart %s", confPath, confPath, serviceName)})
		add(Step{ID: "config", Title: "Write the config with new credentials", File: confPath, Stdin: cfg,
			Why: "A new user id and Reality key pair replace the old ones. Existing share links stop working; the new link is imported for you.",
			Cmd: uploadCmd(confPath, "root:sing-box", "0640", "027")})
		add(Step{ID: "check-config", Title: "Validate the config", Why: "sing-box checks its own config before it is started.", Cmd: fmt.Sprintf("%s check -c %s", binPath, confPath)})
		add(Step{ID: "restart", Title: "Restart the proxy service", Why: "Loads the new credentials; old connections drop.", Cmd: fmt.Sprintf("systemctl restart %s", serviceName)})
		verify()
	case ActionReboot:
		add(Step{ID: "reboot", Title: "Reboot the server", Why: "Everything on the server restarts; it is unreachable for a minute or so. The proxy comes back on its own at boot.",
			Cmd: "nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &"})
	default:
		return Plan{}, fmt.Errorf("unknown action %q", kind)
	}
	return p, nil
}
