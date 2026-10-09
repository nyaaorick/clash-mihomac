package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/nyaaorick/clash-mihomac/internal/client"
	"github.com/nyaaorick/clash-mihomac/internal/daemon"
)

const vpsUsage = `Usage:
  mihomac vps setup --host IP [--name N] [--ssh-port 22] [--node-port 443] [--sni HOST]
                    [--sha256 HEX] [--mode install|repair|upgrade|reinstall]
        Set up a proxy on a fresh server over SSH. You enter the root password (never stored),
        review the exact plan, confirm the server's SSH fingerprint, and it does the rest:
        installs the proxy, imports the node, switches to key login, and tests the node.
  mihomac vps list                       your servers: state, load, traffic against quota
  mihomac vps check <server>             read a server's health now
  mihomac vps restart|rotate|reboot|upgrade <server> [--sha256 HEX] [--yes]
        Preview what the action will do; add --yes to run it.
  mihomac vps share <server>             the node's share link, subscription text, and QR code
  mihomac vps quota <server> --gb N [--reset-day D]
  mihomac vps disable-password <server> --yes
  mihomac vps remove <server> [--uninstall] --yes
  mihomac vps import <link|file|image.png>   add nodes from a share link, subscription, or QR code

Servers are managed over key login; the password is only used during setup.
`

func cmdVPS(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, vpsUsage)
		return errors.New("missing vps command")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("vps "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, vpsUsage) }
	name := instanceFlag(fs)
	host := fs.String("host", "", "server IPv4 address")
	label := fs.String("name", "", "name for the server and its node")
	sshPort := fs.Int("ssh-port", 22, "SSH port")
	nodePort := fs.Int("node-port", 443, "port the proxy listens on")
	sni := fs.String("sni", "", "site Reality impersonates (default www.microsoft.com)")
	sha := fs.String("sha256", "", "SHA-256 of the proxy release asset (required until one is pinned)")
	mode := fs.String("mode", "", "install, repair, upgrade, or reinstall (default: decided from what the server has)")
	yes := fs.Bool("yes", false, "run it instead of only previewing")
	fingerprint := fs.String("fingerprint", "", "the server's SSH fingerprint, if you already know it (skips the question)")
	gb := fs.Int("gb", 0, "monthly traffic allowance in GB")
	resetDay := fs.Int("reset-day", 1, "day of the month the allowance resets")
	uninstall := fs.Bool("uninstall", false, "also remove the proxy from the server")
	var pos []string
	for r := rest; len(r) > 0; {
		fs.Parse(r)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		r = fs.Args()[1:]
	}
	api, _, err := apiFor(*name)
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()
	need := func() (string, error) {
		if len(pos) != 1 {
			return "", fmt.Errorf("usage: mihomac vps %s <server>", sub)
		}
		return pos[0], nil
	}

	switch sub {
	case "setup":
		if *host == "" {
			return errors.New("--host is required")
		}
		pw := os.Getenv("MIHOMAC_VPS_PASSWORD")
		if pw == "" {
			fmt.Fprintf(os.Stderr, "Root password for %s (not stored): ", *host)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return fmt.Errorf("can't read the password (set MIHOMAC_VPS_PASSWORD to pass it non-interactively): %w", err)
			}
			pw = string(b)
		}
		req := daemon.SetupRequest{Name: *label, Host: *host, Port: *sshPort, Password: pw, NodePort: *nodePort, SNI: *sni, SHA256: *sha, Mode: *mode}
		fmt.Println("Connecting and checking the server (read-only)…")
		var prev daemon.PlanPreview
		if err := api.Post(ctx, "/api/vps/preflight", req, &prev); err != nil {
			return err
		}
		showReport(prev)
		fmt.Println(prev.Text)
		if len(prev.Blocked) > 0 {
			return errors.New("the plan is blocked (see above); nothing was changed")
		}
		fmt.Printf("\nThe server's SSH fingerprint is %s\n", prev.HostKey)
		if *fingerprint != "" && *fingerprint != prev.HostKey {
			return fmt.Errorf("the server presented %s, not the fingerprint you gave; nothing was changed", prev.HostKey)
		}
		if !*yes || *fingerprint == "" {
			if !isTerminal() {
				fmt.Println("\nThis was a preview; nothing has changed on the server.")
				return errors.New("to apply it non-interactively, re-run with --yes --fingerprint <the fingerprint above>")
			}
			if !confirm("\nDoes that fingerprint match your provider's console, and do you want to run this plan? [y/N] ") {
				fmt.Println("Cancelled; nothing was changed.")
				return nil
			}
		}
		var started struct {
			JobID string `json:"job_id"`
		}
		if err := api.Post(ctx, "/api/vps/setup", map[string]string{"plan_id": prev.PlanID, "host_key": prev.HostKey}, &started); err != nil {
			return err
		}
		return followJob(api, started.JobID)

	case "list":
		var ms []daemon.MachineView
		if err := api.Get(ctx, "/api/vps/machines", &ms); err != nil {
			return err
		}
		if len(ms) == 0 {
			fmt.Println("No servers yet. `mihomac vps setup --host <ip>` sets one up.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tADDRESS\tSTATE\tCPU\tMEM\tDISK\tTRAFFIC\tCHECKED")
		for _, m := range ms {
			state, cpu, mem, disk, checked := "unknown", "-", "-", "-", "never"
			if m.Last != nil {
				state, checked = string(m.Last.State), time.Since(m.Last.Time).Round(time.Second).String()+" ago"
				if mt := m.Last.Metrics; mt != nil {
					cpu, mem, disk = fmt.Sprintf("%.0f%%", mt.CPUPercent), fmt.Sprintf("%.0f%%", mt.MemUsedPct), fmt.Sprintf("%.0f%%", mt.DiskUsedPct)
				}
			}
			traffic := fmt.Sprintf("%.1f GB", m.TrafficUsedGB)
			if m.Quota.GB > 0 {
				traffic += fmt.Sprintf(" of %d GB", m.Quota.GB)
			}
			fmt.Fprintf(w, "%s\t%s:%d\t%s\t%s\t%s\t%s\t%s\t%s\n", m.Name, m.Host, m.Port, state, cpu, mem, disk, traffic, checked)
		}
		return w.Flush()

	case "check":
		id, err := need()
		if err != nil {
			return err
		}
		var m daemon.MachineView
		if err := api.Post(ctx, "/api/vps/machines/"+id+"/check", map[string]string{}, &m); err != nil {
			return err
		}
		return printMachine(m)

	case "restart", "rotate", "reboot", "upgrade":
		id, err := need()
		if err != nil {
			return err
		}
		var prev daemon.PlanPreview
		if err := api.Post(ctx, "/api/vps/machines/"+id+"/preview", map[string]string{"kind": sub, "sha256": *sha}, &prev); err != nil {
			return err
		}
		fmt.Println(prev.Text)
		if len(prev.Blocked) > 0 {
			return errors.New("the plan is blocked (see above); nothing was changed")
		}
		if !*yes {
			fmt.Println("\nThis was a preview; nothing has changed. Re-run with --yes to apply it.")
			return nil
		}
		var started struct {
			JobID string `json:"job_id"`
		}
		if err := api.Post(ctx, "/api/vps/machines/"+id+"/run", map[string]string{"plan_id": prev.PlanID}, &started); err != nil {
			return err
		}
		return followJob(api, started.JobID)

	case "share":
		id, err := need()
		if err != nil {
			return err
		}
		var s daemon.ShareView
		if err := api.Get(ctx, "/api/vps/machines/"+id+"/share", &s); err != nil {
			return err
		}
		fmt.Println("Share link (contains the node's credentials; treat it like a password):")
		fmt.Println(s.Link)
		fmt.Println("\nSubscription text (base64):")
		fmt.Println(s.Subscription)
		png, err := base64.StdEncoding.DecodeString(s.QRPNG)
		if err == nil {
			path := filepath.Join(os.TempDir(), "mihomac-"+safeName(id)+"-qr.png")
			if err := os.WriteFile(path, png, 0o600); err == nil {
				fmt.Println("\nQR code saved to", path, "(delete it when done)")
			}
		}
		return nil

	case "quota":
		id, err := need()
		if err != nil {
			return err
		}
		var m daemon.MachineView
		if err := api.Post(ctx, "/api/vps/machines/"+id+"/quota", map[string]int{"gb": *gb, "reset_day": *resetDay}, &m); err != nil {
			return err
		}
		fmt.Printf("%s: allowance %d GB, resets on day %d.\n", m.Name, m.Quota.GB, m.Quota.ResetDay)
		return nil

	case "disable-password":
		id, err := need()
		if err != nil {
			return err
		}
		if !*yes {
			fmt.Println("This turns off SSH password login on the server; only key login (this Mac's key) will work.\nRe-run with --yes to apply it.")
			return nil
		}
		var res map[string]string
		if err := api.Post(ctx, "/api/vps/machines/"+id+"/disable-password", map[string]bool{"confirm": true}, &res); err != nil {
			return err
		}
		fmt.Println(res["result"])
		return nil

	case "remove":
		id, err := need()
		if err != nil {
			return err
		}
		if !*yes {
			msg := "This forgets the server and its imported node on this Mac."
			if *uninstall {
				msg += " It also removes the proxy from the server."
			}
			fmt.Println(msg + "\nRe-run with --yes to apply it.")
			return nil
		}
		var res map[string]any
		if err := api.Post(ctx, "/api/vps/machines/"+id+"/remove", map[string]bool{"confirm": true, "uninstall": *uninstall}, &res); err != nil {
			return err
		}
		fmt.Printf("Removed %v.\n", res["removed"])
		return nil

	case "import":
		id, err := need()
		if err != nil {
			return err
		}
		body := map[string]string{}
		switch {
		case strings.Contains(id, "://"):
			body["text"] = id
		default:
			data, err := os.ReadFile(id)
			if err != nil {
				return err
			}
			if ext := strings.ToLower(filepath.Ext(id)); ext == ".png" || ext == ".jpg" || ext == ".jpeg" {
				body["image"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
			} else {
				body["text"] = string(data)
			}
		}
		var prev daemon.ImportPreview
		if err := api.Post(ctx, "/api/vps/import", body, &prev); err != nil {
			return err
		}
		for _, e := range prev.Errors {
			fmt.Println("skipped:", e)
		}
		for _, n := range prev.Nodes {
			warn := ""
			if n.Insecure {
				warn = "  (certificate verification is OFF)"
			}
			fmt.Printf("  %-24s %-10s %s:%d%s\n", n.Name, n.Type, n.Server, n.Port, warn)
		}
		if len(prev.Nodes) == 0 {
			return errors.New("no nodes found")
		}
		if !*yes {
			fmt.Println("\nThis was a preview; add --yes to import these nodes.")
			return nil
		}
		var res map[string]any
		if err := api.Post(ctx, "/api/vps/import/apply", map[string]any{"import_id": prev.ImportID}, &res); err != nil {
			return err
		}
		fmt.Printf("Imported: %v\n", res["imported"])
		if w, ok := res["warning"]; ok {
			fmt.Println("warning:", w)
		}
		return nil
	}
	fmt.Fprint(os.Stderr, vpsUsage)
	return fmt.Errorf("unknown vps command %q", sub)
}

func showReport(p daemon.PlanPreview) {
	r := p.Report
	fmt.Printf("Server: %s, %s, %d MB memory, %d MB free disk\n", firstNonEmpty(r.OS, "unknown OS"), r.Arch, r.MemMB, r.DiskFreeMB)
	for _, i := range r.Issues {
		mark := map[string]string{"error": "✗", "warning": "!", "info": "·"}[i.Severity]
		fmt.Printf("  %s %s\n", mark, i.Message)
	}
	if p.SuggestedMode != "" {
		fmt.Printf("Mode: %s", p.Mode)
		if p.Mode != p.SuggestedMode {
			fmt.Printf(" (suggested: %s)", p.SuggestedMode)
		}
		fmt.Println()
	}
	fmt.Println()
}

func printMachine(m daemon.MachineView) error {
	fmt.Printf("%s (%s:%d): ", m.Name, m.Host, m.Port)
	if m.Last == nil {
		fmt.Println("not checked yet")
		return nil
	}
	fmt.Println(m.Last.State)
	if m.Last.Error != "" {
		fmt.Println("  error:", m.Last.Error)
	}
	for _, r := range m.Last.Reasons {
		fmt.Println("  !", r)
	}
	if mt := m.Last.Metrics; mt != nil {
		fmt.Printf("  CPU %.0f%%, memory %.0f%% of %d MB, disk %.0f%% of %.0f GB, load %.2f %.2f %.2f, up %s\n",
			mt.CPUPercent, mt.MemUsedPct, mt.MemTotalMB, mt.DiskUsedPct, mt.DiskTotalGB, mt.Load1, mt.Load5, mt.Load15, (time.Duration(mt.UptimeSecs) * time.Second).String())
		fmt.Printf("  network ↓ %s/s ↑ %s/s on %s; this period: %.1f GB", byteSize(int64(mt.RxBps)), byteSize(int64(mt.TxBps)), mt.Iface, m.TrafficUsedGB)
		if m.Quota.GB > 0 {
			fmt.Printf(" of %d GB (%.0f%%)", m.Quota.GB, m.QuotaPercent)
		}
		fmt.Printf("\n  service: running=%v version=%s ports=%v\n", mt.ServiceActive, orDash(mt.ServiceVersion), mt.Listening)
	}
	return nil
}

func followJob(api *client.Client, id string) error {
	shown := 0
	for {
		ctx, cancel := apiCtx()
		var j struct {
			Done    bool                    `json:"done"`
			Error   string                  `json:"error"`
			Log     []struct{ Text string } `json:"log"`
			Outcome *daemon.JobOutcome      `json:"outcome"`
		}
		err := api.Get(ctx, "/api/vps/jobs/"+id, &j)
		cancel()
		if err != nil {
			return err
		}
		for ; shown < len(j.Log); shown++ {
			fmt.Println(j.Log[shown].Text)
		}
		if j.Done {
			if j.Error != "" {
				return fmt.Errorf("failed: %s\nThe full (redacted) log is saved under the Mihomac data directory in vps/logs/", j.Error)
			}
			if o := j.Outcome; o != nil {
				fmt.Println()
				if o.Node != "" {
					fmt.Printf("Node %q is imported", o.Node)
					if o.LatencyMs > 0 {
						fmt.Printf(" and answers in %d ms end to end", o.LatencyMs)
					}
					fmt.Println(".")
				}
				if o.EgressIP != "" {
					fmt.Printf("Traffic through it leaves from %s (DNS on the server works: %v).\n", o.EgressIP, o.DNSOK)
				}
				for _, n := range o.Notes {
					fmt.Println("•", n)
				}
			}
			return nil
		}
		time.Sleep(700 * time.Millisecond)
	}
}

func isTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
