package daemon

import (
	"net/http"
	"strings"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

// PackPreview is POST /api/packs/preview's reply: what installing a pack
// would do. Nothing changes until the Change is applied.
type PackPreview struct {
	Pack         rules.Pack   `json:"pack"`
	Placeholders []string     `json:"placeholders"` // targets the person still has to map
	Change       rules.Change `json:"change"`
	Diff         string       `json:"diff"`
}

type packPreviewRequest struct {
	YAML   string            `json:"yaml"`
	URL    string            `json:"url"`
	Map    map[string]string `json:"map"`
	Enable bool              `json:"enable"`
}

func (d *Daemon) handlePackPreview(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return
	}
	var req packPreviewRequest
	if !readJSON(w, r, &req) {
		return
	}
	data := []byte(req.YAML)
	source := ""
	if req.URL != "" {
		if req.YAML != "" {
			httpError(w, http.StatusBadRequest, "give either yaml or url, not both")
			return
		}
		var err error
		if data, err = rules.NewFetcher().Fetch(r.Context(), req.URL); err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		source = req.URL
	}
	prev, err := d.previewPack(data, source, req)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, prev)
}

func (d *Daemon) previewPack(data []byte, source string, req packPreviewRequest) (PackPreview, error) {
	p, err := rules.ParsePack(data)
	if err != nil {
		return PackPreview{}, err
	}
	d.mu.Lock()
	set := d.ruleSet
	d.mu.Unlock()

	prev := PackPreview{Pack: p}
	var missing []string
	for _, ph := range p.Placeholders() {
		if _, ok := req.Map[strings.TrimPrefix(ph, "@")]; !ok {
			if _, ok := req.Map[ph]; !ok {
				missing = append(missing, ph)
			}
		}
	}
	if len(missing) > 0 {
		prev.Placeholders = missing // the GUI asks for these, then previews again
		return prev, nil
	}
	change, _, err := set.PrepareInstall(p, req.Map, source, req.Enable)
	if err != nil {
		return PackPreview{}, err
	}
	diff, err := set.Diff(change)
	if err != nil {
		return PackPreview{}, err
	}
	prev.Change, prev.Diff = change, diff
	return prev, nil
}
