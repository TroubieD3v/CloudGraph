// Package server exposes the analysis engine over a local REST API and serves
// the embedded web UI.
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
	"github.com/TroubieD3v/cloudgraph/internal/report"
	"github.com/TroubieD3v/cloudgraph/internal/store"
)

const maxBody = 16 << 20 // 16 MiB of uploaded configuration

// Server wires the HTTP routes.
type Server struct {
	store  *store.Store
	ui     fs.FS
	limits model.SearchLimits
}

// New builds a Server. ui may be nil for API-only operation.
func New(st *store.Store, ui fs.FS) *Server {
	return &Server{store: st, ui: ui, limits: model.DefaultSearchLimits()}
}

// WithLimits sets the default path search limits for new analyses.
func (s *Server) WithLimits(l model.SearchLimits) *Server {
	s.limits = l
	return s
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/demos", s.demos)
	mux.HandleFunc("GET /api/analyses", s.list)
	mux.HandleFunc("POST /api/analyses", s.create)
	mux.HandleFunc("GET /api/analyses/{id}", s.get)
	mux.HandleFunc("DELETE /api/analyses/{id}", s.remove)
	mux.HandleFunc("POST /api/analyses/{id}/simulate", s.simulate)
	mux.HandleFunc("POST /api/analyses/{id}/patch", s.patch)
	mux.HandleFunc("GET /api/analyses/{id}/report/{ext}", s.reportFile)
	mux.HandleFunc("GET /api/diff", s.diff)
	if s.ui != nil {
		mux.Handle("/", spa(s.ui))
	}
	return secure(mux)
}

// secure adds conservative headers; the API is meant for local use only.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		// Reject cross-site API writes (CSRF against a localhost server).
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && !sameHost(o, r.Host) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			if ct := r.Header.Get("Content-Type"); r.ContentLength != 0 && !strings.HasPrefix(ct, "application/json") {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameHost(origin, host string) bool {
	origin = strings.TrimPrefix(strings.TrimPrefix(origin, "http://"), "https://")
	return origin == host
}

func spa(root fs.FS) http.Handler {
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.Stat(root, "index.html"); err != nil {
			http.Error(w, "CloudGraph API is running, but the web UI has not been built into this binary (run: make build).", http.StatusNotFound)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(root, p); err != nil {
			r.URL.Path = "/" // client-side routing fallback
		}
		files.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return false
	}
	return true
}

func (s *Server) demos(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, examples.List()) }

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.List()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, items)
}

type createReq struct {
	Name string `json:"name"`
	Demo string `json:"demo"`
	// Limits overrides individual search limits; omitted fields keep the server defaults.
	Limits *model.SearchLimits `json:"limits"`
	Files  []struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"files"`
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	lim := s.limits
	req := createReq{Limits: &lim}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Limits == nil {
		req.Limits = &lim
	}
	if err := req.Limits.Validate(); err != nil {
		fail(w, 400, err)
		return
	}
	var files []parse.File
	name := req.Name
	switch {
	case req.Demo != "":
		fs, err := examples.Files(req.Demo)
		if err != nil {
			fail(w, 404, err)
			return
		}
		files = fs
		if name == "" {
			name = "demo:" + req.Demo
		}
	case len(req.Files) > 0:
		for _, f := range req.Files {
			if f.Name == "" || strings.Contains(f.Name, "..") {
				fail(w, 400, fmt.Errorf("invalid file name %q", f.Name))
				return
			}
			files = append(files, parse.File{Name: strings.ReplaceAll(f.Name, "\\", "/"), Data: []byte(f.Content)})
		}
		if name == "" {
			name = "upload"
		}
	default:
		fail(w, 400, errors.New("provide either \"demo\" or \"files\""))
		return
	}
	a, _, err := analyze.RunWith(name, files, *req.Limits)
	if err != nil {
		fail(w, 422, err)
		return
	}
	if len(a.Resources) <= 1 && len(a.Warnings) > 0 {
		fail(w, 422, fmt.Errorf("no supported resources found: %s", strings.Join(a.Warnings, "; ")))
		return
	}
	if err := s.store.Save(a); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 201, a)
}

func (s *Server) load(w http.ResponseWriter, id string) *model.Analysis {
	a, err := s.store.Get(id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, 404, err)
		return nil
	}
	if err != nil {
		fail(w, 500, err)
		return nil
	}
	return a
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	if a := s.load(w, r.PathValue("id")); a != nil {
		writeJSON(w, 200, a)
	}
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("id")); err != nil {
		code := 500
		if errors.Is(err, store.ErrNotFound) {
			code = 404
		}
		fail(w, code, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type fixReq struct {
	Fixes []string `json:"fixes"`
}

func (s *Server) simulate(w http.ResponseWriter, r *http.Request) {
	a := s.load(w, r.PathValue("id"))
	if a == nil {
		return
	}
	var req fixReq
	if !readJSON(w, r, &req) {
		return
	}
	res, err := analyze.Simulate(a, req.Fixes)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) patch(w http.ResponseWriter, r *http.Request) {
	a := s.load(w, r.PathValue("id"))
	if a == nil {
		return
	}
	var req fixReq
	if !readJSON(w, r, &req) {
		return
	}
	text, manual := analyze.Patch(a, req.Fixes, nil)
	writeJSON(w, 200, map[string]any{"patch": text, "manual": manual})
}

func (s *Server) reportFile(w http.ResponseWriter, r *http.Request) {
	a := s.load(w, r.PathValue("id"))
	if a == nil {
		return
	}
	var buf bytes.Buffer
	var err error
	ct := "application/json"
	switch r.PathValue("ext") {
	case "json":
		err = report.JSON(&buf, a)
	case "sarif":
		err = report.SARIF(&buf, a)
	case "html":
		ct = "text/html; charset=utf-8"
		err = report.HTML(&buf, a)
	default:
		fail(w, 404, errors.New("unknown report format"))
		return
	}
	if err != nil {
		fail(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cloudgraph-%s.%s"`, a.ID, r.PathValue("ext")))
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	a := s.load(w, r.URL.Query().Get("a"))
	if a == nil {
		return
	}
	b := s.load(w, r.URL.Query().Get("b"))
	if b == nil {
		return
	}
	writeJSON(w, 200, analyze.Diff(a, b))
}
