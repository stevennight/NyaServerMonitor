package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// themeIDPattern constrains both directory names under data/theme and the
// {id} route segment: lowercase, starts with a letter, 2-48 characters.
var themeIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)

// builtinThemeIDs lists the theme packs shipped inside the binary (embedded
// under webdist/builtin-themes/<id>/) that get copied into the runtime
// data/theme directory the first time the controller starts against a data
// directory that doesn't already have them.
var builtinThemeIDs = []string{
	"hacker-matrix",
	"retro-terminal",
	"cute-panda",
	"cute-cat",
	"forest-critter",
	"it-blue",
	"anime-sakura",
	"cyberpunk-neon",
	"ocean-wave",
	"galaxy-space",
}

type themeManifest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Author      string   `json:"author,omitempty"`
	Preview     []string `json:"preview,omitempty"`
}

type themeInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Author      string   `json:"author,omitempty"`
	Preview     []string `json:"preview,omitempty"`
}

// handleListThemes returns every installed theme pack found directly under
// the controller's data/theme directory. It is intentionally public: theme
// selection is a client-side cosmetic preference, same as the existing
// dark/light toggle, so no session is required to fetch the catalog.
func (s *Server) handleListThemes(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.cfg.ThemeDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []themeInfo{})
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to list themes")
		return
	}
	themes := make([]themeInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !themeIDPattern.MatchString(entry.Name()) {
			continue
		}
		info, ok := readThemeManifest(s.cfg.ThemeDir, entry.Name())
		if !ok {
			continue
		}
		themes = append(themes, info)
	}
	sort.Slice(themes, func(i, j int) bool { return themes[i].Name < themes[j].Name })
	writeJSON(w, http.StatusOK, themes)
}

// readThemeManifest loads and validates a single theme pack's manifest and
// confirms its style.css exists. It never returns an error to the caller:
// an invalid or incomplete pack is simply skipped so one bad drop-in can't
// break the catalog for every other pack.
func readThemeManifest(themeDir, id string) (themeInfo, bool) {
	dir := filepath.Join(themeDir, id)
	raw, err := os.ReadFile(filepath.Join(dir, "theme.json"))
	if err != nil {
		return themeInfo{}, false
	}
	var manifest themeManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return themeInfo{}, false
	}
	manifest.Name = strings.TrimSpace(manifest.Name)
	if manifest.Name == "" {
		return themeInfo{}, false
	}
	if stat, err := os.Stat(filepath.Join(dir, "style.css")); err != nil || stat.IsDir() {
		return themeInfo{}, false
	}
	return themeInfo{
		ID:          id,
		Name:        manifest.Name,
		Description: strings.TrimSpace(manifest.Description),
		Author:      strings.TrimSpace(manifest.Author),
		Preview:     manifest.Preview,
	}, true
}

// handleThemeAsset serves an individual file from within one theme pack's
// directory, e.g. GET /themes/hacker-matrix/style.css. Files are served
// directly off disk (not the embedded FS) so user-dropped packs work with
// no rebuild, and every path is validated to stay inside the requested
// pack's own directory.
func (s *Server) handleThemeAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !themeIDPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	rel := path.Clean("/" + r.PathValue("path"))
	if rel == "/" || strings.Contains(rel, "..") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	themeRoot, err := filepath.Abs(filepath.Join(s.cfg.ThemeDir, id))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to resolve theme")
		return
	}
	full, err := filepath.Abs(filepath.Join(themeRoot, filepath.FromSlash(rel)))
	if err != nil || (full != themeRoot && !strings.HasPrefix(full, themeRoot+string(filepath.Separator))) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	stat, err := os.Stat(full)
	if err != nil || stat.IsDir() || !stat.Mode().IsRegular() {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	contentType := mime.TypeByExtension(filepath.Ext(full))
	if contentType == "" {
		if strings.EqualFold(filepath.Ext(full), ".css") {
			contentType = "text/css; charset=utf-8"
		} else {
			contentType = "application/octet-stream"
		}
	}
	w.Header().Set("Content-Type", contentType)
	// Short, revalidate-friendly cache: user-dropped packs can change at
	// any time (unlike the immutable embedded flag/map assets).
	w.Header().Set("Cache-Control", "public, max-age=120")
	http.ServeFile(w, r, full)
}

// seedBuiltinThemes copies the theme packs embedded in the binary into the
// runtime data/theme directory the first time each one is missing there.
// It never overwrites a pack that already exists on disk, so a user is
// always free to edit, replace, or delete any built-in pack and have that
// choice survive a restart.
func seedBuiltinThemes(themeDir string) error {
	var errs []error
	for _, id := range builtinThemeIDs {
		dest := filepath.Join(themeDir, id)
		if _, err := os.Stat(dest); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			errs = append(errs, err)
			continue
		}
		if err := seedThemeDir(dest, "webdist/builtin-themes/"+id); err != nil {
			errs = append(errs, err)
		}
	}
	readmeDest := filepath.Join(themeDir, "README.md")
	if _, err := os.Stat(readmeDest); os.IsNotExist(err) {
		if data, readErr := webFiles.ReadFile("webdist/builtin-themes/README.md"); readErr == nil {
			if writeErr := os.WriteFile(readmeDest, data, 0o644); writeErr != nil {
				errs = append(errs, writeErr)
			}
		}
	}
	return errors.Join(errs...)
}

func seedThemeDir(dest, embedSrc string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return fs.WalkDir(webFiles, embedSrc, func(embedPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := webFiles.ReadFile(embedPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", embedPath, err)
		}
		relPath := strings.TrimPrefix(embedPath, embedSrc+"/")
		target := filepath.Join(dest, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
