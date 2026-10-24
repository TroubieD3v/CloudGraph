// Package parse imports Docker Compose, Kubernetes YAML and Terraform plan JSON
// into the normalised resource model.
package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

// File is one input document held in memory.
type File struct {
	Name string // slash-separated, relative to the scan root
	Data []byte
}

// Inventory is the output of the import stage.
type Inventory struct {
	Resources []*model.Resource
	Files     map[string][]string // file name -> lines, for patch export
	Warnings  []string
}

// Formats returned by Detect.
const (
	FormatCompose    = "compose"
	FormatKubernetes = "kubernetes"
	FormatTerraform  = "terraform"
	FormatUnknown    = ""
)

var skipDirs = map[string]bool{".git": true, "node_modules": true, ".terraform": true, "vendor": true, ".idea": true}

// LoadPaths reads files and directories (recursively) into memory.
func LoadPaths(paths []string) ([]File, error) {
	var files []File
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			files = append(files, File{Name: filepath.ToSlash(filepath.Base(p)), Data: data})
			continue
		}
		root := p
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skipDirs[d.Name()] && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yaml" && ext != ".yml" && ext != ".json" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			files = append(files, File{Name: filepath.ToSlash(rel), Data: data})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

// Detect guesses the format of a file from its content.
func Detect(f File) string {
	ext := strings.ToLower(filepath.Ext(f.Name))
	if ext == ".json" {
		var probe struct {
			FormatVersion   string          `json:"format_version"`
			PlannedValues   json.RawMessage `json:"planned_values"`
			ResourceChanges json.RawMessage `json:"resource_changes"`
			Configuration   json.RawMessage `json:"configuration"`
		}
		if json.Unmarshal(f.Data, &probe) == nil && probe.FormatVersion != "" &&
			(probe.PlannedValues != nil || probe.ResourceChanges != nil || probe.Configuration != nil) {
			return FormatTerraform
		}
		return FormatUnknown
	}
	dec := yaml.NewDecoder(bytes.NewReader(f.Data))
	for {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			return FormatUnknown
		}
		root := resolve(&n)
		if root == nil || root.Kind != yaml.MappingNode {
			continue
		}
		if get(root, "apiVersion") != nil && get(root, "kind") != nil {
			return FormatKubernetes
		}
		if get(root, "services") != nil {
			return FormatCompose
		}
	}
}

// Parse imports every recognised file. Unrecognised files are reported as warnings.
func Parse(files []File) (*Inventory, error) {
	inv := &Inventory{Files: map[string][]string{}}
	for _, f := range files {
		inv.Files[f.Name] = strings.Split(strings.ReplaceAll(string(f.Data), "\r\n", "\n"), "\n")
		var (
			res  []*model.Resource
			warn []string
			err  error
		)
		switch Detect(f) {
		case FormatKubernetes:
			res, warn, err = parseKubernetes(f)
		case FormatCompose:
			res, warn, err = parseCompose(f)
		case FormatTerraform:
			res, warn, err = parseTerraform(f)
		default:
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: format not recognised, skipped", f.Name))
			continue
		}
		if err != nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: %v", f.Name, err))
			continue
		}
		inv.Warnings = append(inv.Warnings, warn...)
		inv.Resources = append(inv.Resources, res...)
	}
	inv.Resources = dedupe(inv.Resources, &inv.Warnings)
	return inv, nil
}

func dedupe(rs []*model.Resource, warnings *[]string) []*model.Resource {
	seen := map[string]*model.Resource{}
	out := rs[:0:0]
	for _, r := range rs {
		if prev, ok := seen[r.ID]; ok {
			*warnings = append(*warnings, fmt.Sprintf("%s: duplicate resource %s (already defined in %s:%d), ignored",
				r.Src.File, r.ID, prev.Src.File, prev.Src.Line))
			continue
		}
		seen[r.ID] = r
		out = append(out, r)
	}
	return out
}
