// Package examples embeds the demo infrastructure projects so the binary can
// analyse them without any files on disk.
package examples

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/TroubieD3v/cloudgraph/internal/parse"
)

//go:embed all:vulnerable-ecommerce all:insecure-kubernetes all:hardened-infrastructure
var content embed.FS

// Demo describes one bundled project.
type Demo struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	dirs        []string
	prefix      bool
}

var demos = []Demo{
	{Name: "vulnerable-ecommerce", Title: "Vulnerable E-commerce",
		Description: "Docker Compose shop with a public frontend, privileged backend, docker.sock mount and exposed databases, plus an AWS Terraform plan with an open security group and an admin instance role.",
		dirs:        []string{"vulnerable-ecommerce"}},
	{Name: "insecure-kubernetes", Title: "Insecure Kubernetes Cluster",
		Description: "Namespaces, ServiceAccounts, cluster-wide RBAC, a privileged workload behind a LoadBalancer and a database without NetworkPolicy.",
		dirs:        []string{"insecure-kubernetes"}},
	{Name: "hardened-infrastructure", Title: "Hardened Infrastructure",
		Description: "The same shop, cluster and AWS stack with least privilege, TLS, NetworkPolicies and no public data stores. Use it for before/after comparison.",
		dirs:        []string{"hardened-infrastructure"}},
	{Name: "vulnerable-all", Title: "All vulnerable projects",
		Description: "Vulnerable E-commerce and Insecure Kubernetes analysed together. This is the counterpart of the hardened project in infrastructure diffs.",
		dirs:        []string{"vulnerable-ecommerce", "insecure-kubernetes"}, prefix: true},
}

// List returns the bundled demos.
func List() []Demo { return append([]Demo(nil), demos...) }

// Files returns the parsed-input files of a demo.
func Files(name string) ([]parse.File, error) {
	for _, d := range demos {
		if d.Name != name {
			continue
		}
		var out []parse.File
		for _, dir := range d.dirs {
			err := fs.WalkDir(content, dir, func(p string, e fs.DirEntry, err error) error {
				if err != nil || e.IsDir() {
					return err
				}
				data, err := content.ReadFile(p)
				if err != nil {
					return err
				}
				rel := p[len(dir)+1:]
				if d.prefix {
					rel = path.Join(dir, rel)
				}
				out = append(out, parse.File{Name: rel, Data: data})
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
	return nil, fmt.Errorf("unknown demo %q", name)
}
