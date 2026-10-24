// Command cloudgraph is the CloudGraph CLI and API server.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TroubieD3v/cloudgraph/examples"
	"github.com/TroubieD3v/cloudgraph/internal/analyze"
	"github.com/TroubieD3v/cloudgraph/internal/model"
	"github.com/TroubieD3v/cloudgraph/internal/parse"
	"github.com/TroubieD3v/cloudgraph/internal/report"
	"github.com/TroubieD3v/cloudgraph/internal/rules"
)

// version is overridden at release time: -ldflags "-X main.version=v1.2.3"
var version = "0.1.0"

const usage = `CloudGraph — offline infrastructure attack path analysis

Usage:
  cloudgraph scan <path|demo:NAME>... [--format table|json|sarif|html] [--output FILE] [--fail-on SEVERITY]
  cloudgraph simulate <path|demo:NAME>... (--list | --fix ID,ID | --all) [--patch FILE]
  cloudgraph diff <A> <B>
  cloudgraph serve [--addr 127.0.0.1:8080] [--db cloudgraph.db]
  cloudgraph rules [--format table|markdown]
  cloudgraph demos
  cloudgraph version

A path is a file or directory of Docker Compose, Kubernetes YAML or Terraform
plan JSON (terraform show -json plan.out). "demo:NAME" selects a bundled project.
`

func main() {
	report.Version = version
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	code := 0
	switch cmd {
	case "scan":
		code, err = cmdScan(args)
	case "simulate":
		err = cmdSimulate(args)
	case "diff":
		err = cmdDiff(args)
	case "serve":
		err = cmdServe(args)
	case "rules":
		err = cmdRules(args)
	case "demos":
		for _, d := range examples.List() {
			fmt.Printf("demo:%-24s %s\n", d.Name, d.Title)
		}
	case "version", "--version":
		fmt.Println("cloudgraph", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

// parseInterspersed lets flags appear before or after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func load(inputs []string) (string, []parse.File, error) {
	if len(inputs) == 0 {
		return "", nil, fmt.Errorf("no input path given")
	}
	var files []parse.File
	var names []string
	for _, in := range inputs {
		if strings.HasPrefix(in, "demo:") {
			fs, err := examples.Files(strings.TrimPrefix(in, "demo:"))
			if err != nil {
				return "", nil, err
			}
			files = append(files, fs...)
		} else {
			fs, err := parse.LoadPaths([]string{in})
			if err != nil {
				return "", nil, err
			}
			files = append(files, fs...)
		}
		names = append(names, in)
	}
	return strings.Join(names, " + "), files, nil
}

func analyseInputs(inputs []string) (*model.Analysis, *parse.Inventory, error) {
	name, files, err := load(inputs)
	if err != nil {
		return nil, nil, err
	}
	return analyze.Run(name, files)
}

func openOut(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func cmdScan(args []string) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "table", "table, json, sarif or html")
	output := fs.String("output", "", "write to FILE instead of stdout")
	failOn := fs.String("fail-on", "", "exit 1 if a finding of at least this severity exists (critical, high, medium, low)")
	inputs, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	a, _, err := analyseInputs(inputs)
	if err != nil {
		return 2, err
	}
	w, closeFn, err := openOut(*output)
	if err != nil {
		return 2, err
	}
	defer closeFn()
	switch *format {
	case "table":
		report.Text(w, a)
	case "json":
		err = report.JSON(w, a)
	case "sarif":
		err = report.SARIF(w, a)
	case "html":
		err = report.HTML(w, a)
	default:
		err = fmt.Errorf("unknown format %q", *format)
	}
	if err != nil {
		return 2, err
	}
	if *output != "" && *output != "-" {
		fmt.Fprintf(os.Stderr, "cloudgraph: %d findings (%s), %d risk paths → %s\n",
			a.Summary.Findings, strings.Join(report.SeverityCounts(a), ", "), a.Summary.Paths, *output)
	}
	if *failOn != "" {
		min := model.SeverityRank(*failOn)
		if min == 0 {
			return 2, fmt.Errorf("unknown severity %q", *failOn)
		}
		for _, f := range a.Findings {
			if model.SeverityRank(f.Severity) >= min {
				return 1, nil
			}
		}
	}
	return 0, nil
}

func cmdSimulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	list := fs.Bool("list", false, "list available virtual fixes")
	fixArg := fs.String("fix", "", "comma-separated fix IDs to apply virtually")
	all := fs.Bool("all", false, "apply every available fix")
	patch := fs.String("patch", "", "write the proposed patch to FILE")
	inputs, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	a, inv, err := analyseInputs(inputs)
	if err != nil {
		return err
	}
	if *list || (*fixArg == "" && !*all) {
		fmt.Printf("%d paths, %d findings. Available fixes:\n\n", len(a.Paths), len(a.Findings))
		for _, f := range a.Fixes {
			sim, err := analyze.Simulate(a, []string{f.ID})
			if err != nil {
				return err
			}
			fmt.Printf("  %s  resolves %d path(s), %d finding(s)  %s\n", f.ID, len(sim.PathsResolved), len(sim.FindingsResolved), f.Description)
		}
		return nil
	}
	var ids []string
	if *all {
		for _, f := range a.Fixes {
			ids = append(ids, f.ID)
		}
	} else {
		ids = strings.Split(*fixArg, ",")
	}
	sim, err := analyze.Simulate(a, ids)
	if err != nil {
		return err
	}
	fmt.Printf("Applied %d virtual fix(es) — no files were changed.\n", len(sim.Applied))
	fmt.Printf("Attack paths: %d → %d   Findings: %d → %d\n", sim.PathsBefore, sim.PathsAfter, sim.FindingsBefore, sim.FindingsAfter)
	for _, p := range sim.PathsResolved {
		fmt.Printf("  resolved: %s\n", p.Title)
	}
	for _, p := range sim.PathsRemaining {
		fmt.Printf("  remaining: %s\n", p.Title)
	}
	for _, p := range sim.PathsNew {
		fmt.Printf("  NEW: %s\n", p.Title)
	}
	for _, s := range sim.Skipped {
		fmt.Printf("  skipped: %s\n", s)
	}
	if *patch != "" {
		var applied []string
		for _, f := range sim.Applied {
			applied = append(applied, f.ID)
		}
		text, manual := analyze.Patch(a, applied, inv.Files)
		if err := os.WriteFile(*patch, []byte(text), 0o644); err != nil {
			return err
		}
		fmt.Printf("Patch written to %s (%d manual step(s) listed in its header)\n", *patch, len(manual))
	}
	return nil
}

func cmdDiff(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("diff needs exactly two inputs")
	}
	a, _, err := analyseInputs([]string{args[0]})
	if err != nil {
		return err
	}
	b, _, err := analyseInputs([]string{args[1]})
	if err != nil {
		return err
	}
	d := analyze.Diff(a, b)
	fmt.Printf("A: %s\nB: %s\n\n", a.Name, b.Name)
	for _, k := range []string{"resources", "edges", "findings", "paths", "unknowns"} {
		fmt.Printf("  %-10s %4d → %d\n", k, d.Counts[k][0], d.Counts[k][1])
	}
	fmt.Printf("\nPaths that disappeared: %d\n", len(d.PathsDisappeared))
	for _, p := range d.PathsDisappeared {
		fmt.Printf("  - %s\n", p.Title)
	}
	fmt.Printf("Paths that appeared: %d\n", len(d.PathsAppeared))
	for _, p := range d.PathsAppeared {
		fmt.Printf("  + %s\n", p.Title)
	}
	fmt.Printf("Findings fixed: %d, introduced: %d\n", len(d.FindingsRemoved), len(d.FindingsAdded))
	return nil
}

func cmdRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	format := fs.String("format", "table", "table or markdown")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	switch *format {
	case "markdown":
		fmt.Print(rules.Markdown())
	case "table":
		for _, r := range rules.All() {
			fmt.Printf("%-11s %-9s %-11s %s\n", r.ID, r.Severity, r.Domain, r.Title)
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	return nil
}
