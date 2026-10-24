package parse

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Small helpers around yaml.Node so parsers can read values together with the
// line numbers they came from.

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && (n.Kind == yaml.AliasNode || n.Kind == yaml.DocumentNode) {
		if n.Kind == yaml.AliasNode {
			n = n.Alias
		} else if len(n.Content) > 0 {
			n = n.Content[0]
		} else {
			return nil
		}
	}
	return n
}

// get returns the value node stored under key, or nil.
func get(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return resolve(n.Content[i+1])
		}
	}
	return nil
}

// keyLine returns the line of the key itself (more useful than the value line
// for multi-line values).
func keyLine(n *yaml.Node, key string) int {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return 0
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i].Line
		}
	}
	return 0
}

// dig follows a chain of keys.
func dig(n *yaml.Node, keys ...string) *yaml.Node {
	for _, k := range keys {
		n = get(n, k)
		if n == nil {
			return nil
		}
	}
	return n
}

func str(n *yaml.Node) string {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func strAt(n *yaml.Node, keys ...string) string { return str(dig(n, keys...)) }

func boolPtr(n *yaml.Node) *bool {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return nil
	}
	switch strings.ToLower(n.Value) {
	case "true", "yes", "on":
		t := true
		return &t
	case "false", "no", "off":
		f := false
		return &f
	}
	return nil
}

func intPtr(n *yaml.Node) *int64 {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return nil
	}
	v, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

func items(n *yaml.Node) []*yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, 0, len(n.Content))
	for _, c := range n.Content {
		out = append(out, resolve(c))
	}
	return out
}

func strList(n *yaml.Node) []string {
	var out []string
	for _, it := range items(n) {
		if s := str(it); s != "" {
			out = append(out, s)
		}
	}
	return out
}

type pair struct {
	Key  string
	Val  *yaml.Node
	Line int
}

func pairs(n *yaml.Node) []pair {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]pair, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, pair{Key: n.Content[i].Value, Val: resolve(n.Content[i+1]), Line: n.Content[i].Line})
	}
	return out
}

// strMap reads a mapping of scalars (labels, selectors).
func strMap(n *yaml.Node) map[string]string {
	ps := pairs(n)
	if len(ps) == 0 {
		return nil
	}
	out := make(map[string]string, len(ps))
	for _, p := range ps {
		out[p.Key] = str(p.Val)
	}
	return out
}

// lastLine returns the highest line number covered by n.
func lastLine(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	max := n.Line
	if n.Kind == yaml.ScalarNode && (n.Style&yaml.LiteralStyle != 0 || n.Style&yaml.FoldedStyle != 0) {
		max += strings.Count(strings.TrimRight(n.Value, "\n"), "\n") + 1
	}
	for _, c := range n.Content {
		if l := lastLine(c); l > max {
			max = l
		}
	}
	return max
}
