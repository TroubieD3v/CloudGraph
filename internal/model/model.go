// Package model defines the data structures shared by every CloudGraph stage:
// parsers produce Resources, the graph builder produces Edges, rules produce
// Findings and the path engine produces Paths.
package model

import (
	"fmt"
	"sort"
)

// Source points back to the exact place in an input file a fact came from.
type Source struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	EndLine int    `json:"endLine,omitempty"`
	Path    string `json:"path,omitempty"` // logical path, e.g. spec.template.spec.containers[0]
}

// Confidence says how well an edge (or a whole path) is supported by the input.
type Confidence string

const (
	// Confirmed: stated explicitly in configuration (e.g. serviceAccountName).
	Confirmed Confidence = "confirmed"
	// Inferred: derived by matching rules such as label selectors or shared networks.
	Inferred Confidence = "inferred"
	// Conditional: only holds if an attacker precondition is met (e.g. app compromise).
	Conditional Confidence = "conditional"
	// Unknown: the input does not contain enough information. Never traversed.
	Unknown Confidence = "unknown"
)

// Rank orders confidences from weakest to strongest; Unknown is lowest.
func (c Confidence) Rank() int {
	switch c {
	case Confirmed:
		return 3
	case Inferred:
		return 2
	case Conditional:
		return 1
	}
	return 0
}

// Domain identifies the importer a resource came from.
const (
	DomainCompose    = "compose"
	DomainKubernetes = "kubernetes"
	DomainTerraform  = "terraform"
	DomainSynthetic  = "synthetic"
)

// Normalised resource kinds.
const (
	KindInternet       = "Internet"
	KindWorkload       = "Workload"
	KindService        = "Service"
	KindIngress        = "Ingress"
	KindServiceAccount = "ServiceAccount"
	KindRole           = "Role"
	KindBinding        = "Binding"
	KindSecret         = "Secret"
	KindConfigMap      = "ConfigMap"
	KindNetworkPolicy  = "NetworkPolicy"
	KindNamespace      = "Namespace"
	KindNetwork        = "Network"
	KindVolume         = "Volume"
	KindHost           = "Host"
	KindCapability     = "Capability"
	KindFirewall       = "Firewall"
	KindInstance       = "Instance"
	KindIdentity       = "Identity"
	KindPolicy         = "Policy"
	KindBucket         = "Bucket"
	KindDatabase       = "Database"
)

// EnvVar is a container environment variable. Literal values that look like
// secrets are masked by the parsers before they reach this struct.
type EnvVar struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	Literal     bool   `json:"literal"`
	SecretRef   string `json:"secretRef,omitempty"`
	Line        int    `json:"line,omitempty"`
	LooksSecret bool   `json:"looksSecret,omitempty"`
}

// Container is the security-relevant view of one container / compose service.
type Container struct {
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	Privileged     *bool             `json:"privileged,omitempty"`
	AllowPrivEsc   *bool             `json:"allowPrivilegeEscalation,omitempty"`
	RunAsNonRoot   *bool             `json:"runAsNonRoot,omitempty"`
	RunAsUser      *int64            `json:"runAsUser,omitempty"`
	ReadOnlyRootFS *bool             `json:"readOnlyRootFilesystem,omitempty"`
	CapAdd         []string          `json:"capAdd,omitempty"`
	CapDrop        []string          `json:"capDrop,omitempty"`
	Env            []EnvVar          `json:"env,omitempty"`
	EnvFromSecrets []string          `json:"envFromSecrets,omitempty"`
	HasLimits      bool              `json:"hasLimits"`
	Mounts         []string          `json:"mounts,omitempty"` // volume names mounted by this container
	MountSpans     map[string][2]int `json:"mountSpans,omitempty"`
	CapAddLines    []int             `json:"capAddLines,omitempty"` // line of each CapAdd entry
	Locs           map[string]int    `json:"locs,omitempty"`
}

// Volume is a pod volume or compose mount.
type Volume struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // hostPath, bind, socket, secret, configMap, emptyDir, pvc, other
	Source   string `json:"source,omitempty"`
	ReadOnly bool   `json:"readOnly,omitempty"`
	Line     int    `json:"line,omitempty"`
	Span     [2]int `json:"span,omitempty"` // first and last line of the list item
}

// PortBinding is a published port (compose) or service-level exposure.
type PortBinding struct {
	Container int    `json:"container"`
	Host      int    `json:"host,omitempty"`
	Proto     string `json:"proto,omitempty"`
	BindAddr  string `json:"bindAddr,omitempty"` // empty means all interfaces
	Line      int    `json:"line,omitempty"`
}

// Workload holds the runtime-relevant settings of a Pod-like resource.
type Workload struct {
	PodLabels      map[string]string `json:"podLabels,omitempty"`
	ServiceAccount string            `json:"serviceAccount,omitempty"`
	AutomountToken *bool             `json:"automountToken,omitempty"`
	HostNetwork    bool              `json:"hostNetwork,omitempty"`
	HostPID        bool              `json:"hostPID,omitempty"`
	HostIPC        bool              `json:"hostIPC,omitempty"`
	NetworkMode    string            `json:"networkMode,omitempty"`
	Networks       []string          `json:"networks,omitempty"`
	DependsOn      []string          `json:"dependsOn,omitempty"`
	Containers     []Container       `json:"containers"`
	Volumes        []Volume          `json:"volumes,omitempty"`
	Ports          []PortBinding     `json:"ports,omitempty"`
	DataStore      bool              `json:"dataStore,omitempty"`
	Locs           map[string]int    `json:"locs,omitempty"`
}

// PolicyRule is one RBAC rule (K8s) or IAM statement (Terraform).
type PolicyRule struct {
	APIGroups     []string `json:"apiGroups,omitempty"`
	Resources     []string `json:"resources,omitempty"`
	ResourceNames []string `json:"resourceNames,omitempty"`
	Verbs         []string `json:"verbs,omitempty"`
	Line          int      `json:"line,omitempty"`
}

// Subject is a RoleBinding subject.
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// BindingSpec describes a RoleBinding / ClusterRoleBinding.
type BindingSpec struct {
	RoleKind string    `json:"roleKind"`
	RoleName string    `json:"roleName"`
	Cluster  bool      `json:"cluster"`
	Subjects []Subject `json:"subjects"`
}

// NetPolSpec is a reduced NetworkPolicy.
type NetPolSpec struct {
	PodSelector  map[string]string `json:"podSelector,omitempty"`
	Ingress      bool              `json:"ingress"` // policyTypes includes Ingress
	Egress       bool              `json:"egress"`
	AllowSources []NetPolPeer      `json:"allowSources,omitempty"`
	// Unresolvable is set when a selector uses matchExpressions or other
	// constructs CloudGraph does not evaluate. Reachability is then Unknown.
	Unresolvable bool `json:"unresolvable,omitempty"`
}

// NetPolPeer is a "from" peer of a NetworkPolicy ingress rule.
type NetPolPeer struct {
	HasPodSelector    bool              `json:"hasPodSelector,omitempty"`
	PodSelector       map[string]string `json:"podSelector,omitempty"`
	NamespaceSelector map[string]string `json:"namespaceSelector,omitempty"`
	HasNamespaceSel   bool              `json:"hasNamespaceSelector,omitempty"`
	IPBlock           string            `json:"ipBlock,omitempty"`
	AllowAll          bool              `json:"allowAll,omitempty"`
}

// ServiceSpec is a Kubernetes Service.
type ServiceSpec struct {
	Type     string            `json:"type"`
	Selector map[string]string `json:"selector,omitempty"`
	Ports    []int             `json:"ports,omitempty"`
}

// IngressSpec is a Kubernetes Ingress.
type IngressSpec struct {
	Hosts    []string     `json:"hosts,omitempty"`
	Backends []BackendRef `json:"backends,omitempty"`
	TLS      bool         `json:"tls"`
}

// BackendRef points at a Service by name.
type BackendRef struct {
	Service string `json:"service"`
	Line    int    `json:"line,omitempty"`
}

// Resource is one node of the infrastructure inventory.
type Resource struct {
	ID          string            `json:"id"`
	Domain      string            `json:"domain"`
	Kind        string            `json:"kind"`
	Type        string            `json:"type"` // original type: Deployment, aws_security_group, compose.service ...
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Src         Source            `json:"source"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Attrs       map[string]any    `json:"attrs,omitempty"` // free-form, already masked
	Locs        map[string]int    `json:"locs,omitempty"`

	// Generated marks nodes the graph builder synthesised (Internet, hosts,
	// capabilities, implicit ServiceAccounts); they are not part of the input.
	Generated bool `json:"generated,omitempty"`

	Sensitive       bool   `json:"sensitive,omitempty"`
	SensitiveReason string `json:"sensitiveReason,omitempty"`

	// Refs maps an attribute name to the IDs of resources it references
	// (Terraform configuration references). Only resolved references are kept.
	Refs map[string][]string `json:"refs,omitempty"`
	TF   *TFSpec             `json:"tf,omitempty"`

	Workload    *Workload    `json:"workload,omitempty"`
	Rules       []PolicyRule `json:"rules,omitempty"`
	Binding     *BindingSpec `json:"binding,omitempty"`
	NetPol      *NetPolSpec  `json:"netpol,omitempty"`
	Service     *ServiceSpec `json:"service,omitempty"`
	Ingress     *IngressSpec `json:"ingress,omitempty"`
	AutomountSA *bool        `json:"automountSA,omitempty"` // ServiceAccount level setting
}

// TFIngress is one ingress rule of a security group.
type TFIngress struct {
	From     int      `json:"from"`
	To       int      `json:"to"`
	Protocol string   `json:"protocol"`
	CIDRs    []string `json:"cidrs,omitempty"`
}

// TFStatement is one IAM policy statement.
type TFStatement struct {
	Effect    string   `json:"effect"`
	Actions   []string `json:"actions,omitempty"`
	Resources []string `json:"resources,omitempty"`
}

// TFSpec holds Terraform-specific facts used by rules and the graph builder.
type TFSpec struct {
	Ingress            []TFIngress   `json:"ingress,omitempty"`
	PublicIP           *bool         `json:"publicIp,omitempty"`
	HTTPTokens         string        `json:"httpTokens,omitempty"`
	Encrypted          *bool         `json:"encrypted,omitempty"`
	PubliclyAccessible *bool         `json:"publiclyAccessible,omitempty"`
	ACL                string        `json:"acl,omitempty"`
	PublicAccessBlock  *bool         `json:"publicAccessBlock,omitempty"`
	Port               int           `json:"port,omitempty"`
	Statements         []TFStatement `json:"statements,omitempty"`
	ManagedARNs        []string      `json:"managedArns,omitempty"`
	UnknownAttrs       []string      `json:"unknownAttrs,omitempty"`
}

// Annotation returns an annotation value or "".
func (r *Resource) Annotation(key string) string { return r.Annotations[key] }

// Loc returns the line recorded for key, falling back to the resource start.
func (r *Resource) Loc(key string) int {
	if r == nil {
		return 0
	}
	if l, ok := r.Locs[key]; ok && l > 0 {
		return l
	}
	return r.Src.Line
}

// Edge is a directed relationship. Direction follows attacker movement or
// data/permission flow, so path search can walk edges forwards.
type Edge struct {
	ID         string     `json:"id"`
	From       string     `json:"from"`
	To         string     `json:"to"`
	Type       string     `json:"type"`
	Label      string     `json:"label"`
	Confidence Confidence `json:"confidence"`
	Conditions []string   `json:"conditions,omitempty"`
	Evidence   string     `json:"evidence,omitempty"`
	Src        Source     `json:"source"`
	// Attack marks edges that represent attacker movement (as opposed to
	// pure structure such as ingress -> service routing).
	Attack bool `json:"attack,omitempty"`
}

// Severity levels used by rules.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// SeverityRank is used for sorting and --fail-on thresholds.
func SeverityRank(s string) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// Edit is a line-based change used to export patches.
type Edit struct {
	File      string   `json:"file"`
	StartLine int      `json:"startLine"`
	EndLine   int      `json:"endLine"`
	Replace   string   `json:"replace,omitempty"` // replacement text; empty deletes the range
	New       bool     `json:"new,omitempty"`     // the edit creates File
	Old       []string `json:"old,omitempty"`     // original lines (secret-looking values masked)
}

// Fix is a virtual remediation that the what-if simulator can apply.
type Fix struct {
	ID          string         `json:"id"`
	Action      string         `json:"action"`
	Target      string         `json:"target"`
	Description string         `json:"description"`
	Params      map[string]any `json:"params,omitempty"`
	Edits       []Edit         `json:"edits,omitempty"`
	FindingIDs  []string       `json:"findingIds,omitempty"`
}

// Finding is a rule violation anchored to a source location.
type Finding struct {
	ID          string `json:"id"`
	RuleID      string `json:"ruleId"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
	ResourceID  string `json:"resourceId"`
	Src         Source `json:"source"`
	Fix         *Fix   `json:"fix,omitempty"`
}

// Step is one hop of an attack path.
type Step struct {
	From       string     `json:"from"`
	To         string     `json:"to"`
	EdgeID     string     `json:"edgeId"`
	Label      string     `json:"label"`
	Confidence Confidence `json:"confidence"`
	Conditions []string   `json:"conditions,omitempty"`
	Evidence   string     `json:"evidence,omitempty"`
	Src        Source     `json:"source"`
}

// Path is a conditional attack chain from an entry point to a sensitive target.
type Path struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Entry         string     `json:"entry"`
	Target        string     `json:"target"`
	Nodes         []string   `json:"nodes"`
	Steps         []Step     `json:"steps"`
	Confidence    Confidence `json:"confidence"`
	Score         int        `json:"score"`
	Severity      string     `json:"severity"`
	Prerequisites []string   `json:"prerequisites"`
	Explanation   string     `json:"explanation"`
	Signature     string     `json:"signature"`
	FindingIDs    []string   `json:"findingIds,omitempty"`
	// SimilarRoutes is how many other routes with the same first compromised
	// resource, last hop and target were merged into this one (the best supported
	// route represents the group).
	SimilarRoutes int `json:"similarRoutes,omitempty"`
	// Alternatives lists those merged routes, best supported first, when
	// SearchLimits.ShowAlternatives is set. They can rest on different
	// prerequisites even though they start and end in the same place.
	Alternatives []*Path `json:"alternatives,omitempty"`
}

// UnknownNote records a place where the input was insufficient. CloudGraph
// reports these instead of inventing a connection.
type UnknownNote struct {
	ID         string `json:"id"`
	ResourceID string `json:"resourceId"`
	Message    string `json:"message"`
	Src        Source `json:"source"`
}

// SearchLimits bound the attack path search.
type SearchLimits struct {
	// MaxDepth is the longest path, in edges, that is explored.
	MaxDepth int `json:"maxDepth"`
	// MaxCandidates caps the number of raw candidate paths collected.
	MaxCandidates int `json:"maxCandidates"`
	// MaxPivots is the number of network pivots (lateral hops) one path may use.
	MaxPivots int `json:"maxPivots"`
	// ShowAlternatives keeps the routes that are merged into one path because
	// they start and end alike, so an analyst can compare their prerequisites.
	// It changes what is reported, not what is searched.
	ShowAlternatives bool `json:"showAlternatives"`
}

// MaxAlternatives caps the alternatives listed per path.
const MaxAlternatives = 10

// Limits on what callers may request; they keep the search bounded on
// untrusted input.
const (
	MaxDepthLimit      = 20
	MaxCandidatesLimit = 200000
	MaxPivotsLimit     = 3
)

// DefaultSearchLimits are used when nothing else is configured.
func DefaultSearchLimits() SearchLimits {
	return SearchLimits{MaxDepth: 10, MaxCandidates: 20000, MaxPivots: 1}
}

// Validate rejects limits outside the supported ranges.
func (l SearchLimits) Validate() error {
	switch {
	case l.MaxDepth < 1 || l.MaxDepth > MaxDepthLimit:
		return fmt.Errorf("maxDepth must be between 1 and %d", MaxDepthLimit)
	case l.MaxCandidates < 1 || l.MaxCandidates > MaxCandidatesLimit:
		return fmt.Errorf("maxCandidates must be between 1 and %d", MaxCandidatesLimit)
	case l.MaxPivots < 0 || l.MaxPivots > MaxPivotsLimit:
		return fmt.Errorf("maxPivots must be between 0 and %d", MaxPivotsLimit)
	}
	return nil
}

// PathSearch records how the search went, so a report can say when it was cut short.
//
// "Complete" is split in two questions. SearchComplete: did the search run to
// the end, or did a depth or candidate limit stop it? ScopeLimited: were any
// routes left out by a configured limit (depth, candidates or network pivots)?
// A search can be complete and still scope-limited; a client that wants to say
// "no more attack paths exist" must check both.
type PathSearch struct {
	Limits     SearchLimits `json:"limits"`
	Candidates int          `json:"candidates"`
	// DepthLimitHits counts routes that still had unexplored attack edges when
	// they reached MaxDepth.
	DepthLimitHits int `json:"depthLimitHits"`
	// CandidateLimitHit is set when MaxCandidates stopped the search early.
	CandidateLimitHit bool `json:"candidateLimitHit"`
	// PivotLimitHits counts network pivots not taken because of MaxPivots. This
	// is a deliberate scope choice rather than a truncation.
	PivotLimitHits int `json:"pivotLimitHits"`
	// SearchComplete is false when a depth or candidate limit stopped the search.
	SearchComplete bool `json:"searchComplete"`
	// ScopeLimited is true when any limit (depth, candidates or network pivots)
	// excluded routes from the result.
	ScopeLimited bool `json:"scopeLimited"`
	// Complete is the former name of SearchComplete, kept for existing clients.
	// It does not cover MaxPivots; prefer SearchComplete and ScopeLimited.
	Complete bool `json:"complete"`
	// Coverage says what the search could look at.
	Coverage Coverage `json:"coverage"`
	// Notices explains, in plain language, every limit that was reached.
	Notices []string `json:"notices,omitempty"`
}

// Coverage lists the kinds of resources and relationships the search worked
// with, so "no path found" is read against what was actually modelled.
type Coverage struct {
	// ResourceKinds counts the resources in the graph by kind.
	ResourceKinds map[string]int `json:"resourceKinds"`
	// EdgeTypes counts the relationships the search may follow, by type.
	EdgeTypes map[string]int `json:"edgeTypes"`
	// UnknownEdges counts relationships that exist but whose reachability could
	// not be decided; the search never follows them.
	UnknownEdges int `json:"unknownEdges"`
	// UnmodelledTypes counts input resources of types the importer does not
	// model (for Terraform, anything outside docs/terraform-support.md). They
	// are absent from the graph, so no path can run through them.
	UnmodelledTypes map[string]int `json:"unmodelledTypes,omitempty"`
}

// Normalize fills the fields that snapshots saved before they existed lack.
func (s *PathSearch) Normalize() {
	if s.Coverage.ResourceKinds == nil && !s.SearchComplete && s.Complete {
		s.SearchComplete = true
	}
}

// BuildNotices returns human-readable explanations of the limits that were reached.
func (s PathSearch) BuildNotices() []string {
	var out []string
	if s.CandidateLimitHit {
		out = append(out, fmt.Sprintf("Incomplete analysis: the path search stopped after %d candidate paths (limit %d). Some attack paths may be missing; raise --max-paths.",
			s.Candidates, s.Limits.MaxCandidates))
	}
	if s.DepthLimitHits > 0 {
		out = append(out, fmt.Sprintf("Incomplete analysis: %d route(s) reached the depth limit of %d edges and were not followed further. Raise --max-depth to explore them.",
			s.DepthLimitHits, s.Limits.MaxDepth))
	}
	if s.PivotLimitHits > 0 {
		out = append(out, fmt.Sprintf("Limited coverage: %d network pivot(s) beyond the limit of %d per path were not followed, so attack paths that need more pivots are not in this result (chains through ordinary application tiers are not reported). Raise --max-pivots to include them.",
			s.PivotLimitHits, s.Limits.MaxPivots))
	}
	return out
}

// Hotspot is a resource that participates in several attack paths; fixing it
// removes all of them at once.
type Hotspot struct {
	ResourceID string `json:"resourceId"`
	Paths      int    `json:"paths"`
}

// Summary is the dashboard headline.
type Summary struct {
	Resources  int            `json:"resources"`
	Edges      int            `json:"edges"`
	Findings   int            `json:"findings"`
	Paths      int            `json:"paths"`
	Unknowns   int            `json:"unknowns"`
	BySeverity map[string]int `json:"bySeverity"`
}

// Analysis is the full, serialisable result of one scan.
type Analysis struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	CreatedAt string         `json:"createdAt"`
	Inputs    []string       `json:"inputs"`
	Resources []*Resource    `json:"resources"`
	Edges     []*Edge        `json:"edges"`
	Findings  []*Finding     `json:"findings"`
	Paths     []*Path        `json:"paths"`
	Unknowns  []*UnknownNote `json:"unknowns"`
	Fixes     []*Fix         `json:"fixes"`
	Hotspots  []*Hotspot     `json:"hotspots"`
	// PathSearch says which limits applied and whether the search was complete.
	PathSearch PathSearch `json:"pathSearch"`
	Warnings   []string   `json:"warnings,omitempty"`
	// Sources holds the input files line by line with secrets masked, so the
	// UI can show the exact configuration a finding or edge came from.
	Sources map[string][]string `json:"sources,omitempty"`
	Summary Summary             `json:"summary"`
}

// Normalize replaces nil slices with empty ones so JSON clients always get arrays.
func (a *Analysis) Normalize() {
	if a.Resources == nil {
		a.Resources = []*Resource{}
	}
	if a.Edges == nil {
		a.Edges = []*Edge{}
	}
	if a.Findings == nil {
		a.Findings = []*Finding{}
	}
	if a.Paths == nil {
		a.Paths = []*Path{}
	}
	if a.Unknowns == nil {
		a.Unknowns = []*UnknownNote{}
	}
	if a.Fixes == nil {
		a.Fixes = []*Fix{}
	}
	if a.Hotspots == nil {
		a.Hotspots = []*Hotspot{}
	}
	if a.Inputs == nil {
		a.Inputs = []string{}
	}
	for _, p := range a.Paths {
		if p.Prerequisites == nil {
			p.Prerequisites = []string{}
		}
	}
}

// ComputeSummary fills Summary from the other fields.
func (a *Analysis) ComputeSummary() {
	a.Normalize()
	s := Summary{
		Resources:  len(a.Resources),
		Edges:      len(a.Edges),
		Findings:   len(a.Findings),
		Paths:      len(a.Paths),
		Unknowns:   len(a.Unknowns),
		BySeverity: map[string]int{},
	}
	for _, f := range a.Findings {
		s.BySeverity[f.Severity]++
	}
	a.Summary = s
}

// SortFindings orders by severity desc, then rule, then location.
func SortFindings(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := SeverityRank(a.Severity), SeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Src.File != b.Src.File {
			return a.Src.File < b.Src.File
		}
		if a.Src.Line != b.Src.Line {
			return a.Src.Line < b.Src.Line
		}
		return a.ResourceID < b.ResourceID
	})
}
