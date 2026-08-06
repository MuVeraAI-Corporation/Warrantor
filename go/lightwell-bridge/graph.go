package lightwellbridge

import (
	"sort"
)

// AffectedVersionGraph models which deployment versions are patched by which
// bundles. The canonical query is "given a deployed version, which patches
// should be applied?" — answered by PatchesFor.
type AffectedVersionGraph struct {
	// edges maps version -> bundle IDs that apply to it.
	edges map[string]map[string]struct{}
}

// NewAffectedVersionGraph returns an empty graph.
func NewAffectedVersionGraph() *AffectedVersionGraph {
	return &AffectedVersionGraph{edges: make(map[string]map[string]struct{})}
}

// Add records that the named bundle affects the listed versions. Adding the
// same (version, bundle) twice is idempotent.
func (g *AffectedVersionGraph) Add(bundleID string, versions []string) {
	if bundleID == "" {
		return
	}
	for _, v := range versions {
		if v == "" {
			continue
		}
		if g.edges[v] == nil {
			g.edges[v] = make(map[string]struct{})
		}
		g.edges[v][bundleID] = struct{}{}
	}
}

// PatchesFor returns the sorted list of bundle IDs that apply to version v.
func (g *AffectedVersionGraph) PatchesFor(version string) []string {
	set := g.edges[version]
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// AffectedVersions returns the sorted list of versions affected by bundleID.
func (g *AffectedVersionGraph) AffectedVersions(bundleID string) []string {
	out := []string{}
	for v, bundles := range g.edges {
		if _, ok := bundles[bundleID]; ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// AllVersions returns every version the graph knows about, sorted.
func (g *AffectedVersionGraph) AllVersions() []string {
	out := make([]string, 0, len(g.edges))
	for v := range g.edges {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
