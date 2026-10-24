package paths

import (
	"testing"

	"github.com/TroubieD3v/cloudgraph/internal/model"
)

func route(confs ...model.Confidence) raw {
	r := raw{nodes: []string{"internet"}}
	for i, c := range confs {
		id := string(rune('a' + i))
		r.nodes = append(r.nodes, id)
		r.edges = append(r.edges, &model.Edge{ID: id, Confidence: c})
	}
	return r
}

func TestConfirmedLongerRouteBeatsShorterConditionalOne(t *testing.T) {
	short := route(model.Inferred, model.Conditional)
	long := route(model.Confirmed, model.Confirmed, model.Confirmed, model.Confirmed)
	if !better(long, short) || better(short, long) {
		t.Error("a fully confirmed route must win over a shorter one that needs an assumption")
	}
}

func TestFewerAssumptionsWinAtEqualWeakestLink(t *testing.T) {
	a := route(model.Confirmed, model.Confirmed, model.Conditional) // one weak step
	b := route(model.Inferred, model.Conditional)                   // two weak steps, shorter
	if !better(a, b) {
		t.Error("with the same weakest link, the route with fewer unconfirmed steps must win")
	}
}

func TestShorterWinsWhenEvidenceIsEqual(t *testing.T) {
	a := route(model.Confirmed, model.Conditional)
	b := route(model.Confirmed, model.Confirmed, model.Conditional)
	if !better(a, b) || better(b, a) {
		t.Error("with equal evidence the shorter route must win")
	}
}

func TestSelectionIsDeterministic(t *testing.T) {
	a := route(model.Confirmed, model.Conditional)
	b := route(model.Confirmed, model.Conditional)
	b.nodes[1] = "z"
	if better(a, b) == better(b, a) {
		t.Error("ties must be broken deterministically")
	}
}
