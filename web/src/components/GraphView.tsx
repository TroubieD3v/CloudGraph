import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  useReactFlow,
  type Edge as RFEdge,
  type Node as RFNode,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Box, BrickWall, Crosshair, Database, DoorOpen, Globe, KeyRound, Link2, Lock, Network, Route, ScrollText, Server, Shield, User, type LucideIcon } from "lucide-react";
import dagre from "@dagrejs/dagre";
import type { Analysis, Edge, Finding, Resource, Severity, Source } from "../types";
import type { Theme } from "../theme";
import { Badge, Conf, SEVERITIES, SourceLink, nameMap } from "./common";

interface NodeData extends Record<string, unknown> {
  res: Resource;
  worst?: Severity;
  dim: boolean;
}

// Nodes are drawn as a 44 px disc with the label underneath; the layout reserves room for the label.
const D = 44;
const LAYOUT_W = 150;
const LAYOUT_H = 78;

const KIND_ICON: Record<string, LucideIcon> = {
  Internet: Globe, Ingress: DoorOpen, Service: Network, Firewall: BrickWall, Workload: Box, Instance: Server,
  ServiceAccount: KeyRound, Identity: User, Binding: Link2, Role: Shield, Policy: ScrollText,
  Capability: Crosshair, Host: Server, Secret: Lock, Database: Database,
};

function CgNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  const { res, worst, dim } = data;
  const cls = ["rf-node", `k-${res.kind}`, res.sensitive ? "sensitive" : "", res.kind === "Internet" ? "internet" : "", dim ? "dim" : "", selected ? "selected" : ""]
    .filter(Boolean)
    .join(" ");
  const Icon = KIND_ICON[res.kind] ?? (res.sensitive ? Crosshair : Box);
  return (
    <div className={cls} data-testid={`node-${res.id}`} title={res.sensitiveReason ?? res.id}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div className="disc"><Icon /></div>
      {worst && <span className={`sev ${worst}`} title={worst} />}
      <div className="label">
        <span className="name">{res.name}</span>
        <span className="kind">{res.generated && res.kind === "Capability" ? "Sensitive target" : res.type}</span>
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { cg: CgNode };

// SVG markers cannot read CSS variables, so edge colours come from the theme here.
const COLORS: Record<Theme, Record<string, string>> = {
  dark: { hot: "#d98577", attack: "#d0a866", structure: "#4a5058", grid: "#2a2e34", minimapBg: "#1f2226", minimapDim: "#2b2f35", minimapNode: "#6b7178", minimapMask: "rgba(25,27,30,.6)" },
  light: { hot: "#a8402f", attack: "#87601a", structure: "#a3aab2", grid: "#d5dade", minimapBg: "#f8f9fa", minimapDim: "#dce0e4", minimapNode: "#858c94", minimapMask: "rgba(238,240,242,.6)" },
};

function layout(nodes: RFNode<NodeData>[], edges: RFEdge[]): RFNode<NodeData>[] {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 10, ranksep: 70, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: LAYOUT_W, height: LAYOUT_H }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    // the disc sits in the upper part of the reserved box, the label hangs below it
    return { ...n, position: { x: p.x - D / 2, y: p.y - LAYOUT_H / 2 } };
  });
}

const dash: Record<string, string | undefined> = { confirmed: undefined, inferred: "7 4", conditional: "2 5", unknown: "2 2" };

type Selection = { kind: "node"; id: string } | { kind: "edge"; id: string } | null;

export function GraphView({
  a,
  pathId,
  setPathId,
  onOpen,
  theme,
}: {
  a: Analysis;
  pathId: string;
  setPathId: (id: string) => void;
  onOpen: (s: Source) => void;
  theme: Theme;
}) {
  const C = COLORS[theme];
  const [mode, setMode] = useState<"attack" | "all">("attack");
  const [sel, setSel] = useState<Selection>(null);
  const names = useMemo(() => nameMap(a), [a]);
  const path = a.paths.find((p) => p.id === pathId);

  const findingsBy = useMemo(() => {
    const m = new Map<string, Finding[]>();
    a.findings.forEach((f) => m.set(f.resourceId, [...(m.get(f.resourceId) ?? []), f]));
    return m;
  }, [a]);

  const { nodes, edges } = useMemo(() => {
    const ids = new Set<string>();
    if (mode === "all") a.resources.forEach((r) => ids.add(r.id));
    a.paths.forEach((p) => p.nodes.forEach((n) => ids.add(n)));
    const visibleEdges: Edge[] = a.edges.filter((e) => (mode === "all" ? true : e.attack && ids.has(e.from) && ids.has(e.to)));
    const pathNodes = new Set(path?.nodes ?? []);
    const pathEdges = new Set(path?.steps.map((s) => s.edgeId) ?? []);

    const rfEdges: RFEdge[] = visibleEdges
      .filter((e) => ids.has(e.from) && ids.has(e.to))
      .map((e) => {
        const onPath = pathEdges.has(e.id);
        const dimmed = !!path && !onPath;
        const color = onPath ? C.hot : e.attack ? C.attack : C.structure;
        return {
          id: e.id,
          source: e.from,
          target: e.to,
          type: "default",
          animated: onPath,
          // relationship names on the highlighted path, as in attack-graph tools
          label: onPath ? e.type.replace(/_/g, " ") : undefined,
          labelBgPadding: [4, 2] as [number, number],
          markerEnd: { type: MarkerType.ArrowClosed, color },
          style: { stroke: color, strokeWidth: onPath ? 2.2 : 1.3, strokeDasharray: dash[e.confidence], opacity: dimmed ? 0.12 : 1 },
          data: { confidence: e.confidence },
        };
      });

    const sevRank = (s: Severity) => SEVERITIES.indexOf(s);
    const rfNodes: RFNode<NodeData>[] = [...ids]
      .filter((id) => names.has(id))
      .map((id) => {
        const fs = findingsBy.get(id) ?? [];
        const worst = fs.map((f) => f.severity).sort((x, y) => sevRank(x) - sevRank(y))[0];
        return {
          id,
          type: "cg",
          position: { x: 0, y: 0 },
          width: D,
          height: D,
          data: { res: names.get(id)!, worst, dim: !!path && !pathNodes.has(id) },
        };
      });
    return { nodes: layout(rfNodes, rfEdges), edges: rfEdges };
  }, [a, mode, path, names, findingsBy, C]);

  const selectedNode = sel?.kind === "node" ? names.get(sel.id) : undefined;
  const selectedEdge = sel?.kind === "edge" ? a.edges.find((e) => e.id === sel.id) : undefined;

  return (
    <>
      <div className="graph-wrap" data-testid="graph">
        <div className="graph-tools">
          <div className="gt-head"><Route /> Pathfinding</div>
          <label>
            View{" "}
            <select value={mode} onChange={(e) => setMode(e.target.value as "attack" | "all")} aria-label="Graph view">
              <option value="attack">Attack-relevant</option>
              <option value="all">All resources</option>
            </select>
          </label>
          <label>
            Path{" "}
            <select value={pathId} onChange={(e) => setPathId(e.target.value)} aria-label="Highlight path">
              <option value="">— none —</option>
              {a.paths.map((p) => (
                <option key={p.id} value={p.id}>
                  [{p.severity}] {p.title}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="legend">
          <span>
            <i /> attack step, confirmed
          </span>
          <span>
            <i className="inf" /> inferred (selector / network)
          </span>
          <span>
            <i className="con" /> conditional (needs compromise)
          </span>
          <span>
            <i className="str" /> structure only
          </span>
          <span>
            <i className="hot" /> highlighted path
          </span>
        </div>
        <ReactFlow
          nodes={nodes.map((n) => ({ ...n, selected: sel?.kind === "node" && sel.id === n.id }))}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.1}
          nodesConnectable={false}
          onNodeClick={(_, n) => setSel({ kind: "node", id: n.id })}
          onEdgeClick={(_, e) => setSel({ kind: "edge", id: e.id })}
          onPaneClick={() => setSel(null)}
          proOptions={{ hideAttribution: true }}
          colorMode={theme}
        >
          <Background gap={24} size={1.4} color={C.grid} />
          <Controls showInteractive={false} />
          <MiniMap
            pannable
            zoomable
            bgColor={C.minimapBg}
            nodeColor={(n) => ((n.data as NodeData).res.sensitive ? C.hot : (n.data as NodeData).dim ? C.minimapDim : C.minimapNode)}
            maskColor={C.minimapMask}
          />
          <FitOnChange nodeIds={path?.nodes} trigger={`${pathId}|${mode}|${sel ? "open" : "closed"}`} />
        </ReactFlow>
      </div>
      {(selectedNode || selectedEdge) && (
        <aside className="inspector" data-testid="inspector">
          {selectedNode && <NodeInspector a={a} res={selectedNode} findings={findingsBy.get(selectedNode.id) ?? []} names={names} onOpen={onOpen} />}
          {selectedEdge && <EdgeInspector e={selectedEdge} names={names} onOpen={onOpen} />}
        </aside>
      )}
    </>
  );
}

// Re-frames the canvas when the highlighted path, the view or the inspector changes.
function FitOnChange({ nodeIds, trigger }: { nodeIds?: string[]; trigger: string }) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    const t = setTimeout(() => {
      void fitView({ padding: 0.12, duration: 300, maxZoom: 1.2, nodes: nodeIds?.map((id) => ({ id })) });
    }, 30);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trigger]);
  return null;
}

function EdgeBlock({ e, names, onOpen, dir }: { e: Edge; names: Map<string, Resource>; onOpen: (s: Source) => void; dir: "in" | "out" }) {
  const other = names.get(dir === "out" ? e.to : e.from);
  return (
    <div className="edge-item">
      <div>
        {dir === "out" ? "→" : "←"} <b>{other?.name ?? (dir === "out" ? e.to : e.from)}</b> <Conf c={e.confidence} />
      </div>
      <div className="note">{e.label}</div>
      {e.evidence && <div className="note">Evidence: {e.evidence}</div>}
      {e.conditions && e.conditions.length > 0 && (
        <ul>
          {e.conditions.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      )}
      <SourceLink src={e.source} onOpen={onOpen} />
    </div>
  );
}

function NodeInspector({ a, res, findings, names, onOpen }: { a: Analysis; res: Resource; findings: Finding[]; names: Map<string, Resource>; onOpen: (s: Source) => void }) {
  const out = a.edges.filter((e) => e.from === res.id);
  const inn = a.edges.filter((e) => e.to === res.id);
  return (
    <div>
      <h3>{res.name}</h3>
      <div className="note">{res.type}</div>
      <dl>
        <dt>Kind</dt>
        <dd>{res.kind}</dd>
        {res.namespace && (
          <>
            <dt>Namespace</dt>
            <dd>{res.namespace}</dd>
          </>
        )}
        <dt>Source</dt>
        <dd>{res.source.file ? <SourceLink src={res.source} onOpen={onOpen} /> : <span className="note">synthesised by CloudGraph</span>}</dd>
        {res.sensitive && (
          <>
            <dt>Sensitive</dt>
            <dd>{res.sensitiveReason}</dd>
          </>
        )}
      </dl>
      {findings.length > 0 && (
        <>
          <span className="overline">Findings</span>
          {findings.map((f) => (
            <div key={f.id} className="edge-item">
              <Badge sev={f.severity} /> <span className="mono">{f.ruleId}</span>
              <div className="note">{f.message}</div>
              <SourceLink src={f.source} onOpen={onOpen} />
            </div>
          ))}
        </>
      )}
      {inn.length > 0 && <span className="overline">Incoming</span>}
      {inn.map((e) => (
        <EdgeBlock key={e.id} e={e} names={names} onOpen={onOpen} dir="in" />
      ))}
      {out.length > 0 && <span className="overline">Outgoing</span>}
      {out.map((e) => (
        <EdgeBlock key={e.id} e={e} names={names} onOpen={onOpen} dir="out" />
      ))}
    </div>
  );
}

function EdgeInspector({ e, names, onOpen }: { e: Edge; names: Map<string, Resource>; onOpen: (s: Source) => void }) {
  return (
    <div>
      <h3>{e.type.replace(/_/g, " ")}</h3>
      <div className="note">
        {names.get(e.from)?.name ?? e.from} → {names.get(e.to)?.name ?? e.to}
      </div>
      <p>{e.label}</p>
      <Conf c={e.confidence} />
      {e.evidence && <p className="note">Evidence: {e.evidence}</p>}
      {e.conditions && e.conditions.length > 0 && (
        <div className="prereq">
          <b>Conditions</b>
          <ul>
            {e.conditions.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      )}
      <p>
        <SourceLink src={e.source} onOpen={onOpen} />
      </p>
    </div>
  );
}
