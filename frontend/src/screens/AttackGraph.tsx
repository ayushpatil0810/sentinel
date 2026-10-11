import { useEffect, useRef, useState, useCallback } from "react"
import cytoscape, { type Core } from "cytoscape"
import { api } from "../api/client"
import type {
  GraphResponse,
  GraphRoutesResponse,
  GraphRoute,
  RemediationsResponse,
  RemediationSuggestion,
  RemediationPreviewResponse,
  GraphDiff,
  BlastRadius,
} from "../api/types"
import {
  field,
  PageHeader,
  ErrorBanner,
  Skeleton,
  EmptyState,
  JsonView,
  button,
} from "../components/ui"
import { useApp } from "../state/AppContext"

const SENSITIVITY_COLORS: Record<string, string> = {
  critical: "#da3633",
  high: "#f85149",
  medium: "#d29922",
  low: "#58a6ff",
  none: "#30363d",
}

const NODE_SHAPES: Record<string, string> = {
  user: "ellipse",
  role: "round-rectangle",
  service: "round-rectangle",
  agent: "hexagon",
  tool: "diamond",
  asset: "barrel",
  external: "round-rectangle",
}

export default function AttackGraph() {
  const { user, notify, reportError } = useApp()
  const isAdmin = user?.roles.includes("admin")

  const cyContainerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)

  // State
  const [graphData, setGraphData] = useState<GraphResponse | null>(null)
  const [routesData, setRoutesData] = useState<GraphRoutesResponse | null>(null)
  const [remediations, setRemediations] = useState<RemediationsResponse | null>(null)
  const [maxDepth, setMaxDepth] = useState<number>(4)
  const [selectedRouteId, setSelectedRouteId] = useState<string | null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [blastInfo, setBlastInfo] = useState<BlastRadius | null>(null)
  const [preview, setPreview] = useState<{
    edgeId: string
    data: RemediationPreviewResponse
  } | null>(null)
  const [diff, setDiff] = useState<GraphDiff | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  // Upload dialog state
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [uploadText, setUploadText] = useState("")
  const [validateOnly, setValidateOnly] = useState(false)
  const [uploadResult, setUploadResult] = useState<{
    valid?: boolean
    errors?: unknown[]
    warnings?: string[]
  } | null>(null)

  // Load graph, routes, remediations
  const loadGraph = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [g, r, rem] = await Promise.all([
        api.graph(),
        api.routes(maxDepth),
        api.remediations(),
      ])
      setGraphData(g)
      setRoutesData(r)
      setRemediations(rem)
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  }, [maxDepth])

  useEffect(() => {
    void loadGraph()
  }, [loadGraph])

  // Look up blast radius on node click
  useEffect(() => {
    if (!selectedNodeId) {
      setBlastInfo(null)
      return
    }
    api
      .blastRadius(selectedNodeId)
      .then(setBlastInfo)
      .catch(() => setBlastInfo(null))
  }, [selectedNodeId])

  // Initialize or update Cytoscape canvas
  useEffect(() => {
    if (!cyContainerRef.current || !graphData) return

    const nodes = (graphData.nodes || []).map((n) => {
      const isEntry = Boolean(n.entry_point)
      const isDerived = n.entry_source === "derived"
      const shape = NODE_SHAPES[n.type] || "round-rectangle"
      const bgColor =
        (n.sensitivity ? SENSITIVITY_COLORS[n.sensitivity] : undefined) ||
        "#21262d"

      return {
        data: {
          id: n.id,
          label: n.name || n.id,
          type: n.type,
          sensitivity: n.sensitivity,
          isEntry,
          isDerived,
          shape,
          bgColor,
        },
      }
    })

    const edges = (graphData.edges || []).map((e) => {
      const isReversed = e.type === "ingests_from" || e.type === "trusts"
      return {
        data: {
          id: e.id,
          source: isReversed ? e.dst : e.src,
          target: isReversed ? e.src : e.dst,
          originalSrc: e.src,
          originalDst: e.dst,
          type: e.type,
          isReversed,
        },
      }
    })

    const cy = cytoscape({
      container: cyContainerRef.current,
      elements: [...nodes, ...edges],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: "#e6edf3",
            "font-size": "11px",
            "font-family": "monospace",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "background-color": "data(bgColor)",
            shape: "data(shape)" as cytoscape.Css.NodeShape,
            width: "36px",
            height: "36px",
            "border-width": 1.5,
            "border-color": "#484f58",
            "transition-property": "opacity, border-color, border-width, background-color",
            "transition-duration": 0.2,
          },
        },
        {
          selector: "node[?isEntry]",
          style: {
            "border-width": 3,
            "border-color": "#3fb950",
            "border-style": "solid",
          },
        },
        {
          selector: "node[?isDerived]",
          style: {
            "border-width": 3,
            "border-color": "#58a6ff",
            "border-style": "dashed",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#484f58",
            "target-arrow-color": "#484f58",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "arrow-scale": 0.8,
            "transition-property": "opacity, line-color, width, target-arrow-color",
            "transition-duration": 0.2,
          },
        },
        {
          selector: "edge[?isReversed]",
          style: {
            "line-style": "dashed",
            "line-color": "#6e7681",
          },
        },
        // Route highlighting styles
        {
          selector: "node.route-highlight",
          style: {
            "border-color": "#bc8cff",
            "border-width": 3,
            opacity: 1,
          },
        },
        {
          selector: "edge.route-highlight",
          style: {
            "line-color": "#bc8cff",
            "target-arrow-color": "#bc8cff",
            width: 3,
            opacity: 1,
          },
        },
        {
          selector: ".dimmed",
          style: {
            opacity: 0.15,
          },
        },
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 30,
        roots: nodes
          .filter((n) => n.data.isEntry)
          .map((n) => `#${n.data.id.replace(/:/g, "\\:")}`),
      },
    })

    cy.on("tap", "node", (evt) => {
      const n = evt.target
      setSelectedNodeId(n.id())
    })

    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        setSelectedNodeId(null)
      }
    })

    cyRef.current = cy

    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [graphData])

  // Highlight route when selectedRouteId changes
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !routesData) return

    cy.elements().removeClass("route-highlight dimmed")

    if (!selectedRouteId) {
      return
    }

    const route = routesData.routes.find((r) => r.path_id === selectedRouteId)
    if (!route) return

    const nodeIds = new Set<string>()
    const edgeIds = new Set<string>()

    nodeIds.add(route.entry)
    nodeIds.add(route.asset)

    for (const step of route.steps || []) {
      if (step.edge_id) edgeIds.add(step.edge_id)
      if (step.from) nodeIds.add(step.from)
      if (step.to) nodeIds.add(step.to)
    }

    cy.elements().addClass("dimmed")

    nodeIds.forEach((id) => {
      const el = cy.getElementById(id)
      if (el) {
        el.removeClass("dimmed")
        el.addClass("route-highlight")
      }
    })

    edgeIds.forEach((id) => {
      const el = cy.getElementById(id)
      if (el) {
        el.removeClass("dimmed")
        el.addClass("route-highlight")
      }
    })
  }, [selectedRouteId, routesData])

  // Remediations handlers
  const handlePreview = async (suggestion: RemediationSuggestion) => {
    try {
      const p = await api.previewRemediation(suggestion.edge_id)
      setPreview({ edgeId: suggestion.edge_id, data: p })
    } catch (err) {
      reportError(err)
    }
  }

  const handleApply = async (edgeId: string) => {
    if (!graphData || !isAdmin) return
    const confirmed = window.confirm(
      `Apply remediation to remove edge "${edgeId}"? This will modify the graph model and record an audit ledger entry.`,
    )
    if (!confirmed) return

    setBusy(true)
    try {
      const res = await api.applyRemediation(edgeId, graphData.graph_version)
      setDiff(res.diff)
      notify(`Applied remediation on edge ${edgeId}. Graph updated to v${res.graph_version}.`)
      setPreview(null)
      setSelectedRouteId(null)
      await loadGraph()
    } catch (err) {
      reportError(err)
    } finally {
      setBusy(false)
    }
  }

  const handleDeriveEntryPoints = async () => {
    setBusy(true)
    try {
      const res = await api.deriveEntryPoints()
      notify(
        res.changed
          ? `Derived entry points updated (Graph v${res.graph_version}).`
          : "Entry points already up to date.",
      )
      await loadGraph()
    } catch (err) {
      reportError(err)
    } finally {
      setBusy(false)
    }
  }

  const handleDownloadModel = () => {
    if (!graphData) return
    const blob = new Blob([JSON.stringify(graphData, null, 2)], {
      type: "application/json",
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `sentinel-graph-v${graphData.graph_version}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    let parsed: unknown
    try {
      parsed = JSON.parse(uploadText)
    } catch {
      setUploadResult({
        valid: false,
        errors: [{ message: "Invalid JSON format." }],
      })
      return
    }

    setBusy(true)
    try {
      if (validateOnly) {
        const res = await api.validateGraph(parsed)
        setUploadResult(res)
      } else {
        const res = await api.uploadGraph(parsed, "json")
        notify(`Graph v${res.graph_version} uploaded successfully.`)
        setShowUploadModal(false)
        setUploadText("")
        setUploadResult(null)
        await loadGraph()
      }
    } catch (err) {
      reportError(err)
    } finally {
      setBusy(false)
    }
  }

  const activeRoute = selectedRouteId
    ? routesData?.routes.find((r) => r.path_id === selectedRouteId)
    : null

  return (
    <div className="flex h-full flex-col space-y-4 p-5 lg:p-6">
      <PageHeader
        title="Attack Graph"
        lead="BreachPath explores reachability and suggests remediations."
        right={
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-dim">
              v{graphData?.graph_version ?? 1} · {graphData?.nodes.length ?? 0} nodes ·{" "}
              {graphData?.edges.length ?? 0} edges
            </span>

            {/* Depth selector */}
            <div className="flex items-center gap-1.5 rounded-sm border border-line bg-panel px-2.5 py-1 text-xs">
              <span className="text-dim">Max depth:</span>
              <select
                aria-label="Max depth"
                value={maxDepth}
                onChange={(e) => setMaxDepth(Number(e.target.value))}
                className="bg-transparent font-mono font-bold text-fg outline-none"
              >
                {[1, 2, 3, 4, 5, 6, 7, 8].map((d) => (
                  <option key={d} value={d} className="bg-panel text-fg">
                    {d}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={() => void handleDeriveEntryPoints()}
              disabled={busy}
              className={button("ghost", "sm")}
              title="Derive entry points from action registries (X-03)"
            >
              Derive entries
            </button>

            {isAdmin && (
              <button
                onClick={() => {
                  setUploadText("")
                  setUploadResult(null)
                  setShowUploadModal(true)
                }}
                className={button("ghost", "sm")}
              >
                Upload model
              </button>
            )}

            <button
              onClick={handleDownloadModel}
              disabled={!graphData}
              className={button("ghost", "sm")}
            >
              Export JSON
            </button>

            <button
              onClick={() => cyRef.current?.fit(undefined, 30)}
              className={button("ghost", "sm")}
              title="Fit canvas to view"
            >
              Fit
            </button>
          </div>
        }
      />

      {error != null && <ErrorBanner error={error} onRetry={() => void loadGraph()} />}
      {loading && !graphData && <Skeleton rows={10} />}

      {/* Main Graph Grid */}
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[18rem_minmax(0,1fr)_20rem]">
        {/* Left Panel: Attack Routes */}
        <section
          aria-label="Attack routes"
          className="flex min-h-0 flex-col rounded-sm border border-line bg-panel overflow-hidden"
        >
          <header className="border-b border-line px-4 py-2.5">
            <h2 className="eyebrow !text-dim">
              Attack Routes ({routesData?.routes.length ?? 0})
            </h2>
            {routesData?.truncated && (
              <p className="mt-1 rounded border border-hold/60 bg-hold/10 px-2 py-0.5 font-mono text-[11px] text-hold">
                Truncated: cap reached at depth {maxDepth}
              </p>
            )}
          </header>

          <div className="flex-1 space-y-2 overflow-y-auto p-3">
            {routesData && routesData.routes.length === 0 && (
              <EmptyState
                title="No attack routes"
                hint={`No routes reach sensitive assets within depth ${maxDepth}.`}
              />
            )}

            {(routesData?.routes || []).map((r) => {
              const isSelected = selectedRouteId === r.path_id
              return (
                <div
                  key={r.path_id}
                  onClick={() =>
                    setSelectedRouteId(isSelected ? null : r.path_id)
                  }
                  tabIndex={0}
                  onKeyDown={(e) =>
                    e.key === "Enter" &&
                    setSelectedRouteId(isSelected ? null : r.path_id)
                  }
                  className={`cursor-pointer rounded-xs border p-2.5 transition-colors ${
                    isSelected
                      ? "border-path-llm bg-path-llm/10 shadow-sm"
                      : "border-line hover:border-line-strong hover:bg-raised/40"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-fg">
                      {r.path_id}
                    </span>
                    <span className="font-mono text-dim">
                      {r.length} {r.length === 1 ? "step" : "steps"}
                    </span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-xs text-dim">
                    {r.summary || `${r.entry} → ${r.asset}`}
                  </p>
                </div>
              )
            })}
          </div>

          {/* Route step explanation when a route is selected */}
          {activeRoute && (
            <div className="border-t border-line bg-ink/40 p-3 max-h-48 overflow-y-auto">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-path-llm">
                  Route {activeRoute.path_id} Details
                </span>
                <button
                  onClick={() => setSelectedRouteId(null)}
                  className="text-xs text-dim hover:text-fg"
                >
                  ✕
                </button>
              </div>
              <p className="mt-1 text-xs text-dim leading-snug">
                {activeRoute.summary}
              </p>
              <ol className="mt-2 space-y-1.5 border-t border-line/60 pt-2 text-[11px]">
                {(activeRoute.steps || []).map((step, idx) => (
                  <li key={idx} className="font-mono text-dim">
                    <span className="font-bold text-fg">{idx + 1}.</span>{" "}
                    {step.text || `${step.from} -> ${step.to}`}
                  </li>
                ))}
              </ol>
            </div>
          )}
        </section>

        {/* Center: Cytoscape Canvas */}
        <section
          aria-label="Graph canvas"
          className="relative min-h-[28rem] rounded-sm border border-line bg-panel overflow-hidden"
        >
          <div
            ref={cyContainerRef}
            className="h-full w-full"
            style={{ minHeight: "400px" }}
          />

          {/* Canvas overlay: Legend */}
          <div className="pointer-events-none absolute bottom-3 left-3 flex flex-wrap gap-2 rounded-xs border border-line bg-ink/90 p-2 text-[11px] backdrop-blur-xs">
            <span className="flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-full border border-[#3fb950] bg-transparent" />
              Entry point
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-full border border-dashed border-[#58a6ff] bg-transparent" />
              Derived entry
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-sm bg-[#da3633]" />
              Sensitive asset
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2.5 w-2.5 border-b border-dashed border-dim" />
              Reversed edge
            </span>
          </div>

          {/* Node detail card if a node is tapped */}
          {selectedNodeId && (
            <div className="absolute right-3 top-3 w-64 rounded-sm border border-line bg-panel/95 p-3 shadow-xl backdrop-blur-xs">
              <div className="flex items-start justify-between">
                <div>
                  <span className="eyebrow block">Node</span>
                  <span className="font-mono text-xs font-bold text-fg">
                    {selectedNodeId}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNodeId(null)}
                  className="text-xs text-dim hover:text-fg"
                >
                  ✕
                </button>
              </div>

              {blastInfo && (
                <div className="mt-2.5 space-y-1.5 border-t border-line pt-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-dim">Blast Level:</span>
                    <span
                      className={`font-mono font-bold uppercase ${
                        blastInfo.level === "high"
                          ? "text-block"
                          : blastInfo.level === "medium"
                            ? "text-hold"
                            : "text-allow"
                      }`}
                    >
                      {blastInfo.level}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dim">On Attack Path:</span>
                    <span className="font-mono">
                      {blastInfo.on_attack_path ? "Yes" : "No"}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dim">Paths Count:</span>
                    <span className="font-mono">{blastInfo.paths_count}</span>
                  </div>
                  {blastInfo.reason && (
                    <p className="text-[11px] text-dim">{blastInfo.reason}</p>
                  )}
                </div>
              )}
            </div>
          )}
        </section>

        {/* Right Panel: Remediation Suggestions */}
        <section
          aria-label="Remediations"
          className="flex min-h-0 flex-col rounded-sm border border-line bg-panel overflow-hidden"
        >
          <header className="border-b border-line px-4 py-2.5">
            <h2 className="eyebrow !text-dim">
              Remediations ({remediations?.suggestions.length ?? 0})
            </h2>
          </header>

          <div className="flex-1 space-y-3 overflow-y-auto p-3">
            {remediations && remediations.suggestions.length === 0 && (
              <EmptyState
                title="No remediations"
                hint="No candidate edge removals needed for this graph."
              />
            )}

            {(remediations?.suggestions || []).map((s) => {
              const isPreviewed = preview?.edgeId === s.edge_id
              return (
                <div
                  key={s.edge_id}
                  className={`space-y-2 rounded-xs border p-3 ${
                    isPreviewed ? "border-allow bg-allow/5" : "border-line"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-fg">
                      {s.edge_id}
                    </span>
                    <span className="rounded bg-block/15 px-1.5 py-0.5 font-mono text-[11px] font-bold text-block">
                      Breaks {s.breaks}
                    </span>
                  </div>
                  <p className="text-xs text-dim leading-snug">{s.rationale}</p>

                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={() => void handlePreview(s)}
                      className={button("ghost", "sm") + " flex-1"}
                    >
                      {isPreviewed ? "Previewing" : "Preview"}
                    </button>
                    {isAdmin && (
                      <button
                        onClick={() => void handleApply(s.edge_id)}
                        disabled={busy}
                        className={button("danger", "sm") + " flex-1"}
                        title="Admin only: commits graph modification"
                      >
                        Apply
                      </button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Remediation Preview Box */}
          {preview && (
            <div className="border-t border-line bg-ink/50 p-3 text-xs">
              <div className="flex items-center justify-between font-mono font-bold">
                <span className="text-allow">Preview: {preview.edgeId}</span>
                <button
                  onClick={() => setPreview(null)}
                  className="text-dim hover:text-fg"
                >
                  ✕
                </button>
              </div>
              <div className="mt-2 space-y-1 font-mono text-[11px]">
                <p className="text-block">
                  - Removed routes: {preview.data.removed.length}
                </p>
                <p className="text-dim">
                  = Remaining routes: {preview.data.remaining.length}
                </p>
                {preview.data.new.length > 0 && (
                  <p className="text-hold">
                    + New routes: {preview.data.new.length}
                  </p>
                )}
              </div>
            </div>
          )}
        </section>
      </div>

      {/* Bottom Panel: Diff Panel after change */}
      {diff && (
        <section
          aria-label="Graph diff"
          className="rounded-sm border border-line bg-panel p-4"
        >
          <div className="flex items-center justify-between border-b border-line pb-2">
            <h3 className="font-mono text-xs font-bold text-fg">
              Graph Diff: v{diff.from_version} → v{diff.to_version}
            </h3>
            <button
              onClick={() => setDiff(null)}
              className="text-xs text-dim hover:text-fg"
            >
              Dismiss
            </button>
          </div>

          <div className="mt-3 grid grid-cols-1 gap-4 md:grid-cols-3">
            <div className="rounded border border-block/40 bg-block/5 p-3">
              <h4 className="font-mono text-xs font-bold text-block">
                Removed Routes ({diff.removed.length})
              </h4>
              <ul className="mt-2 max-h-32 space-y-1 overflow-y-auto font-mono text-[11px] text-dim">
                {diff.removed.map((pid) => (
                  <li key={pid}>- {pid}</li>
                ))}
              </ul>
            </div>

            <div className="rounded border border-line bg-panel p-3">
              <h4 className="font-mono text-xs font-bold text-dim">
                Remaining Routes ({diff.remaining.length})
              </h4>
              <ul className="mt-2 max-h-32 space-y-1 overflow-y-auto font-mono text-[11px] text-dim">
                {diff.remaining.map((pid) => (
                  <li key={pid}>= {pid}</li>
                ))}
              </ul>
            </div>

            <div className="rounded border border-hold/40 bg-hold/5 p-3">
              <h4 className="font-mono text-xs font-bold text-hold">
                New Routes ({diff.new.length})
              </h4>
              <ul className="mt-2 max-h-32 space-y-1 overflow-y-auto font-mono text-[11px] text-dim">
                {diff.new.length === 0 ? (
                  <li className="text-faint">None</li>
                ) : (
                  diff.new.map((pid) => <li key={pid}>+ {pid}</li>)
                )}
              </ul>
            </div>
          </div>
        </section>
      )}

      {/* Upload Model Modal */}
      {showUploadModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs"
        >
          <div className="w-full max-w-xl rounded-sm border border-line bg-panel p-6 shadow-2xl">
            <h2 className="text-base font-bold text-fg">
              Upload Graph Model (Admin)
            </h2>
            <p className="mt-1 text-xs text-dim">
              Upload a complete graph JSON model. Use &quot;Validate only&quot; for a dry-run check without updating the active graph.
            </p>

            {uploadResult && (
              <div
                className={`mt-3 rounded border p-3 text-xs ${
                  uploadResult.valid
                    ? "border-allow bg-allow/10 text-allow"
                    : "border-block bg-block/10 text-block"
                }`}
              >
                <p className="font-bold">
                  {uploadResult.valid
                    ? "Model is valid!"
                    : "Validation rejected:"}
                </p>
                {uploadResult.errors && (
                  <div className="mt-1 max-h-32 overflow-y-auto">
                    <JsonView value={uploadResult.errors} />
                  </div>
                )}
              </div>
            )}

            <form onSubmit={handleUploadSubmit} className="mt-4 space-y-3">
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-dim">
                  Graph JSON Model
                </span>
                <textarea
                  rows={10}
                  value={uploadText}
                  onChange={(e) => setUploadText(e.target.value)}
                  placeholder="Paste { nodes: [...], edges: [...] } JSON"
                  className={`w-full font-mono text-xs leading-relaxed ${field} h-auto p-3`}
                  required
                />
              </label>

              <label className="flex items-center gap-2 text-xs text-dim">
                <input
                  type="checkbox"
                  checked={validateOnly}
                  onChange={(e) => setValidateOnly(e.target.checked)}
                />
                Validate only (dry run, do not update model)
              </label>

              <div className="mt-4 flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className={button("ghost")}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busy || !uploadText.trim()}
                  className={button("primary")}
                >
                  {validateOnly ? "Validate Model" : "Upload & Save"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
