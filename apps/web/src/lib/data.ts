"use client";

// Data access with two interchangeable backends:
//  - static (default): JSON exported by scripts/export_demo.py into public/threatgraph-data/
//  - live API: set NEXT_PUBLIC_TG_API_BASE=http://localhost:8000/api/v1
// Both return the same v1 payloads (verified by tests/integration/test_end_to_end.py).

import { useEffect, useState } from "react";
import type {
  Benchmarks,
  EntityDetail,
  EvalSplit,
  Explanation,
  ExplanationBundle,
  GraphWindow,
  GraphWindowIndex,
  Incident,
  IncidentIndex,
  Metadata,
  ModelList,
  ModelMetrics,
  ScoreTable,
  Summary,
} from "./types";

export const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
const API_BASE = process.env.NEXT_PUBLIC_TG_API_BASE ?? "";
const DATASET = process.env.NEXT_PUBLIC_TG_DATASET ?? "demo";
const STATIC_BASE = `${BASE_PATH}/threatgraph-data/${DATASET}/v1`;

export const dataSourceLabel = API_BASE ? "Live API" : "Static export";
export const isLiveApi = Boolean(API_BASE);
/** Plain files (CSV/Markdown) written by the exporter; they have no API equivalent. */
export const downloadUrl = (rel: string) => `${STATIC_BASE}/downloads/${rel}`;

/** Static file name for an id: same rule as threatgraph.serving.export.static_slug. */
export function staticSlug(id: string): string {
  return id.replace(/[^A-Za-z0-9._-]/g, "_");
}

class NotFound extends Error {}

const cache = new Map<string, Promise<unknown>>();

async function getJson<T>(url: string): Promise<T> {
  if (!cache.has(url)) {
    const p = fetch(url).then(async (r) => {
      if (r.status === 404) throw new NotFound(`404 for ${url}`);
      if (!r.ok) throw new Error(`${r.status} ${r.statusText} for ${url}`);
      return r.json();
    });
    p.catch(() => cache.delete(url));
    cache.set(url, p);
  }
  return cache.get(url) as Promise<T>;
}

/** Like getJson, but a missing resource (404) resolves to null. */
async function getJsonOrNull<T>(url: string): Promise<T | null> {
  try {
    return await getJson<T>(url);
  } catch (e) {
    if (e instanceof NotFound) return null;
    throw e;
  }
}

function route(apiPath: string, staticFile: string): string {
  return API_BASE ? `${API_BASE}${apiPath}` : `${STATIC_BASE}/${staticFile}`;
}

export const api = {
  metadata: () => getJson<Metadata>(route("/metadata", "metadata.json")),
  summary: () => getJson<Summary>(route("/summary", "summary.json")),
  models: () => getJson<ModelList>(route("/models", "models.json")),
  benchmarks: () => getJson<Benchmarks>(route("/benchmarks", "benchmarks.json")),
  metrics: (id: string) => getJson<ModelMetrics>(route(`/models/${id}/metrics`, `models/${id}/metrics.json`)),
  scores: (id: string, split: EvalSplit) =>
    getJson<ScoreTable>(route(`/models/${id}/scores?split=${split}`, `models/${id}/scores/${split}.json`)),
  /** Resolves to null when a static export did not precompute this window. */
  explanation: async (id: string, split: EvalSplit, windowId: string): Promise<Explanation | null> => {
    if (API_BASE) {
      return getJson<Explanation>(`${API_BASE}/models/${id}/explanations/${encodeURIComponent(windowId)}`);
    }
    if (split !== "test") return null;
    const bundle = await getJson<ExplanationBundle>(`${STATIC_BASE}/models/${id}/explanations/test.json`);
    return bundle.explanations[windowId] ?? null;
  },
  graphIndex: (split: EvalSplit) =>
    getJson<GraphWindowIndex>(route(`/graph/windows?split=${split}`, `graph/windows/${split}/index.json`)),
  /** Resolves to null when the window has no graph (or the static export did not include it). */
  graphWindow: (windowId: string) =>
    getJsonOrNull<GraphWindow>(
      route(`/graph/windows/${encodeURIComponent(windowId)}`, `graph/windows/${staticSlug(windowId)}.json`),
    ),
  /** Resolves to null when the static export did not include this entity (hop-2 entities). */
  entity: (entityId: string) =>
    getJsonOrNull<EntityDetail>(route(`/entities/${encodeURIComponent(entityId)}`, `entities/${staticSlug(entityId)}.json`)),
  incidents: () => getJson<IncidentIndex>(route("/incidents", "incidents/index.json")),
  incident: (id: string) =>
    getJsonOrNull<Incident>(route(`/incidents/${encodeURIComponent(id)}`, `incidents/${staticSlug(id)}.json`)),
  explanationsAvailable: async (id: string, split: EvalSplit): Promise<Set<string> | "all"> => {
    if (API_BASE) return "all";
    if (split !== "test") return new Set();
    const bundle = await getJson<ExplanationBundle>(`${STATIC_BASE}/models/${id}/explanations/test.json`);
    return new Set(Object.keys(bundle.explanations));
  },
};

export type Loadable<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; data: T };

/** Load async data; `key` changes trigger a reload. */
export function useLoad<T>(fn: () => Promise<T>, key: string): Loadable<T> {
  const [state, setState] = useState<{ key: string; value: Loadable<T> }>({ key, value: { status: "loading" } });
  useEffect(() => {
    let live = true;
    fn().then(
      (data) => live && setState({ key, value: { status: "ready", data } }),
      (e: unknown) => live && setState({ key, value: { status: "error", error: String(e) } }),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return state.key === key ? state.value : { status: "loading" };
}
