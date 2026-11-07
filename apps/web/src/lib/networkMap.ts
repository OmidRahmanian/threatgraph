// What the network map shows for a model, a day range and a filter.
//
// Every count is recomputed from the per-day link records, so a link that carried red-team
// events on day 12 is not marked red-team when only day 13 is selected.

import type { MapAccount, MapComputer, MapLink, NetworkMap } from "./types";

export type ShowMode = "alerted" | "redteam" | "all";

export interface ViewOptions {
  modelId: string;
  show: ShowMode;
  from: number;
  to: number;
}

export interface AccountView {
  id: string;
  label: string;
  /** Windows in range flagged by the selected model. */
  alerts: number;
  /** Windows in range that contain known red-team events. */
  redteamWindows: number;
  events: number;
  degree: number;
  account: MapAccount;
}

export interface ComputerView {
  id: string;
  label: string;
  degree: number;
  events: number;
  knownRedteam: number;
  computer: MapComputer;
}

export interface LinkView {
  id: string;
  account: string;
  computer: string;
  events: number;
  fail: number;
  knownRedteam: number;
  /** A window flagged by the selected model, in range, contains this link's events. */
  alerted: boolean;
  link: MapLink;
}

export interface MapView {
  accounts: AccountView[];
  computers: ComputerView[];
  links: LinkView[];
}

export const linkId = (l: { account: string; computer: string }) => `${l.account}|${l.computer}`;

export function buildView(map: NetworkMap, opts: ViewOptions): MapView {
  const { modelId, show, from, to } = opts;
  const mi = map.models.indexOf(modelId);
  const inRange = (d: number) => d >= from && d <= to;

  const links: LinkView[] = [];
  for (const l of map.links) {
    let events = 0;
    let fail = 0;
    let knownRedteam = 0;
    let alerted = false;
    let any = false;
    for (const d of l.by_day) {
      if (!inRange(d.day)) continue;
      any = true;
      events += d.n_events;
      fail += d.n_fail;
      knownRedteam += d.n_known_redteam;
      alerted ||= d.alerted.includes(mi);
    }
    if (any) links.push({ id: linkId(l), account: l.account, computer: l.computer, events, fail, knownRedteam, alerted, link: l });
  }
  const linksOf = new Map<string, LinkView[]>();
  for (const l of links) linksOf.set(l.account, [...(linksOf.get(l.account) ?? []), l]);

  const accounts: AccountView[] = [];
  for (const a of map.accounts) {
    const own = linksOf.get(a.node_id) ?? [];
    const windows = a.windows.filter((w) => inRange(w.day));
    const alerts = windows.filter((w) => w.scores[modelId]?.flagged).length;
    const redteamWindows = windows.filter((w) => w.known_redteam).length;
    const keep = show === "alerted" ? alerts > 0 : show === "redteam" ? redteamWindows > 0 : own.length > 0;
    if (!keep || own.length === 0) continue;
    accounts.push({
      id: a.node_id,
      label: a.label,
      alerts,
      redteamWindows,
      events: own.reduce((s, l) => s + l.events, 0),
      degree: own.length,
      account: a,
    });
  }
  const shown = new Set(accounts.map((a) => a.id));
  const keptLinks = links.filter((l) => shown.has(l.account));

  const byComputer = new Map<string, LinkView[]>();
  for (const l of keptLinks) byComputer.set(l.computer, [...(byComputer.get(l.computer) ?? []), l]);
  const computers: ComputerView[] = [];
  for (const c of map.computers) {
    const own = byComputer.get(c.node_id);
    if (!own) continue;
    computers.push({
      id: c.node_id,
      label: c.label,
      degree: own.length,
      events: own.reduce((s, l) => s + l.events, 0),
      knownRedteam: own.reduce((s, l) => s + l.knownRedteam, 0),
      computer: c,
    });
  }
  return { accounts, computers, links: keptLinks };
}

/** Node ids whose label contains the query (case-insensitive), accounts first. */
export function searchNodes(view: MapView, query: string, limit = 8): { id: string; label: string; kind: "account" | "computer" }[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const hits = [
    ...view.accounts.filter((a) => a.label.toLowerCase().includes(q)).map((a) => ({ id: a.id, label: a.label, kind: "account" as const })),
    ...view.computers.filter((c) => c.label.toLowerCase().includes(q)).map((c) => ({ id: c.id, label: c.label, kind: "computer" as const })),
  ];
  // Exact and prefix matches first.
  const rank = (label: string) => (label.toLowerCase() === q ? 0 : label.toLowerCase().startsWith(q) ? 1 : 2);
  return hits.sort((a, b) => rank(a.label) - rank(b.label) || a.label.localeCompare(b.label)).slice(0, limit);
}

export function neighbors(view: MapView, id: string): Set<string> {
  const out = new Set([id]);
  for (const l of view.links) {
    if (l.account === id) out.add(l.computer);
    if (l.computer === id) out.add(l.account);
  }
  return out;
}
