"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api, dataSourceLabel, useLoad } from "@/lib/data";
import { ProvenanceBadge } from "./ui";

const NAV = [
  { href: "/threatgraph", label: "Overview", built: true },
  { href: "/threatgraph/lab", label: "Experiment Lab", built: true },
  { href: null, label: "Network explorer", built: false, phase: "Phase 3" },
  { href: null, label: "Incident replay", built: false, phase: "Phase 4" },
] as const;

function ThemeToggle() {
  const [theme, setTheme] = useState<string | null>(null);
  useEffect(() => {
    let saved: string | null = null;
    try {
      saved = localStorage.getItem("tg-theme");
    } catch {}
    if (saved) document.documentElement.dataset.theme = saved;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setTheme(saved);
  }, []);
  const next = () => {
    const isDark =
      theme === "dark" || (theme === null && window.matchMedia("(prefers-color-scheme: dark)").matches);
    const value = isDark ? "light" : "dark";
    document.documentElement.dataset.theme = value;
    try {
      localStorage.setItem("tg-theme", value);
    } catch {}
    setTheme(value);
  };
  return (
    <button onClick={next} className="rounded-md border border-line px-2.5 py-1 text-xs text-ink-2 hover:text-ink" aria-label="Toggle color theme">
      Theme
    </button>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const meta = useLoad(api.metadata, "metadata");
  const provenance = meta.status === "ready" ? meta.data.provenance : null;
  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-20 border-b border-line bg-bg/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <Link href="/threatgraph" className="flex items-center gap-2 font-semibold tracking-tight text-ink">
            <svg aria-hidden width="20" height="20" viewBox="0 0 20 20">
              <circle cx="4" cy="15" r="2.5" fill="var(--model)" />
              <circle cx="16" cy="15" r="2.5" fill="var(--ink-3)" />
              <path d="M10 2.5 L13 5.5 L10 8.5 L7 5.5 Z" fill="var(--redteam)" />
              <path d="M5.5 13.5 L8.5 7.5 M14.5 13.5 L11.5 7.5 M6.5 15 L13.5 15" stroke="var(--ink-3)" strokeWidth="1.2" />
            </svg>
            ThreatGraph AI
          </Link>
          <nav aria-label="ThreatGraph sections" className="order-3 flex w-full gap-1 overflow-x-auto sm:order-none sm:w-auto">
            {NAV.map((item) =>
              item.built ? (
                <Link
                  key={item.label}
                  href={item.href}
                  aria-current={pathname === item.href ? "page" : undefined}
                  className={`whitespace-nowrap rounded-md px-2.5 py-1.5 text-sm ${
                    pathname === item.href ? "bg-panel-2 text-ink" : "text-ink-2 hover:text-ink"
                  }`}
                >
                  {item.label}
                </Link>
              ) : (
                <span
                  key={item.label}
                  aria-disabled="true"
                  title={`${item.label} is not built yet (${item.phase})`}
                  className="flex cursor-not-allowed items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-1.5 text-sm text-ink-3"
                >
                  {item.label}
                  <span className="hidden text-[10px] lg:inline">({item.phase})</span>
                </span>
              ),
            )}
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <ProvenanceBadge provenance={provenance} />
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:py-8">{children}</main>
      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap gap-x-6 gap-y-1 px-4 py-4 text-xs text-ink-3">
          <span>Data source: {dataSourceLabel}</span>
          {provenance ? (
            <span>
              Config {provenance.config_hash} · pipeline {provenance.pipeline_version}
            </span>
          ) : null}
          <span>Historical/synthetic research data — not live threat intelligence or live traffic.</span>
        </div>
      </footer>
    </div>
  );
}
