import type { Metadata } from "next";
import { LiveDashboard } from "@/components/live/LiveDashboard";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Live monitoring",
  robots: { index: false, follow: false },
};

export default function LivePage() {
  return <LiveDashboard />;
}
