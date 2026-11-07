import type { Metadata } from "next";
import { Explorer } from "@/components/explorer/Explorer";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Network explorer",
};

export default function ExplorerPage() {
  return <Explorer />;
}
