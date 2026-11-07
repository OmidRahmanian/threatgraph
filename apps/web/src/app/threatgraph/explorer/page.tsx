import type { Metadata } from "next";
import { Explorer } from "@/components/explorer/Explorer";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Hour explorer",
};

export default function ExplorerPage() {
  return <Explorer />;
}
