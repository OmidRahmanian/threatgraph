import type { Metadata } from "next";
import { NetworkMap } from "@/components/network/NetworkMap";

export const metadata: Metadata = {
  title: "ThreatGraph AI · Network map",
};

export default function NetworkPage() {
  return <NetworkMap />;
}
