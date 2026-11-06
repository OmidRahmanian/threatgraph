import type { NextConfig } from "next";

// Static export so the module can be hosted on any static site, optionally under a sub-path
// of an existing personal site (set NEXT_PUBLIC_BASE_PATH, e.g. "/projects").
const basePath = process.env.NEXT_PUBLIC_BASE_PATH || undefined;

const nextConfig: NextConfig = {
  output: "export",
  basePath,
  trailingSlash: true,
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
