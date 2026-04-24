import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output drastically shrinks the Docker image — Next.js
  // copies only the runtime deps into .next/standalone/, so the final
  // container ships ~150 MB instead of the full node_modules.
  output: "standalone",

  // Reduce the attack surface by removing the X-Powered-By header.
  poweredByHeader: false,

  // The dashboard talks to the FastAPI backend by its docker service name
  // (http://kryon:8000). Next.js lets us rewrite browser-side calls to
  // that service via the network, but all reads happen server-side via
  // lib/api/client.ts so we don't need browser rewrites today.
};

export default nextConfig;
