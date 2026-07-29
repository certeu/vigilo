import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The SPA talks only to the API. In dev, proxy /api to the FastAPI server so the
// same-origin fetch('/api/...') calls work without CORS.
export default defineConfig({
  plugins: [react()],
  server: {
    // Bind to all interfaces so PyCharm/SSH port-forwarding and tunnels can reach
    // it from a dev VM (localhost-only binding is not forwardable). allowedHosts:true
    // accepts the tunnel's Host header.
    host: true,
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    proxy: {
      "/api": {
        target: process.env.VIGILO_API_URL || "http://localhost:8080",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
