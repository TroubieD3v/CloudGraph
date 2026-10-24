import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build is embedded into the Go binary (internal/ui/dist).
export default defineConfig({
  plugins: [react()],
  build: { outDir: "../internal/ui/dist", emptyOutDir: true, chunkSizeWarningLimit: 900 },
  server: {
    port: 5173,
    // The API rejects cross-origin writes, so present the proxied requests as same-origin.
    proxy: { "/api": { target: "http://127.0.0.1:8080", changeOrigin: true, headers: { Origin: "http://127.0.0.1:8080" } } },
  },
});
