import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The dev server proxies /api to the loopback FastAPI backend, so the browser
// talks to a single origin and no wildcard CORS is ever needed.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: false,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: false },
    },
  },
  preview: { host: "127.0.0.1", port: 4173 },
  build: { outDir: "dist", sourcemap: false },
  test: {
    include: ["src/test/**/*.{test,spec}.{js,jsx}"],
    environment: "jsdom",
    setupFiles: ["./src/test/setup.js"],
    css: false,
  },
});
