import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const proxy = {
  "/api": {},
};

function expressPlugin() {
  return {
    name: "express-plugin",
    config(_, { mode }) {
      if (mode === "production") {
        return {};
      }

      return {
        server: { proxy },
        preview: { proxy },
      };
    },
    async configureServer(server) {
      const { app } = await import("./functions/app.js");

      server.middlewares.use(app);
    },
  };
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [expressPlugin(), react()],
});
