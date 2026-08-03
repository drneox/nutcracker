import { defineConfig } from "vite";

// Sale directo a nutcracker_core/plugins/dashboard/static/, servido por
// server.py (StaticFiles) como cualquier otro estático -- el HTML lo importa
// con `await import("/static/webusb-video.bundle.js")` de forma perezosa.
//
// build.lib (no rollupOptions.input a secas) es necesario: un build "app"
// normal de Vite trata este archivo como un script sin efectos secundarios y
// hace tree-shaking de TODO (encontrado en vivo: el chunk principal salía en
// 0.00kB, vacío) porque nada "usa" sus exports dentro del propio build. Modo
// librería le dice a Vite/Rollup que preserve los exports nombrados
// (isSupported, connect) para que el `import()` dinámico del HTML los vea.
export default defineConfig({
  build: {
    outDir: "../static",
    emptyOutDir: false,
    lib: {
      entry: "src/main.ts",
      name: "NutcrackerWebUsbVideo",
      formats: ["es"],
      fileName: () => "webusb-video.bundle.js",
    },
  },
});
