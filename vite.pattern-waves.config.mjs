import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'code/frontend',
    emptyOutDir: false,
    copyPublicDir: false,
    lib: {
      entry: 'src/pattern-waves-widget.jsx',
      name: 'GhostguardPatternWaves',
      formats: ['iife'],
      fileName: () => 'pattern-waves-widget.js',
    },
  },
});
