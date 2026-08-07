import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

import { manualChunks } from './src/buildChunks';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks,
      },
    },
  },
  server: {
    port: 5173,
  },
});
