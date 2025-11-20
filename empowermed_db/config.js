// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    https: false, // use false for local dev to avoid blank page
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
  },
  define: {
    global: 'window',
    'process.env': {},
  },
})