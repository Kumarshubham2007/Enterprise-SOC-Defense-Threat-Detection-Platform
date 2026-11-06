import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const backendPort = process.env.ESMIR_BACKEND_PORT || '8000';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
      },
    },
  },
})
