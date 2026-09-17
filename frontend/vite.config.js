import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/audit': 'http://localhost:8000',
      '/audit-from-screenshot': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/api': 'http://localhost:8000'
    }
  }
})
