import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Plugin to prevent Vite serve static middleware from failing on malformed URIs
const safeUriDecodePlugin = () => ({
  name: 'safe-uri-decode',
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (req.url) {
        try {
          // Decode URL safely or sanitize percent symbols
          decodeURI(req.url)
        } catch {
          // Replace raw '%' or invalid escape sequences with '%25'
          req.url = req.url.replace(/%(?![0-9A-Fa-f]{2})/g, '%25')
          try {
            decodeURI(req.url)
          } catch {
            // Fallback to sanitizing percent signs if still failing
            req.url = encodeURI(req.url)
          }
        }
      }
      next()
    })
  }
})

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    safeUriDecodePlugin(),
  ],
  server: {
    port: 5173,
    host: true,
    allowedHosts: ['centinela.casmart.internal'],
    hmr: {
      overlay: false
    }
  }
})


