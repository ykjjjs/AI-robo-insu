import { defineConfig } from 'vite'
import pages from '@hono/vite-cloudflare-pages'
import { writeFileSync } from 'node:fs'

export default defineConfig({
  plugins: [
    pages(),
    {
      name: 'custom-routes-json',
      closeBundle() {
        // Override _routes.json to only route /api/* to Worker
        // Everything else served as static assets (no redirect loop)
        writeFileSync('dist/_routes.json', JSON.stringify({
          version: 1,
          include: ["/api/*"],
          exclude: []
        }, null, 2))
      }
    }
  ],
  build: {
    outDir: 'dist'
  }
})
