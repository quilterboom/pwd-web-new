import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 部署形态：构建产物是纯静态文件，由 FastAPI 的 StaticFiles 同源托管，
// 因此 base 用相对路径，且不依赖任何服务端路由回退（使用 hash 路由）。
export default defineConfig({
  plugins: [vue()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // 本地开发时将 API 代理到后端，避免跨域
      '/api': 'http://localhost:9010',
    },
  },
})
