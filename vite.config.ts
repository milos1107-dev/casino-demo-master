import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const ENV_PREFIX = ['VITE_']

export default defineConfig(() => ({
  envPrefix: ENV_PREFIX,
  server: { port: 4001, host: true },
  assetsInclude: ["**/*.glb"],
  define: {
    'process.env.ANCHOR_BROWSER': true,
  },
  resolve: {
    alias: {
      fs: require.resolve("rollup-plugin-node-builtins"),
      crypto: 'crypto-browserify',
    },
  },
  plugins: [
    react({ jsxRuntime: 'classic' }),
  ],
}))
