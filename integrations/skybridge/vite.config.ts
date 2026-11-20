import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { skybridge } from '@skybridge/vite-plugin';
import path from 'node:path';

export default defineConfig({
  plugins: [skybridge(), react()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
});
