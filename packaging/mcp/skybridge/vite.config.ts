import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { skybridge } from '@skybridge/vite-plugin';

export default defineConfig({
  plugins: [react(), skybridge()],
  server: { host: '127.0.0.1' },
});
