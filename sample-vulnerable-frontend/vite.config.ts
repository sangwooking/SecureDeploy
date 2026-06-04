import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const apiKey = 'vite_config_api_key_1234567890';

export default defineConfig({
  plugins: [react()],
  define: {
    __API_KEY__: JSON.stringify(apiKey),
  },
});
