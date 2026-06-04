import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const dashboardBuildApiKey = 'vite_admin_dashboard_api_key_1234567890';

export default defineConfig({
  plugins: [react()],
  define: {
    __DASHBOARD_BUILD_API_KEY__: JSON.stringify(dashboardBuildApiKey),
  },
});
