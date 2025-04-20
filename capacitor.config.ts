import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.solura.app',
  appName: 'Solura',
  webDir: 'empty', // Can be any placeholder since you're not using local files
  server: {
    url: 'https://solura-6b215edc5c30.herokuapp.com',
    cleartext: true
  }
};

export default config;
