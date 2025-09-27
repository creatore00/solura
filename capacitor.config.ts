import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.solura.app',
  appName: 'Solura',
  webDir: 'www',
  server: {
    url: "https://solura.uk", // point to your server
    cleartext: false,         // since you’re using HTTPS
  }
};

export default config;
