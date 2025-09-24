import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.solura.app',
  appName: 'Solura',
  webDir: 'www',
  server: {
    url: "https://solura.uk",   // carica direttamente il tuo server Node
  }
};

export default config;
