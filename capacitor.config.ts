import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.solura.app',
  appName: 'Solura',
  webDir: 'www',
  server: {
    androidScheme: 'https',
    hostname: 'solura.uk'
  },
  plugins: {
    NativeBiometric: {
      server: 'com.solura.app'
    }
  },
  android: {
    allowMixedContent: true // For testing, remove in production
  }
};

export default config;