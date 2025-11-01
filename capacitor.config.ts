import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.solura.app',
  appName: 'Solura',
  webDir: 'www',
  server: {
    androidScheme: 'https'
  },
  plugins: {
    BiometricAuth: {
      enabled: true
    }
  }
};

export default config;