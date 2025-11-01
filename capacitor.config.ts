import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.solura.app',
  appName: 'Solura',
  webDir: 'www',
  server: {
    url: "https://solura.uk", // point to your server
    cleartext: false,         // since you’re using HTTPS
  },
  plugins: {
    BiometricAuth: {
      // iOS specific configuration
      ios: {
        usageDescription: 'Use Face ID/Touch ID to securely access your account'
      }
    }
  }
};

export default config;
