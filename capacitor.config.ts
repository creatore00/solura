import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.solura.app',
  appName: 'Solura',
  webDir: 'www',
"server": {
    "androidScheme": "https",
    // **ADD THIS SECTION. This is the critical fix.**
    "hostname": "www.solura.uk",
    "iosScheme": "https",
    "allowNavigation": [
      "www.solura.uk"
    ]
  },
  // Add this section if it's missing
  "plugins": {
    "CapacitorCookies": {
      "enabled": true
    }
  }
}
export default config;
