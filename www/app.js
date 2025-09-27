import { Capacitor } from '@capacitor/core';

document.addEventListener('deviceready', () => {
  if (!Capacitor.isNativePlatform()) {
    // fallback for web
    window.location.href = 'https://solura.uk';
  }
});
