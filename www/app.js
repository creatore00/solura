import { Browser } from '@capacitor/browser';
import { Capacitor } from '@capacitor/core';

document.addEventListener('deviceready', async () => {
  if (Capacitor.isNativePlatform()) {
    await Browser.open({
      url: 'https://solura.uk',
      presentationStyle: 'fullscreen'
    });
  } else {
    // fallback for browser
    window.location.href = 'https://solura.uk';
  }
});
