import { PushNotifications } from '@capacitor/push-notifications';

async function setupPush() {
  let perm = await PushNotifications.requestPermissions();
  if (perm.receive === 'granted') {
    await PushNotifications.register();
  }

  PushNotifications.addListener('registration', token => {
    console.log('Device token:', token.value);
  });

  PushNotifications.addListener('pushNotificationReceived', notification => {
    alert(notification.title + ": " + notification.body);
  });
}

setupPush();
