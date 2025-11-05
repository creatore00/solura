// sendPushNotification.js
const { google } = require("googleapis");
const fetch = require("node-fetch");

// Load service account credentials
const serviceAccount = require("./serviceAccount.json"); // Your downloaded service account JSON

const PROJECT_ID = serviceAccount.project_id;
const SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"];

// Gets an access token using the service account
async function getAccessToken() {
  try {
    const jwtClient = new google.auth.JWT(
      serviceAccount.client_email,
      null,
      serviceAccount.private_key,
      SCOPES
    );

    const tokens = await jwtClient.authorize();
    return tokens.access_token;
  } catch (error) {
    console.error("Error getting access token:", error);
    throw error;
  }
}

// Sends push notification
async function sendPushNotification(token, title, body, data = {}) {
  try {
    const accessToken = await getAccessToken();

    const response = await fetch(
      `https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: {
            token: token, // The registered device token
            notification: {
              title: title,
              body: body,
            },
            data: data, // Optional custom data
          },
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`FCM API error: ${response.status} - ${errorText}`);
    }

    const responseData = await response.json();
    console.log("FCM response:", responseData);
    return responseData;
  } catch (error) {
    console.error("Error sending push notification:", error);
    throw error;
  }
}

// Example usage
(async () => {
  try {
    const testDeviceToken = "102496539184452823703"; // Token from Firebase client
    await sendPushNotification(
      testDeviceToken,
      "Ciao da Solura 🚀",
      "Questa è una notifica di test!",
      { type: "test", screen: "home" } // Optional custom data
    );
    console.log("Notification sent successfully!");
  } catch (error) {
    console.error("Failed to send notification:", error);
  }
})();

// Export for use in other modules
module.exports = { sendPushNotification };