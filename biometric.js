import { NativeBiometric } from "capacitor-native-biometric";

async function loginWithFaceID() {
  try {
    await NativeBiometric.verifyIdentity({
      reason: "Per accedere all'app",
      title: "Autenticazione",
      subtitle: "Usa Face ID o impronta"
    });
    alert("Autenticazione riuscita!");
  } catch (e) {
    alert("Autenticazione fallita!");
  }
}
