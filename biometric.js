const { Capacitor } = require('@capacitor/core');
const { NativeBiometric } = require('@capgo/capacitor-native-biometric');


const isCapacitor = Capacitor.isNativePlatform();
let databases = [];
let currentUserData = null;

document.getElementById('loginForm').addEventListener('submit', submitForm);
document.getElementById('enableBioBtn').addEventListener('click', enableBiometric);
document.getElementById('skipBioBtn').addEventListener('click', skipBiometric);
document.getElementById('continueDbBtn').addEventListener('click', submitDatabase);
document.getElementById('closeDbBtn').addEventListener('click', closePopup);

init();

async function init() {
    console.log('Initializing app...');
    await tryBiometricLoginOnLoad();
}

// ------------------- Biometric Login -------------------
async function tryBiometricLoginOnLoad() {
    if (!isCapacitor) return showLoginForm();

    try {
        const available = await NativeBiometric.isAvailable();
        if (!available.isAvailable) return showLoginForm();

        const credentials = await NativeBiometric.getCredentials({ server: 'com.solura.app' });
        if (credentials?.username) {
            await NativeBiometric.verifyIdentity({
                reason: 'Per accedere all\'app',
                title: 'Autenticazione',
                subtitle: 'Usa Face ID o impronta'
            });

            let { accessToken, refreshToken } = JSON.parse(credentials.password);

            let res = await fetch('/auto-login', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${accessToken}` },
                credentials: 'include'
            });

            if (res.status === 401) {
                const refreshRes = await fetch('/refresh-token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refreshToken })
                });

                if (!refreshRes.ok) throw new Error('Refresh token failed');
                const data = await refreshRes.json();
                accessToken = data.accessToken;

                await NativeBiometric.setCredentials({
                    username: credentials.username,
                    password: JSON.stringify({ accessToken, refreshToken }),
                    server: 'com.solura.app'
                });

                res = await fetch('/auto-login', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${accessToken}` },
                    credentials: 'include'
                });
            }

            if (res.ok) {
                const userData = await res.json();
                window.location.href = userData.redirectUrl;
            } else {
                showLoginForm();
            }
        } else {
            showLoginForm();
        }
    } catch (e) {
        console.warn('Biometric login failed:', e.message);
        showLoginForm();
    }
}

function showLoginForm() {
    document.getElementById('loginForm').style.display = 'block';
}

// ------------------- Manual Login -------------------
async function submitForm(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const submitBtn = event.target.querySelector('button[type="submit"]');

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Authenticating...';

    try {
        const res = await fetch('/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password })
        });

        if (!res.ok) throw new Error(await res.text());
        const data = await res.json();

        if (data.message === 'Multiple databases found') {
            databases = data.databases;
            showDatabasePopup(databases);
        } else if (data.redirectUrl) {
            currentUserData = { email, accessToken: data.accessToken, refreshToken: data.refreshToken, redirectUrl: data.redirectUrl };
            if (await checkBiometricAvailability()) {
                document.getElementById('biometricPrompt').style.display = 'block';
            } else {
                window.location.href = data.redirectUrl;
            }
        } else {
            alert('Incorrect Email or Password.');
        }
    } catch (e) {
        alert(`Login failed: ${e.message}`);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In';
    }
}

// ------------------- Biometric Enable/Skip -------------------
async function enableBiometric() {
    if (!isCapacitor) return window.location.href = currentUserData.redirectUrl;
    try {
        await NativeBiometric.setCredentials({
            username: currentUserData.email,
            password: JSON.stringify({ accessToken: currentUserData.accessToken, refreshToken: currentUserData.refreshToken }),
            server: 'com.solura.app'
        });
    } catch (error) {
        alert('Failed to enable biometric login: ' + error.message);
    }
    document.getElementById('biometricPrompt').style.display = 'none';
    window.location.href = currentUserData.redirectUrl;
}

function skipBiometric() {
    document.getElementById('biometricPrompt').style.display = 'none';
    window.location.href = currentUserData.redirectUrl;
}

// ------------------- Database Popup -------------------
function showDatabasePopup(databases) {
    const popup = document.getElementById('databasePopup');
    const list = document.getElementById('databaseList');
    list.innerHTML = '';
    databases.forEach(db => {
        const li = document.createElement('li');
        li.innerHTML = `<input type="radio" name="database" id="db-${db.db_name}" value="${db.db_name}" required>
                        <label for="db-${db.db_name}"><strong>${db.db_name}</strong><span style="display:block;font-size:0.9em;color:#777">${db.access} access</span></label>`;
        list.appendChild(li);
    });
    popup.style.display = 'block';
}

async function submitDatabase() {
    const selectedDatabase = document.querySelector('input[name="database"]:checked')?.value;
    if (!selectedDatabase) return alert('Please select a database.');

    const popupBtn = document.getElementById('continueDbBtn');
    popupBtn.disabled = true;
    popupBtn.innerHTML = '<span class="spinner"></span> Connecting...';

    try {
        const res = await fetch('/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email: currentUserData.email, password: '', dbName: selectedDatabase })
        });

        const data = await res.json();
        if (data.redirectUrl) {
            currentUserData.accessToken = data.accessToken;
            currentUserData.refreshToken = data.refreshToken;
            document.getElementById('databasePopup').style.display = 'none';
            if (await checkBiometricAvailability()) {
                document.getElementById('biometricPrompt').style.display = 'block';
            } else {
                window.location.href = data.redirectUrl;
            }
        }
    } catch (e) {
        alert(`Database selection failed: ${e.message}`);
    } finally {
        popupBtn.disabled = false;
        popupBtn.textContent = 'Continue';
    }
}

function closePopup() {
    document.getElementById('databasePopup').style.display = 'none';
    document.getElementById('loginForm').reset();
}

// ------------------- Helpers -------------------
async function checkBiometricAvailability() {
    if (!isCapacitor) return false;
    try {
        const available = await NativeBiometric.isAvailable();
        return available.isAvailable;
    } catch {
        return false;
    }
}
