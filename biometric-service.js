class BiometricService {
    constructor() {
        this.isAvailable = false;
        this.plugin = null;
        this.biometricType = 'unknown';
        this.init();
    }

    async init() {
        console.log('🔐 Initializing Biometric Service...');
        
        // Check if we're in a Capacitor environment
        if (typeof Capacitor !== 'undefined' && Capacitor.Plugins && Capacitor.Plugins.BiometricAuth) {
            this.plugin = Capacitor.Plugins.BiometricAuth;
            console.log('📱 Capacitor BiometricAuth plugin detected');
            
            try {
                const result = await this.plugin.isAvailable();
                console.log('📱 Biometric availability result:', result);
                
                this.isAvailable = result.isAvailable;
                this.biometricType = result.biometryType || 'unknown';
                
                if (this.isAvailable) {
                    console.log('✅ Biometric authentication available:', this.biometricType);
                } else {
                    console.log('❌ Biometric authentication not available');
                }
            } catch (error) {
                console.error('❌ Error checking biometric availability:', error);
                this.isAvailable = false;
            }
        } else {
            console.log('📱 Capacitor environment not detected, using fallback');
            this.isAvailable = this.detectFallbackBiometric();
        }
    }

    detectFallbackBiometric() {
        // Fallback detection for non-Capacitor environments
        const userAgent = navigator.userAgent.toLowerCase();
        const isIOS = /iphone|ipad|ipod/.test(userAgent);
        const isAndroid = /android/.test(userAgent);
        
        if (isIOS) {
            this.biometricType = 'face_id';
            console.log('📱 iOS device detected - assuming Face ID/Touch ID support');
            return true;
        } else if (isAndroid) {
            this.biometricType = 'fingerprint';
            console.log('📱 Android device detected - assuming fingerprint support');
            return true;
        }
        
        console.log('❌ No biometric support detected');
        return false;
    }

    async authenticate(reason = 'Authenticate to access your account') {
        console.log('🔐 Starting biometric authentication...');
        
        if (!this.isAvailable) {
            throw new Error('Biometric authentication not available on this device');
        }

        // Use Capacitor plugin if available
        if (this.plugin) {
            try {
                console.log('📱 Using Capacitor biometric authentication');
                const result = await this.plugin.verifyIdentity({
                    reason: reason,
                    title: 'Solura Authentication',
                    subtitle: 'Use biometrics to login',
                    description: ''
                });

                console.log('📱 Biometric authentication result:', result);
                
                if (result.verified) {
                    console.log('✅ Biometric authentication successful');
                    return true;
                } else {
                    throw new Error('Biometric verification failed');
                }
            } catch (error) {
                console.error('❌ Biometric authentication error:', error);
                throw new Error(this.getFriendlyErrorMessage(error));
            }
        } else {
            // Fallback for non-Capacitor environments
            console.log('📱 Using fallback biometric authentication');
            return this.fallbackBiometricAuth(reason);
        }
    }

    async fallbackBiometricAuth(reason) {
        return new Promise((resolve, reject) => {
            // Simulate biometric authentication with a prompt
            const userConfirmed = confirm(`${reason}\n\nClick OK to simulate successful biometric authentication.`);
            
            if (userConfirmed) {
                console.log('✅ Fallback biometric authentication successful');
                resolve(true);
            } else {
                console.log('❌ Fallback biometric authentication cancelled');
                reject(new Error('Authentication cancelled'));
            }
        });
    }

    getFriendlyErrorMessage(error) {
        const message = error.message || error.toString();
        
        if (message.includes('cancel') || message.includes('user cancel')) {
            return 'Authentication was cancelled';
        } else if (message.includes('not available')) {
            return 'Biometric authentication is not available on this device';
        } else if (message.includes('not enrolled')) {
            return 'No biometric data enrolled. Please setup Face ID/Touch ID in your device settings.';
        } else if (message.includes('passcode not set')) {
            return 'Device passcode not set. Please setup a device passcode to use biometric authentication.';
        } else if (message.includes('locked out')) {
            return 'Biometric authentication is temporarily locked. Please try again later or use your device passcode.';
        } else {
            return 'Biometric authentication failed. Please try again.';
        }
    }

    async checkBiometry() {
        if (!this.plugin) {
            return { isAvailable: this.isAvailable, biometryType: this.biometricType };
        }

        try {
            return await this.plugin.isAvailable();
        } catch (error) {
            console.error('Error checking biometry:', error);
            return { isAvailable: false, biometryType: 'unknown' };
        }
    }

    async getSupportedBiometryType() {
        const result = await this.checkBiometry();
        return result.biometryType || this.biometricType;
    }

    isFaceID() {
        return this.biometricType === 'faceId' || this.biometricType === 'face_id';
    }

    isTouchID() {
        return this.biometricType === 'touchId' || this.biometricType === 'fingerprint';
    }

    isFingerprint() {
        return this.biometricType === 'fingerprint';
    }
}

// Create global instance
window.biometricService = new BiometricService();

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BiometricService;
}