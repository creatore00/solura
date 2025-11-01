class BiometricService {
    constructor() {
        this.isAvailable = false;
        this.plugin = null;
        this.init();
    }

    async init() {
        if (typeof Capacitor !== 'undefined' && Capacitor.Plugins.BiometricAuth) {
            this.plugin = Capacitor.Plugins.BiometricAuth;
            try {
                const result = await this.plugin.checkBiometry();
                this.isAvailable = result.isAvailable;
                console.log('🔐 Biometric availability:', result);
            } catch (error) {
                console.error('Biometric check failed:', error);
                this.isAvailable = false;
            }
        } else {
            console.warn('Biometric plugin not available');
        }
    }

    async authenticate(reason = 'Authenticate to access your account') {
        if (!this.isAvailable || !this.plugin) {
            throw new Error('Biometric authentication not available');
        }

        try {
            const result = await this.plugin.authenticate({
                reason: reason,
                title: 'Solura Authentication',
                subtitle: 'Use biometrics to login',
                description: ''
            });

            if (result.verified) {
                console.log('✅ Biometric authentication successful');
                return true;
            } else {
                throw new Error('Authentication failed');
            }
        } catch (error) {
            console.error('❌ Biometric authentication error:', error);
            throw error;
        }
    }

    async setupBiometric() {
        if (!this.isAvailable) {
            throw new Error('Biometric authentication not available on this device');
        }

        try {
            await this.authenticate('Setup biometric authentication for faster login');
            return true;
        } catch (error) {
            console.error('Biometric setup failed:', error);
            throw error;
        }
    }
}

// Create global instance
window.biometricService = new BiometricService();