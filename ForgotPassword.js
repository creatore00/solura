const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const { mainPool } = require('./db.js');

const app = express();
// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// Generate secure token
function generateToken() {
    return crypto.randomBytes(4).toString('hex');
}

// Handle password recovery request
app.post('/api/password-recovery', (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    // Check if email exists in database
    mainPool.query(
        'SELECT Email FROM users WHERE Email = ?', 
        [email],
        (err, users) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            if (users.length === 0) {
                return res.status(404).json({ message: 'Email not found' });
            }

            // Generate token and expiration (1 hour from now)
            const token = generateToken();
            const expiration = new Date(Date.now() + 3600000); // 1 hour
            
            // Store token in database
            mainPool.query(
                'UPDATE users SET Token = ?, Expiry = ? WHERE Email = ?',
                [token, expiration, email],
                (updateErr) => {
                    if (updateErr) {
                        console.error('Database update error:', updateErr);
                        return res.status(500).json({ message: 'Internal server error' });
                    }
                // Create reset link
                const resetLink = `https://solura-6b215edc5c30.herokuapp.com/token`;
                    
                                // Send password reset link to the provided email address
                                const transporter = nodemailer.createTransport({
                                    host: 'smtp0001.neo.space', // Your SMTP Host
                                    port: 465, // SSL Port
                                    secure: true, // `true` for SSL (port 465)
                                    auth: {
                                        user: 'founder@solura.uk',
                                        pass: 'Salvemini01@'
                                    }
                                });
                    // Send email
                    transporter.sendMail({
                        from: 'Solura Support <founder@solura.uk>', // FIXED
                        to: email,
                        subject: 'Password Reset Request',
                        html: `
                            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                                <h2 style="color: #333;">Password Reset Request</h2>
                                <p>You requested to reset your password. Please Copy and Past this Token '${token}' in the link below to proceed:</p>
                                <p><a href="${resetLink}" style="background-color: #474747; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
                                <p>This link will expire in 1 hour. If you didn't request this, please ignore this email.</p>
                                <p>Alternatively, you can copy and paste this link into your browser:</p>
                                <p style="word-break: break-all;">${resetLink}</p>
                            </div>
                        `
                    }, (mailErr) => {
                        if (mailErr) {
                            console.error('Email sending error:', mailErr);
                            return res.status(500).json({ message: 'Failed to send recovery email' });
                        }
                    
                        res.json({ message: 'Recovery email sent successfully' });
                    });                    
                }
            );
        }
    );
});

// Cleanup expired tokens (run every hour)
setInterval(() => {
    mainPool.query(
        'UPDATE users SET Token = NULL, Expiry = NULL WHERE Expiry < NOW()',
        (err) => {
            if (err) {
                console.error('Error cleaning up expired tokens:', err);
            } else {
                console.log('Cleaned up expired password reset tokens');
            }
        }
    );
}, 3600000); // 1 hour

// Route to serve the FP.html file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'ForgotPassword.html'));
});

module.exports = app;