// ============================================
// SERVICE 1: MULTI-TENANT SCANNER SERVICE
// FINAL PRODUCTION VERSION - RENDER OPTIMIZED
// ============================================

const express = require('express');
const cors = require('cors');
const { Client, NoAuth } = require('whatsapp-web.js');
const mongoose = require('mongoose');
const qrcode = require('qrcode');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Single client instance to save memory
let activeClient = null;
let clientState = {
    qrCode: null,
    qrImage: null,
    status: 'disconnected',
    sessionId: null,
    phoneNumber: null,
    isInitializing: false,
    createdAt: null
};

// ============================================
// ENCRYPTION UTILITIES
// ============================================
const ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY 
    ? Buffer.from(process.env.ENCRYPTION_KEY.substring(0, 64), 'hex')
    : crypto.randomBytes(32);

function encryptData(text) {
    try {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return {
            encrypted: encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    } catch (error) {
        console.error('❌ Encryption error:', error);
        throw error;
    }
}

// ============================================
// MONGODB SESSION SCHEMA
// ============================================
const SessionSchema = new mongoose.Schema({
    sessionId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    phoneNumber: {
        type: String,
        required: true,
        index: true
    },
    authData: {
        serialized: String,
        remoteAuthPath: String
    },
    metadata: {
        deviceName: String,
        platform: String,
        whatsappVersion: String,
        createdAt: { type: Date, default: Date.now },
        lastActive: { type: Date, default: Date.now }
    },
    status: {
        type: String,
        enum: ['pending', 'active', 'inactive'],
        default: 'active'
    },
    encryption: {
        iv: String,
        authTag: String
    }
}, { timestamps: true });

const Session = mongoose.model('Session', SessionSchema);

// ============================================
// DESTROY CLIENT SAFELY
// ============================================
async function destroyClient() {
    if (!activeClient) return;
    
    console.log('🧹 Destroying active client...');
    try {
        await activeClient.destroy();
        console.log('✅ Client destroyed');
    } catch (error) {
        console.error('⚠️  Error destroying client:', error.message);
    }
    
    activeClient = null;
    clientState = {
        qrCode: null,
        qrImage: null,
        status: 'disconnected',
        sessionId: null,
        phoneNumber: null,
        isInitializing: false,
        createdAt: null
    };
}

// ============================================
// INITIALIZE WHATSAPP CLIENT
// ============================================
async function initializeClient() {
    if (clientState.isInitializing) {
        console.log('⚠️  Already initializing, skipping...');
        return false;
    }
    
    if (activeClient) {
        console.log('🧹 Destroying existing client first...');
        await destroyClient();
    }
    
    clientState.isInitializing = true;
    clientState.status = 'initializing';
    clientState.createdAt = Date.now();
    
    console.log('🚀 Creating new WhatsApp client...');
    
    try {
        const client = new Client({
            authStrategy: new NoAuth(),
            puppeteer: {
                headless: true,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--single-process',
                    '--disable-gpu',
                    '--disable-software-rasterizer',
                    '--disable-web-security'
                ],
                timeout: 60000
            },
            qrMaxRetries: 3
        });

        activeClient = client;

        // QR Code Generation
        client.on('qr', async (qr) => {
            console.log('📱 QR CODE RECEIVED');
            clientState.qrCode = qr;
            clientState.status = 'qr_ready';
            
            try {
                clientState.qrImage = await qrcode.toDataURL(qr);
                console.log('✅ QR code converted to image');
            } catch (err) {
                console.error('❌ QR generation failed:', err);
            }
        });

        // Authenticated
        client.on('authenticated', () => {
            console.log('🔐 AUTHENTICATED');
            clientState.status = 'authenticated';
        });

        // Ready - Save Session
        client.on('ready', async () => {
            console.log('✅ CLIENT READY');
            clientState.status = 'ready';

            try {
                const info = client.info;
                const phoneNumber = info.wid.user;
                const deviceName = info.pushname || 'Unknown';
                const sessionId = `session_${phoneNumber}_${Date.now()}`;
                
                clientState.sessionId = sessionId;
                clientState.phoneNumber = phoneNumber;

                console.log(`📞 Phone: ${phoneNumber}`);
                console.log(`🔑 Session ID: ${sessionId}`);

                // Serialize and encrypt
                const sessionData = {
                    phoneNumber,
                    deviceName,
                    wid: info.wid,
                    timestamp: new Date().toISOString()
                };

                const serialized = JSON.stringify(sessionData);
                const encrypted = encryptData(serialized);

                // Save to MongoDB
                await Session.create({
                    sessionId,
                    phoneNumber,
                    authData: {
                        serialized: encrypted.encrypted
                    },
                    metadata: {
                        deviceName,
                        platform: info.platform || 'web',
                        whatsappVersion: info.wwebVersion || 'unknown'
                    },
                    status: 'active',
                    encryption: {
                        iv: encrypted.iv,
                        authTag: encrypted.authTag
                    }
                });

                console.log('💾 Session saved to MongoDB');

                // Send to WhatsApp
                await sendSessionToWhatsApp(client, phoneNumber, sessionId, deviceName);

                clientState.status = 'session_saved';

                // Cleanup after 30 seconds
                setTimeout(async () => {
                    console.log('🧹 Auto-cleanup after success');
                    await destroyClient();
                }, 30000);

            } catch (error) {
                console.error('❌ Save session error:', error);
                clientState.status = 'error';
            }
        });

        // Loading
        client.on('loading_screen', (percent) => {
            if (percent % 25 === 0) {
                console.log(`⏳ Loading: ${percent}%`);
            }
        });

        // Auth Failure
        client.on('auth_failure', async () => {
            console.error('❌ AUTHENTICATION FAILED');
            clientState.status = 'auth_failed';
            setTimeout(() => destroyClient(), 5000);
        });

        // Disconnected
        client.on('disconnected', () => {
            console.log('🔌 DISCONNECTED');
            clientState.status = 'disconnected';
        });

        // Initialize
        console.log('⏳ Initializing WhatsApp Web...');
        await client.initialize();
        clientState.isInitializing = false;
        
        return true;

    } catch (error) {
        console.error('❌ Initialize error:', error.message);
        clientState.status = 'error';
        clientState.isInitializing = false;
        await destroyClient();
        return false;
    }
}

// ============================================
// SEND SESSION TO WHATSAPP
// ============================================
async function sendSessionToWhatsApp(client, phoneNumber, sessionId, deviceName) {
    try {
        const chatId = `${phoneNumber}@c.us`;
        
        const message = `🎉 *Authentication Successful!*

✅ Your session has been created.

🔑 *Session ID:*
\`${sessionId}\`

📱 *Device:* ${deviceName}
📅 *Created:* ${new Date().toLocaleString()}

🚀 *Next Steps:*
1. Copy the Session ID above
2. Add to your .env: SESSION_ID=${sessionId}
3. Deploy your bot backend
4. Your bot will auto-connect!

⚠️ Keep this Session ID SECRET!

Happy botting! 🤖✨`;

        await client.sendMessage(chatId, message);
        console.log(`✅ Session ID sent to ${phoneNumber}`);

    } catch (error) {
        console.error('❌ Failed to send message:', error.message);
    }
}

// ============================================
// AUTO-TIMEOUT FOR STALE SESSIONS
// ============================================
function checkTimeout() {
    if (!clientState.createdAt) return;
    
    const age = Date.now() - clientState.createdAt;
    const TIMEOUT = 5 * 60 * 1000; // 5 minutes
    
    if (age > TIMEOUT && clientState.status !== 'session_saved') {
        console.log('⏱️  Session timeout - cleaning up');
        destroyClient();
    }
}

setInterval(checkTimeout, 60000); // Check every minute

// ============================================
// API ROUTES
// ============================================

app.get('/api/health', (req, res) => {
    res.json({
        service: 'scanner',
        status: 'ok',
        clientStatus: clientState.status,
        hasActiveClient: !!activeClient,
        timestamp: new Date().toISOString()
    });
});

app.post('/api/auth/start', async (req, res) => {
    try {
        if (clientState.isInitializing) {
            return res.json({
                success: false,
                message: 'Already initializing, please wait...'
            });
        }

        if (activeClient && clientState.status === 'qr_ready') {
            return res.json({
                success: true,
                message: 'Client already active',
                clientId: 'active'
            });
        }

        console.log('🆕 New authentication request');
        
        // Start initialization (non-blocking)
        initializeClient().catch(err => {
            console.error('Init failed:', err);
        });

        res.json({
            success: true,
            message: 'Authentication started',
            clientId: 'active'
        });

    } catch (error) {
        console.error('Start auth error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

app.post('/api/auth/reset', async (req, res) => {
    try {
        console.log('🔄 Reset requested');
        await destroyClient();
        res.json({
            success: true,
            message: 'Reset successful'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

app.get('/api/qr/:clientId', (req, res) => {
    if (clientState.qrImage) {
        res.json({
            success: true,
            qrImage: clientState.qrImage,
            status: clientState.status
        });
    } else {
        res.json({
            success: false,
            message: getStatusMessage(clientState.status),
            status: clientState.status
        });
    }
});

app.get('/api/status/:clientId', (req, res) => {
    res.json({
        status: clientState.status,
        hasQR: !!clientState.qrCode,
        sessionId: clientState.sessionId,
        phoneNumber: clientState.phoneNumber,
        message: getStatusMessage(clientState.status)
    });
});

app.get('/api/sessions', async (req, res) => {
    try {
        const sessions = await Session.find({})
            .select('-authData.serialized')
            .sort({ createdAt: -1 })
            .limit(50);
        
        res.json({
            success: true,
            count: sessions.length,
            sessions
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/sessions/:sessionId', async (req, res) => {
    try {
        const session = await Session.findOne({ 
            sessionId: req.params.sessionId 
        }).select('-authData.serialized');
        
        if (!session) {
            return res.status(404).json({
                success: false,
                message: 'Session not found'
            });
        }

        res.json({ success: true, session });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/api/sessions/verify', async (req, res) => {
    try {
        const { sessionId } = req.body;
        
        if (!sessionId) {
            return res.status(400).json({
                success: false,
                message: 'Session ID required'
            });
        }

        const session = await Session.findOne({ 
            sessionId, 
            status: 'active' 
        });
        
        res.json({
            success: !!session,
            exists: !!session,
            ...(session && {
                phoneNumber: session.phoneNumber,
                deviceName: session.metadata.deviceName,
                createdAt: session.metadata.createdAt
            })
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

function getStatusMessage(status) {
    const messages = {
        'disconnected': 'Not connected',
        'initializing': 'Initializing WhatsApp...',
        'qr_ready': 'QR ready - scan now',
        'authenticated': 'Authenticated',
        'ready': 'Saving session...',
        'session_saved': 'Session saved successfully',
        'auth_failed': 'Authentication failed',
        'error': 'Error occurred'
    };
    return messages[status] || status;
}

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 4000;

async function startServer() {
    try {
        if (!process.env.MONGODB_URI) {
            throw new Error('MONGODB_URI required');
        }

        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB Connected');

        app.listen(PORT, '0.0.0.0', () => {
            console.log('\n' + '='.repeat(60));
            console.log('🎉 SCANNER SERVICE STARTED');
            console.log('='.repeat(60));
            console.log(`📱 Port: ${PORT}`);
            console.log(`💾 Database: Connected`);
            console.log(`🔐 Encryption: Enabled`);
            console.log('='.repeat(60) + '\n');
        });

    } catch (error) {
        console.error('❌ Startup failed:', error);
        process.exit(1);
    }
}

startServer();

// ============================================
// GRACEFUL SHUTDOWN
// ============================================
async function shutdown(signal) {
    console.log(`\n🛑 ${signal} - Shutting down...`);
    
    await destroyClient();
    await mongoose.connection.close();
    
    console.log('✅ Shutdown complete');
    process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err);
});

process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled Rejection:', err);
});