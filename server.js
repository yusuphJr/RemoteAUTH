// ============================================
// SERVICE 1: MULTI-TENANT SCANNER SERVICE
// Render Deployment Version - Fixed
// ============================================

const express = require('express');
const cors = require('cors');
const { Client, RemoteAuth } = require('whatsapp-web.js');
const mongoose = require('mongoose');
const { MongoStore } = require('wwebjs-mongo');
const qrcode = require('qrcode');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Store multiple client instances
const activeClients = new Map();
let mongoStore = null;
let isShuttingDown = false;

// ============================================
// ENCRYPTION UTILITIES
// ============================================
const ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY 
    ? Buffer.from(process.env.ENCRYPTION_KEY.substring(0, 64), 'hex')
    : (() => {
        console.warn('⚠️  WARNING: No ENCRYPTION_KEY in .env! Generating temporary key.');
        return crypto.randomBytes(32);
    })();

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
        serialized: {
            type: String,
            required: true
        },
        remoteAuthPath: {
            type: String,
            required: true
        }
    },
    metadata: {
        deviceName: String,
        platform: String,
        whatsappVersion: String,
        createdAt: {
            type: Date,
            default: Date.now
        },
        lastActive: {
            type: Date,
            default: Date.now
        },
        lastSync: {
            type: Date,
            default: Date.now
        }
    },
    status: {
        type: String,
        enum: ['pending', 'active', 'inactive', 'expired'],
        default: 'pending',
        index: true
    },
    encryption: {
        algorithm: {
            type: String,
            default: 'aes-256-gcm'
        },
        iv: String,
        authTag: String
    }
}, {
    timestamps: true
});

SessionSchema.index({ status: 1, 'metadata.lastActive': -1 });
SessionSchema.index({ phoneNumber: 1, status: 1 });

const Session = mongoose.model('Session', SessionSchema);

// ============================================
// CLEANUP OLD REMOTE AUTH DATA
// ============================================
async function cleanupOldRemoteAuthData(clientId) {
    try {
        console.log(`🧹 Cleaning up old RemoteAuth data for: ${clientId}`);
        
        // Delete from RemoteAuth collection
        const RemoteAuth = mongoose.connection.collection('RemoteAuth');
        const result = await RemoteAuth.deleteOne({ _id: clientId });
        
        if (result.deletedCount > 0) {
            console.log(`✅ Deleted old RemoteAuth data for: ${clientId}`);
        }
    } catch (error) {
        console.error(`⚠️  Failed to cleanup RemoteAuth data:`, error.message);
    }
}

// ============================================
// INITIALIZE WHATSAPP CLIENT FOR A USER
// ============================================
async function initializeAuthClient(clientId) {
    console.log(`🚀 Initializing client for: ${clientId}`);
    
    // Clean up any existing RemoteAuth data for this client
    await cleanupOldRemoteAuthData(clientId);
    
    const client = new Client({
        authStrategy: new RemoteAuth({
            clientId: clientId,
            store: mongoStore,
            backupSyncIntervalMs: 300000
        }),
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
                '--disable-gpu'
            ],
        },
        qrMaxRetries: 5
    });

    // Store client state
    const clientState = {
        client: client,
        qrCode: null,
        qrImage: null,
        status: 'initializing',
        sessionId: null,
        phoneNumber: null,
        createdAt: Date.now()
    };

    activeClients.set(clientId, clientState);

    // QR Code Generation
    client.on('qr', async (qr) => {
        console.log(`📱 QR RECEIVED for client: ${clientId}`);
        clientState.qrCode = qr;
        clientState.status = 'qr_ready';
        
        try {
            clientState.qrImage = await qrcode.toDataURL(qr);
            console.log(`✅ QR code generated and stored for: ${clientId}`);
        } catch (err) {
            console.error('❌ QR code generation failed:', err);
        }
    });

    // Authentication Success
    client.on('authenticated', () => {
        console.log(`🔐 Authentication Successful for: ${clientId}`);
        clientState.status = 'authenticated';
    });

    // Client Ready
    client.on('ready', async () => {
        console.log(`✅ CLIENT READY for: ${clientId}`);
        clientState.status = 'ready';

        try {
            const info = client.info;
            const phoneNumber = info.wid.user;
            const deviceName = info.pushname || 'Unknown Device';
            const platform = info.platform || 'web';

            const sessionId = `session_${phoneNumber}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
            
            clientState.sessionId = sessionId;
            clientState.phoneNumber = phoneNumber;

            console.log(`📞 Phone: ${phoneNumber}`);
            console.log(`🔑 Session ID: ${sessionId}`);

            const sessionData = {
                phoneNumber: phoneNumber,
                deviceName: deviceName,
                platform: platform,
                wid: info.wid,
                me: info.me,
                timestamp: new Date().toISOString(),
                remoteAuthPath: clientId
            };

            const serialized = JSON.stringify(sessionData);
            const encrypted = encryptData(serialized);

            await Session.create({
                sessionId: sessionId,
                phoneNumber: phoneNumber,
                authData: {
                    serialized: encrypted.encrypted,
                    remoteAuthPath: clientId
                },
                metadata: {
                    deviceName: deviceName,
                    platform: platform,
                    whatsappVersion: info.wwebVersion || 'unknown',
                    createdAt: new Date(),
                    lastActive: new Date(),
                    lastSync: new Date()
                },
                status: 'active',
                encryption: {
                    algorithm: 'aes-256-gcm',
                    iv: encrypted.iv,
                    authTag: encrypted.authTag
                }
            });

            console.log('💾 Session saved to MongoDB');

            await sendSessionIdToUser(client, phoneNumber, sessionId, deviceName);

            clientState.status = 'session_saved';

            // Cleanup after success
            setTimeout(async () => {
                console.log(`🧹 Cleaning up successful client: ${clientId}`);
                try {
                    await client.destroy();
                    activeClients.delete(clientId);
                } catch (err) {
                    console.error('Cleanup error:', err);
                }
            }, 30000);

        } catch (error) {
            console.error('❌ Failed to save session:', error);
            clientState.status = 'error';
        }
    });

    // Loading screen
    client.on('loading_screen', (percent, message) => {
        console.log(`⏳ Loading [${clientId}]: ${percent}% - ${message}`);
    });

    // Authentication Failure
    client.on('auth_failure', async (msg) => {
        console.error(`❌ Authentication Failed [${clientId}]:`, msg);
        clientState.status = 'auth_failed';
        
        // Cleanup on failure
        setTimeout(async () => {
            try {
                await client.destroy();
                activeClients.delete(clientId);
                await cleanupOldRemoteAuthData(clientId);
            } catch (err) {
                console.error('Cleanup error:', err);
            }
        }, 5000);
    });

    // Disconnected
    client.on('disconnected', (reason) => {
        console.log(`🔌 Client Disconnected [${clientId}]:`, reason);
        clientState.status = 'disconnected';
    });

    // Remote session saved
    client.on('remote_session_saved', () => {
        console.log(`💾 Remote session saved [${clientId}]`);
    });

    // Initialize client
    try {
        await client.initialize();
    } catch (error) {
        console.error(`❌ Failed to initialize client ${clientId}:`, error);
        clientState.status = 'error';
        activeClients.delete(clientId);
        throw error;
    }
    
    return clientId;
}

// ============================================
// SEND SESSION ID TO USER
// ============================================
async function sendSessionIdToUser(client, phoneNumber, sessionId, deviceName) {
    try {
        const chatId = `${phoneNumber}@c.us`;
        
        const message = `🎉 *WhatsApp Bot Authentication Successful!*

✅ Your bot session has been created and saved securely.

📋 *Session Details:*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔑 *Session ID:*
\`${sessionId}\`

📱 *Device:* ${deviceName}
📅 *Created:* ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 *Next Steps - Deploy Your Bot:*

1️⃣ Copy your Session ID above
2️⃣ Add it to your .env file:
   \`SESSION_ID=${sessionId}\`
3️⃣ Deploy your bot backend
4️⃣ Your bot will auto-connect!

⚠️ *Important:*
• Keep this Session ID SECRET
• Don't share it with anyone
• Store it safely in your .env file
• You can use this ID to deploy multiple bot instances

💡 *Need help?* Check the documentation or contact support.

Happy botting! 🤖✨`;

        await client.sendMessage(chatId, message);
        console.log(`✅ Session ID sent to user: ${phoneNumber}`);

    } catch (error) {
        console.error('❌ Failed to send session ID to user:', error);
    }
}

// ============================================
// CLEANUP STALE CLIENTS
// ============================================
function cleanupStaleClients() {
    const now = Date.now();
    const STALE_TIMEOUT = 5 * 60 * 1000; // 5 minutes

    for (const [clientId, clientState] of activeClients.entries()) {
        const age = now - clientState.createdAt;
        
        if (age > STALE_TIMEOUT && clientState.status !== 'session_saved') {
            console.log(`🧹 Removing stale client: ${clientId} (age: ${Math.floor(age/1000)}s)`);
            
            try {
                clientState.client.destroy();
            } catch (err) {
                console.error(`Error destroying stale client:`, err);
            }
            
            activeClients.delete(clientId);
        }
    }
}

// Run cleanup every 2 minutes
setInterval(cleanupStaleClients, 2 * 60 * 1000);

// ============================================
// API ROUTES
// ============================================

// Health Check
app.get('/api/health', (req, res) => {
    res.json({
        service: 'scanner',
        status: 'ok',
        activeClients: activeClients.size,
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Start New Authentication Session
app.post('/api/auth/start', async (req, res) => {
    if (isShuttingDown) {
        return res.status(503).json({
            success: false,
            message: 'Server is shutting down, please try again in a moment'
        });
    }

    // Limit concurrent authentications to prevent resource exhaustion
    if (activeClients.size >= 3) {
        return res.status(429).json({
            success: false,
            message: 'Too many active authentications. Please try again in a few minutes.'
        });
    }

    try {
        const clientId = `auth_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        
        console.log(`🆕 New auth request - Creating client: ${clientId}`);
        
        // Start initialization in background
        initializeAuthClient(clientId).catch(err => {
            console.error(`Failed to initialize ${clientId}:`, err);
            activeClients.delete(clientId);
        });
        
        res.json({
            success: true,
            message: 'Authentication started',
            clientId: clientId
        });
    } catch (error) {
        console.error('Failed to start auth:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to start authentication',
            error: error.message
        });
    }
});

// Reset Authentication
app.post('/api/auth/reset', async (req, res) => {
    try {
        console.log(`🔄 Reset requested - cleaning up ${activeClients.size} clients`);
        
        for (const [clientId, clientState] of activeClients.entries()) {
            try {
                await clientState.client.destroy();
                await cleanupOldRemoteAuthData(clientId);
            } catch (err) {
                console.error(`Error cleaning up ${clientId}:`, err);
            }
            activeClients.delete(clientId);
        }
        
        res.json({
            success: true,
            message: 'All sessions reset successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to reset',
            error: error.message
        });
    }
});

// Get QR Code
app.get('/api/qr/:clientId', (req, res) => {
    const { clientId } = req.params;
    const clientState = activeClients.get(clientId);

    if (!clientState) {
        return res.json({
            success: false,
            message: 'Session not found or expired',
            status: 'not_found'
        });
    }

    if (clientState.qrImage) {
        res.json({ 
            success: true, 
            qr: clientState.qrCode,
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

// Get Status
app.get('/api/status/:clientId', (req, res) => {
    const { clientId } = req.params;
    const clientState = activeClients.get(clientId);

    if (!clientState) {
        return res.json({
            status: 'not_found',
            message: 'Session not found or expired'
        });
    }

    res.json({
        status: clientState.status,
        hasQR: !!clientState.qrCode,
        sessionId: clientState.sessionId,
        phoneNumber: clientState.phoneNumber,
        message: getStatusMessage(clientState.status)
    });
});

// Get All Sessions
app.get('/api/sessions', async (req, res) => {
    try {
        const sessions = await Session.find({})
            .select('-authData.serialized')
            .sort({ 'metadata.createdAt': -1 })
            .limit(50);
        
        res.json({
            success: true,
            count: sessions.length,
            sessions: sessions
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Get Specific Session
app.get('/api/sessions/:sessionId', async (req, res) => {
    try {
        const session = await Session.findOne({ sessionId: req.params.sessionId })
            .select('-authData.serialized');
        
        if (!session) {
            return res.status(404).json({
                success: false,
                message: 'Session not found'
            });
        }

        res.json({
            success: true,
            session: session
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Verify Session
app.post('/api/sessions/verify', async (req, res) => {
    try {
        const { sessionId } = req.body;
        
        if (!sessionId) {
            return res.status(400).json({
                success: false,
                message: 'Session ID is required'
            });
        }

        const session = await Session.findOne({ sessionId, status: 'active' });
        
        if (session) {
            res.json({
                success: true,
                exists: true,
                phoneNumber: session.phoneNumber,
                deviceName: session.metadata.deviceName,
                createdAt: session.metadata.createdAt
            });
        } else {
            res.json({
                success: false,
                exists: false,
                message: 'Session not found or inactive'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Root Route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Helper Functions
function getStatusMessage(status) {
    const messages = {
        'initializing': 'Initializing WhatsApp client...',
        'qr_ready': 'QR code ready - scan with WhatsApp',
        'authenticated': 'Authenticated - extracting session...',
        'ready': 'Session data being saved...',
        'session_saved': 'Session saved! Check your WhatsApp for Session ID',
        'auth_failed': 'Authentication failed - please try again',
        'disconnected': 'Disconnected',
        'error': 'An error occurred',
        'not_found': 'Session not found or expired'
    };
    return messages[status] || 'Unknown status';
}

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 4000;

async function startServer() {
    try {
        if (!process.env.MONGODB_URI) {
            throw new Error('MONGODB_URI environment variable is required');
        }

        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB Connected');

        mongoStore = new MongoStore({ mongoose });
        console.log('✅ MongoDB Store initialized for RemoteAuth');

        app.listen(PORT, '0.0.0.0', () => {
            console.log('\n' + '='.repeat(60));
            console.log('🎉 SERVICE 1: MULTI-TENANT SCANNER STARTED');
            console.log('='.repeat(60));
            console.log(`📱 Server running on port: ${PORT}`);
            console.log(`🔌 Health: /api/health`);
            console.log('='.repeat(60) + '\n');
        });

    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();

// ============================================
// GRACEFUL SHUTDOWN
// ============================================
async function gracefulShutdown(signal) {
    console.log(`\n🛑 ${signal} received, shutting down gracefully...`);
    isShuttingDown = true;
    
    // Stop accepting new requests
    console.log('⏸️  Stopping new authentications...');
    
    // Destroy all active clients
    const cleanupPromises = [];
    for (const [clientId, clientState] of activeClients.entries()) {
        console.log(`🧹 Cleaning up client: ${clientId}`);
        cleanupPromises.push(
            clientState.client.destroy().catch(err => 
                console.error(`Error destroying ${clientId}:`, err)
            )
        );
    }
    
    await Promise.all(cleanupPromises);
    activeClients.clear();
    
    await mongoose.connection.close();
    console.log('✅ Shutdown complete');
    process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});