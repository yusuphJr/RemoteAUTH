// ============================================
// SERVICE 1: MULTI-TENANT SCANNER SERVICE
// Render Deployment Version
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

// Store multiple client instances (one per authentication session)
const activeClients = new Map();

let mongoStore = null;

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
// INITIALIZE WHATSAPP CLIENT FOR A USER
// ============================================
async function initializeAuthClient(clientId) {
    console.log(`🚀 Initializing client for: ${clientId}`);
    
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
        }
    });

    // Store client state
    const clientState = {
        client: client,
        qrCode: null,
        qrImage: null,
        status: 'initializing',
        sessionId: null,
        phoneNumber: null
    };

    activeClients.set(clientId, clientState);

    // QR Code Generation
    client.on('qr', async (qr) => {
        console.log(`📱 QR RECEIVED for client: ${clientId}`);
        clientState.qrCode = qr;
        clientState.status = 'qr_ready';
        
        try {
            clientState.qrImage = await qrcode.toDataURL(qr);
            console.log('✅ QR code generated successfully');
        } catch (err) {
            console.error('❌ QR code generation failed:', err);
        }
    });

    // Authentication Success
    client.on('authenticated', () => {
        console.log(`🔐 Authentication Successful for: ${clientId}`);
        clientState.status = 'authenticated';
    });

    // Client Ready - Save Session and Send ID to User
    client.on('ready', async () => {
        console.log(`✅ CLIENT READY for: ${clientId}`);
        clientState.status = 'ready';

        try {
            const info = client.info;
            const phoneNumber = info.wid.user;
            const deviceName = info.pushname || 'Unknown Device';
            const platform = info.platform || 'web';

            // Generate unique session ID
            const sessionId = `session_${phoneNumber}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
            
            clientState.sessionId = sessionId;
            clientState.phoneNumber = phoneNumber;

            console.log(`📞 Phone: ${phoneNumber}`);
            console.log(`🔑 Session ID: ${sessionId}`);

            // Serialize session data
            const sessionData = {
                phoneNumber: phoneNumber,
                deviceName: deviceName,
                platform: platform,
                wid: info.wid,
                me: info.me,
                timestamp: new Date().toISOString(),
                remoteAuthPath: clientId
            };

            // Encrypt session data
            const serialized = JSON.stringify(sessionData);
            const encrypted = encryptData(serialized);

            // Save to MongoDB
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

            // SEND SESSION ID TO USER'S WHATSAPP
            await sendSessionIdToUser(client, phoneNumber, sessionId, deviceName);

            clientState.status = 'session_saved';

            // Cleanup after 30 seconds
            setTimeout(async () => {
                console.log(`🧹 Cleaning up client: ${clientId}`);
                await client.destroy();
                activeClients.delete(clientId);
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
    await client.initialize();
    
    return clientId;
}

// ============================================
// SEND SESSION ID TO USER VIA WHATSAPP
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
        console.log(`📧 Message delivered successfully`);

    } catch (error) {
        console.error('❌ Failed to send session ID to user:', error);
        console.log('💡 User will need to get session ID from API or logs');
    }
}

// ============================================
// API ROUTES
// ============================================

// Health Check
app.get('/api/health', (req, res) => {
    res.json({
        service: 'scanner',
        status: 'ok',
        activeClients: activeClients.size,
        timestamp: new Date().toISOString()
    });
});

// Start New Authentication Session
app.post('/api/auth/start', async (req, res) => {
    // Destroy any existing clients to prevent Puppeteer crashes
    for (const [clientId, clientState] of activeClients.entries()) {
        console.log(`🧹 Destroying previous client: ${clientId}`);
        try {
            await clientState.client.destroy();
        } catch (err) {
            console.error(`Error destroying client ${clientId}:`, err);
        }
        activeClients.delete(clientId);
    }

    try {
        // Generate unique client ID for this auth session
        const clientId = `auth_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        
        await initializeAuthClient(clientId);
        
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
        // Destroy all active clients
        for (const [clientId, clientState] of activeClients.entries()) {
            await clientState.client.destroy();
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

// Get QR Code for Client
app.get('/api/qr/:clientId', (req, res) => {
    const { clientId } = req.params;
    const clientState = activeClients.get(clientId);

    if (!clientState) {
        return res.json({
            success: false,
            message: 'Client session not found or expired',
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

// Get Status for Client
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

// Get All Sessions from DB
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

// Get Specific Session Info by Session ID
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

// Verify Session Exists (for backend to check before starting)
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

// ============================================
// HELPER FUNCTIONS
// ============================================
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
        // Validate required environment variables
        if (!process.env.MONGODB_URI) {
            throw new Error('MONGODB_URI environment variable is required');
        }

        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB Connected');

        // Initialize MongoStore for RemoteAuth
        mongoStore = new MongoStore({ mongoose });
        console.log('✅ MongoDB Store initialized for RemoteAuth');

        // Start Express Server
        app.listen(PORT, '0.0.0.0', () => {
            console.log('\n' + '='.repeat(60));
            console.log('🎉 SERVICE 1: MULTI-TENANT SCANNER STARTED');
            console.log('='.repeat(60));
            console.log(`📱 Server running on port: ${PORT}`);
            console.log(`🔌 API: http://localhost:${PORT}/api`);
            console.log('='.repeat(60));
            console.log('\n📋 Multi-Tenant Features:');
            console.log('   ✓ Multiple users can authenticate simultaneously');
            console.log('   ✓ Each user gets unique Session ID');
            console.log('   ✓ Session ID sent to user\'s WhatsApp inbox');
            console.log('   ✓ Users deploy their own backend with Session ID');
            console.log('   ✓ All sessions stored in MongoDB\n');
        });

    } catch (error) {
        console.error('❌ Failed to start server:', error);
        console.log('💡 Check your MONGODB_URI in environment variables');
        process.exit(1);
    }
}

startServer();

// ============================================
// GRACEFUL SHUTDOWN
// ============================================
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down Scanner Service...');
    
    // Destroy all active clients
    for (const [clientId, clientState] of activeClients.entries()) {
        try {
            await clientState.client.destroy();
            console.log(`✅ Cleaned up client: ${clientId}`);
        } catch (error) {
            console.error(`Failed to cleanup ${clientId}:`, error);
        }
    }
    
    await mongoose.connection.close();
    console.log('✅ Shutdown complete');
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 SIGTERM received, shutting down gracefully...');
    
    for (const [clientId, clientState] of activeClients.entries()) {
        try {
            await clientState.client.destroy();
        } catch (error) {
            console.error(`Failed to cleanup ${clientId}:`, error);
        }
    }
    
    await mongoose.connection.close();
    process.exit(0);
});