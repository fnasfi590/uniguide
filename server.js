import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import morgan from 'morgan';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { GoogleGenAI } from '@google/genai';
import { rateLimit } from 'express-rate-limit';
import { createServer } from 'http';
import { Server } from 'socket.io';

// Process-level error handling to prevent silent crashes
process.on('uncaughtException', (err) => {
  console.error('[CRITICAL] Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[CRITICAL] Unhandled Rejection at:', promise, 'reason:', reason);
});

dotenv.config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'uniguide_secret_key_123';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// Rate Limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.status(429).json({ 
      success: false, 
      message: 'Too many attempts, please try again later' 
    });
  },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  handler: (req, res) => {
    return res.status(429).json({ 
      success: false, 
      message: 'Too many accounts created, please try again later' 
    });
  },
});

// Database State
let db;

// Middleware to ensure DB is initialized
const ensureDB = (req, res, next) => {
  if (!db) {
    return res.status(503).json({ 
      success: false, 
      message: 'Database not initialized. Please try again in a few seconds.' 
    });
  }
  next();
};

// Middleware to guarantee a response and prevent hanging
const responseGuard = (req, res, next) => {
  // Set a 15-second timeout for every request
  const timeout = setTimeout(() => {
    if (!res.headersSent) {
      console.error(`[TIMEOUT] Request to ${req.method} ${req.url} timed out.`);
      res.status(504).json({
        success: false,
        message: 'Request timed out - the server took too long to respond.',
        error: 'Gateway Timeout'
      });
    }
  }, 15000);

  // Hook into res.json and res.send to clear the timeout
  const originalJson = res.json;
  const originalSend = res.send;

  res.json = function(data) {
    clearTimeout(timeout);
    return originalJson.call(this, data);
  };

  res.send = function(data) {
    clearTimeout(timeout);
    return originalSend.call(this, data);
  };

  next();
};

// Middleware
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(cors());
app.use(morgan('dev'));

// Debug middleware to check body parsing
app.use((req, res, next) => {
  console.log(`[DEBUG] Incoming ${req.method} ${req.url} - Content-Type: ${req.headers['content-type']}`);
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  if (req.method === 'POST' || req.method === 'PUT') {
    console.log(`[DEBUG] Body after parsing:`, req.body);
  }
  next();
});

// Ping route before DB check
app.get('/api/ping', (req, res) => {
  return res.json({ success: true, message: 'pong', timestamp: new Date() });
});

app.use(responseGuard);
app.use(ensureDB);

// Request logging middleware for debugging empty responses
app.use((req, res, next) => {
  const startTime = Date.now();
  
  // Hook into res.end to log the final status and timing
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const duration = Date.now() - startTime;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - ${res.statusCode} (${duration}ms)`);
    return originalEnd.call(this, chunk, encoding);
  };

  const oldJson = res.json;
  res.json = function(data) {
    try {
      const dataStr = JSON.stringify(data);
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - JSON Data:`, dataStr.substring(0, 100) + '...');
    } catch (e) {
      console.warn(`[LOG ERROR] Could not stringify response for logging:`, e.message);
    }
    return oldJson.call(this, data);
  };
  next();
});

// Database Initialization
const initDB = async () => {
  try {
    db = await open({
      filename: './database.sqlite',
      driver: sqlite3.Database
    });
    console.log("Database connected successfully");
  } catch (error) {
    console.error("Database connection failed:", error);
    throw error;
  }

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      department TEXT,
      avatar TEXT,
      isOnline BOOLEAN DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      senderId TEXT NOT NULL,
      receiverId TEXT NOT NULL,
      text TEXT NOT NULL,
      isAnonymous BOOLEAN DEFAULT 0,
      attachment TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS call_logs (
      id TEXT PRIMARY KEY,
      callerId TEXT,
      receiverId TEXT,
      type TEXT,
      status TEXT,
      duration INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(callerId) REFERENCES users(id),
      FOREIGN KEY(receiverId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS reset_tokens (
      email TEXT PRIMARY KEY,
      token TEXT NOT NULL,
      expiresAt DATETIME NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(senderId);
    CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiverId);
    CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(senderId, receiverId);
  `);

  const userCount = await db.get('SELECT COUNT(*) as count FROM users');
  if (userCount.count === 0) {
    const hashedZied = await bcrypt.hash('zied1234@', 10);
    const hashedFarouk = await bcrypt.hash('farouk1234@', 10);

    await db.run(`
      INSERT INTO users (id, name, email, password, role, department, avatar, isOnline)
      VALUES 
      ('p_zied', 'Zied Benhamad', 'zied.benhamad@apac.tn', ?, 'PROFESSOR', 'Computer Science', 'https://ui-avatars.com/api/?name=Zied+Benhamad&background=7c3aed&color=fff', 1),
      ('s_farouk', 'Farouk Nasfi', 'farouk.nasfi@apac.tn', ?, 'STUDENT', 'Software Engineering', 'https://ui-avatars.com/api/?name=Farouk+Nasfi&background=0ea5e9&color=fff', 1)
    `, [hashedZied, hashedFarouk]);
  }
};

// Socket.IO logic
io.on('connection', (socket) => {
  console.log(`Socket connection established: ${socket.id}`);

  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their notification room (Socket: ${socket.id})`);
  });

  socket.on('disconnect', (reason) => {
    console.log(`Socket disconnected: ${socket.id} (Reason: ${reason})`);
  });

  socket.on('send_message', async (data) => {
    const { tempId, senderId, receiverId, text, isAnonymous, attachment } = data;
    const messageId = crypto.randomUUID();
    
    try {
      // Persist to DB
      await db.run(
        'INSERT INTO messages (id, senderId, receiverId, text, isAnonymous, attachment) VALUES (?, ?, ?, ?, ?, ?)',
        [messageId, senderId, receiverId, text, isAnonymous ? 1 : 0, attachment ? JSON.stringify(attachment) : null]
      );

      const messageToSend = {
        id: messageId,
        tempId,
        senderId: isAnonymous ? 'anonymous' : senderId,
        realSenderId: senderId, // Hidden for UI, used for session matching
        receiverId,
        text,
        attachment,
        timestamp: new Date(),
        isAnonymous
      };

      // Emit to receiver
      io.to(receiverId).emit('receive_message', messageToSend);
      // Also emit back to sender to confirm display
      io.to(senderId).emit('message_sent', messageToSend);
      
      console.log(`Message from ${senderId} to ${receiverId} sent. ID: ${messageId}`);
    } catch (err) {
      console.error("Message persistence error:", err);
    }
  });
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication token required',
        error: 'Unauthorized'
      });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        console.warn(`[AUTH] Invalid token attempt: ${err.message}`);
        return res.status(403).json({ 
          success: false, 
          message: 'Invalid or expired token',
          error: 'Forbidden'
        });
      }
      req.user = user;
      next();
    });
  } catch (error) {
    console.error('[AUTH] Critical middleware error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Authentication service error',
      error: 'Internal Server Error'
    });
  }
};

// Routes
app.get('/api/health', (req, res) => {
  return res.json({ success: true, message: 'Server is healthy' });
});

app.get('/api/messages/:partnerId', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { partnerId } = req.params;

    const messages = await db.all(`
      SELECT * FROM messages 
      WHERE (senderId = ? AND receiverId = ?) 
         OR (senderId = ? AND receiverId = ?)
      ORDER BY timestamp ASC
    `, [userId, partnerId, partnerId, userId]);

    const sanitizedMessages = messages.map(m => ({
      ...m,
      realSenderId: m.senderId,
      senderId: (m.isAnonymous && m.senderId !== userId) ? 'anonymous' : m.senderId,
      isAnonymous: !!m.isAnonymous,
      attachment: m.attachment ? JSON.parse(m.attachment) : undefined
    }));

    return res.json({ success: true, data: sanitizedMessages });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login/professor', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.role !== 'PROFESSOR') return res.status(403).json({ success: false, message: 'Access denied' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ success: false, message: 'Invalid password' });
    
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    const { password: _, ...userWithoutPassword } = user;
    return res.json({ success: true, data: { user: userWithoutPassword, token } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });

    const user = await db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ success: false, message: 'Invalid password' });
    
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    const { password: _, ...userWithoutPassword } = user;
    return res.json({ success: true, data: { user: userWithoutPassword, token } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/register', registerLimiter, async (req, res, next) => {
  try {
    const { name, email, password, role, department } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ success: false, message: 'Missing required fields' });

    // Email validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@apac\.tn$/;
    if (!emailRegex.test(email.toLowerCase())) {
      return res.status(400).json({ success: false, message: 'Email must be a valid @apac.tn address' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=${role === 'STUDENT' ? '0ea5e9' : '7c3aed'}&color=fff`;
    await db.run('INSERT INTO users (id, name, email, password, role, department, avatar) VALUES (?, ?, ?, ?, ?, ?, ?)', [id, name, email.toLowerCase(), hashedPassword, role, department, avatar]);
    const token = jwt.sign({ id, role }, JWT_SECRET, { expiresIn: '24h' });
    return res.status(201).json({ 
      success: true, 
      data: { user: { id, name, email, role, department, avatar }, token } 
    });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) return res.status(400).json({ success: false, message: 'Email already exists' });
    next(error);
  }
});

app.post('/api/auth/reset-password/request', async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });

    const user = await db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) return res.json({ success: true, message: 'Reset code generated if email exists.' });
    const token = Math.random().toString(36).substring(2, 8).toUpperCase();
    const expiresAt = new Date(Date.now() + 3600000);
    await db.run('INSERT OR REPLACE INTO reset_tokens (email, token, expiresAt) VALUES (?, ?, ?)', [email.toLowerCase(), token, expiresAt.toISOString()]);
    return res.json({ success: true, message: 'Reset code generated.', debug_token: token });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/reset-password/confirm', async (req, res, next) => {
  try {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword) return res.status(400).json({ success: false, message: 'Missing required fields' });

    const record = await db.get('SELECT * FROM reset_tokens WHERE email = ? AND token = ?', [email.toLowerCase(), token]);
    if (!record || new Date(record.expiresAt) < new Date()) return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.run('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email.toLowerCase()]);
    await db.run('DELETE FROM reset_tokens WHERE email = ?', [email.toLowerCase()]);
    return res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/contacts', authenticateToken, async (req, res, next) => {
  try {
    const targetRole = req.user.role === 'STUDENT' ? 'PROFESSOR' : 'STUDENT';
    let contacts = await db.all('SELECT id, name, email, role, department, avatar, isOnline FROM users WHERE role = ? AND id != ?', [targetRole, req.user.id]);
    if (req.user.role === 'STUDENT') {
      contacts = contacts.map(c => ({ ...c, name: 'Professeur', avatar: `https://ui-avatars.com/api/?name=P&background=9ca3af&color=fff` }));
    }
    return res.json({ success: true, data: contacts });
  } catch (error) {
    next(error);
  }
});

app.post('/api/ai/chat', authenticateToken, async (req, res, next) => {
  try {
    const { message, systemInstruction } = req.body;
    
    // Return error if API key is missing or placeholder instead of fallback message
    if (!GEMINI_API_KEY || GEMINI_API_KEY === 'PLACEHOLDER_API_KEY' || GEMINI_API_KEY.includes('YOUR_API_KEY')) {
      console.warn("Gemini API Key missing, AI chat disabled");
      return res.status(503).json({ 
        success: false, 
        message: 'AI service currently unavailable'
      });
    }

    const genAI = new GoogleGenAI(GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash", systemInstruction });
    const result = await model.generateContent(message);
    const response = await result.response;
    return res.json({ success: true, data: { text: response.text() } });
  } catch (error) {
    next(error);
  }
});

// 404 Handler
app.use((req, res) => {
  console.warn(`[404] Route not found: ${req.method} ${req.url}`);
  return res.status(404).json({ 
    success: false, 
    message: `Route ${req.originalUrl} not found`,
    error: 'Not Found'
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  // If headers already sent, delegate to default express error handler
  if (res.headersSent) {
    return next(err);
  }

  console.error(`[500] Error at ${req.method} ${req.url}:`, err);
  
  return res.status(500).json({ 
    success: false, 
    message: 'An unexpected error occurred on the server',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal Server Error'
  });
});

// Start Server after DB Init
const start = async () => {
  try {
    await initDB();
    
    httpServer.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`[CRITICAL] Port ${PORT} is already in use. Please kill the process using this port or change it in .env`);
      } else {
        console.error('[CRITICAL] Server error:', err);
      }
      process.exit(1);
    });

    httpServer.listen(PORT, '0.0.0.0', () => {
      console.log(`[READY] Server running on http://0.0.0.0:${PORT}`);
      console.log(`[INFO] Environment: ${process.env.NODE_ENV || 'development'}`);
    });

    // Handle idle connections to prevent "Empty response"
    httpServer.keepAliveTimeout = 61000;
    httpServer.headersTimeout = 62000;
  } catch (err) {
    console.error("[CRITICAL] Failed to start server:", err);
    process.exit(1);
  }
};

start();
