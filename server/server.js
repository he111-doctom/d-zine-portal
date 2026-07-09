'use strict';

const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const morgan       = require('morgan');
const compression  = require('compression');
const path         = require('path');
const { Sequelize, DataTypes, Op } = require('sequelize');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const rateLimit    = require('express-rate-limit');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 5000;
const isProd = process.env.NODE_ENV === 'production';

// ============================================
// SECURITY MIDDLEWARE
// ============================================
app.set('trust proxy', 1);

app.use(helmet({
    contentSecurityPolicy: false, // Relax for HTML client pages served separately
    crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// CORS — restrict in production to your real domain
const allowedOrigins = isProd
    ? (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean)
    : ['http://localhost:5500', 'http://127.0.0.1:5500',
       'http://localhost:5501', 'http://127.0.0.1:5501',
       'http://localhost:3000'];

app.use(cors({
    origin: (origin, cb) => {
        // Allow requests with no origin (Postman, curl, same-origin)
        if (!origin || !isProd) return cb(null, true);
        if (allowedOrigins.includes(origin)) return cb(null, true);
        return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 20,
    message: { error: 'Too many requests. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 min
    max: 120,
    message: { error: 'Too many requests. Please slow down.' }
});

app.use('/api/auth', authLimiter);
app.use('/api',      apiLimiter);

app.use(compression());
app.use(morgan(isProd ? 'combined' : 'dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    maxAge: isProd ? '7d' : 0
}));

// ============================================
// DATABASE
// ============================================
const sequelize = new Sequelize(
    process.env.DB_NAME     || 'dzine_portal',
    process.env.DB_USER     || 'root',
    process.env.DB_PASSWORD || '',
    {
        host:    process.env.DB_HOST || 'localhost',
        port:    parseInt(process.env.DB_PORT || '3306'),
        dialect: 'mysql',
        logging: false,
        pool: { max: 10, min: 0, acquire: 30000, idle: 10000 },
        define:  { underscored: true }
    }
);

// ============================================
// MODELS
// ============================================
const User = sequelize.define('User', {
    id:           { type: DataTypes.INTEGER,  primaryKey: true, autoIncrement: true },
    email:        { type: DataTypes.STRING(255), allowNull: false, unique: true,
                    validate: { isEmail: true } },
    password_hash:{ type: DataTypes.STRING(255), allowNull: false },
    full_name:    { type: DataTypes.STRING(255), allowNull: false,
                    validate: { len: [1, 255] } },
    company_name: { type: DataTypes.STRING(255), defaultValue: '' },
    role:         { type: DataTypes.ENUM('client', 'admin', 'studio'), defaultValue: 'client' },
    is_active:    { type: DataTypes.BOOLEAN, defaultValue: true },
    last_login:   { type: DataTypes.DATE, allowNull: true }
}, { tableName: 'users', timestamps: true, underscored: true });

const Project = sequelize.define('Project', {
    id:                   { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    client_id:            { type: DataTypes.INTEGER, allowNull: false },
    project_name:         { type: DataTypes.STRING(255), allowNull: false },
    project_description:  { type: DataTypes.TEXT },
    status:               { type: DataTypes.ENUM('pending', 'active', 'completed', 'archived'), defaultValue: 'active' },
    current_stage:        { type: DataTypes.STRING(50), defaultValue: 'questionnaire' },
    progress_percentage:  { type: DataTypes.INTEGER, defaultValue: 0 },
    start_date:           { type: DataTypes.DATE },
    completion_date:      { type: DataTypes.DATE }
}, { tableName: 'projects', timestamps: true, underscored: true });

// ============================================
// HELPERS
// ============================================
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'your_super_secret_key_change_this') {
    if (isProd) {
        console.error('❌ FATAL: JWT_SECRET is not set to a secure value. Refusing to start in production.');
        process.exit(1);
    } else {
        console.warn('⚠️  WARNING: JWT_SECRET is using a default value. Change it before deploying!');
    }
}
const SECRET = JWT_SECRET || 'dzine-dev-secret-NOT-FOR-PROD';

function signToken(payload) {
    return jwt.sign(payload, SECRET, { expiresIn: process.env.JWT_EXPIRE || '7d' });
}

function safeUser(user) {
    const obj = user.toJSON ? user.toJSON() : { ...user };
    delete obj.password_hash;
    return obj;
}

// Auth middleware
async function requireAuth(req, res, next) {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '').trim();
        if (!token) return res.status(401).json({ error: 'Authentication required' });
        req.decoded = jwt.verify(token, SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

async function requireAdmin(req, res, next) {
    await requireAuth(req, res, async () => {
        const admin = await User.findByPk(req.decoded.id);
        if (!admin || admin.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        req.admin = admin;
        next();
    });
}

// Input sanitiser
function sanitize(str, maxLen = 255) {
    if (typeof str !== 'string') return '';
    return str.trim().slice(0, maxLen);
}

// ============================================
// AUTH ROUTES
// ============================================

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const email    = sanitize((req.body.email || '').toLowerCase());
        const password = req.body.password || '';

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.is_active) {
            return res.status(403).json({ error: 'Account is inactive. Contact support.' });
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login (non-blocking)
        user.update({ last_login: new Date() }).catch(() => {});

        const token = signToken({ id: user.id, email: user.email, role: user.role });

        res.json({ message: 'Login successful', token, user: safeUser(user) });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    try {
        const email        = sanitize((req.body.email || '').toLowerCase());
        const password     = req.body.password || '';
        const full_name    = sanitize(req.body.full_name || req.body.name || '');
        const company_name = sanitize(req.body.company_name || '');

        // Validation
        if (!email || !password || !full_name) {
            return res.status(400).json({ error: 'Full name, email and password are required' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email address' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        if (password.length > 128) {
            return res.status(400).json({ error: 'Password too long' });
        }

        const existing = await User.findOne({ where: { email } });
        if (existing) {
            return res.status(409).json({ error: 'This email is already registered' });
        }

        const password_hash = await bcrypt.hash(password, 12);

        const user = await User.create({ email, password_hash, full_name, company_name, role: 'client' });

        const token = signToken({ id: user.id, email: user.email, role: user.role });

        res.status(201).json({ message: 'Registration successful', token, user: safeUser(user) });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.decoded.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(safeUser(user));
    } catch {
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', async (req, res) => {
    let dbOk = false;
    try { await sequelize.authenticate(); dbOk = true; } catch {}
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: dbOk ? 'Connected ✅' : 'Disconnected ❌'
    });
});

// ============================================
// PROJECTS ROUTES
// ============================================
app.get('/api/projects', requireAuth, async (req, res) => {
    try {
        const where = req.decoded.role === 'admin' ? {} : { client_id: req.decoded.id };
        const projects = await Project.findAll({ where, order: [['created_at', 'DESC']] });
        res.json(projects);
    } catch { res.status(500).json({ error: 'Failed to fetch projects' }); }
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const project = await Project.findByPk(req.params.id);
        if (!project) return res.status(404).json({ error: 'Project not found' });
        // Clients can only see their own projects
        if (req.decoded.role === 'client' && project.client_id !== req.decoded.id) {
            return res.status(403).json({ error: 'Access denied' });
        }
        res.json(project);
    } catch { res.status(500).json({ error: 'Failed to fetch project' }); }
});

app.get('/api/projects/:id/stages', requireAuth, async (req, res) => {
    try {
        const stages = await sequelize.query(
            `SELECT stage_key, stage_name, status, order_index
             FROM project_stages WHERE project_id = ? ORDER BY order_index`,
            { replacements: [req.params.id], type: sequelize.QueryTypes.SELECT }
        );
        const obj = {};
        stages.forEach(s => { obj[s.stage_key] = s.status; });
        res.json(obj);
    } catch { res.status(500).json({ error: 'Failed to fetch stages' }); }
});

// ============================================
// QUESTIONNAIRE ROUTES
// ============================================
app.get('/api/questionnaire/:projectId', requireAuth, async (req, res) => {
    try {
        const rows = await sequelize.query(
            `SELECT question_index, answer_value, is_submitted
             FROM questionnaires WHERE project_id = ? ORDER BY question_index`,
            { replacements: [req.params.projectId], type: sequelize.QueryTypes.SELECT }
        );
        res.json(rows);
    } catch { res.status(500).json({ error: 'Failed to fetch questionnaire' }); }
});

app.post('/api/questionnaire/:projectId', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { answers } = req.body;
        if (!Array.isArray(answers)) return res.status(400).json({ error: 'answers must be an array' });

        for (let i = 0; i < answers.length; i++) {
            await sequelize.query(
                `UPDATE questionnaires SET answer_value = ? WHERE project_id = ? AND question_index = ?`,
                { replacements: [String(answers[i] || '').slice(0, 5000), projectId, i], type: sequelize.QueryTypes.UPDATE }
            );
        }
        res.json({ message: 'Questionnaire saved' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/questionnaire/:projectId/submit', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { answers } = req.body;
        if (!Array.isArray(answers)) return res.status(400).json({ error: 'answers must be an array' });

        for (let i = 0; i < answers.length; i++) {
            await sequelize.query(
                `UPDATE questionnaires SET answer_value = ?, is_submitted = TRUE WHERE project_id = ? AND question_index = ?`,
                { replacements: [String(answers[i] || '').slice(0, 5000), projectId, i], type: sequelize.QueryTypes.UPDATE }
            );
        }
        await sequelize.query(
            `UPDATE project_stages SET status = 'approved' WHERE project_id = ? AND stage_key = 'questionnaire'`,
            { replacements: [projectId], type: sequelize.QueryTypes.UPDATE }
        );
        await sequelize.query(
            `UPDATE project_stages SET status = 'pending' WHERE project_id = ? AND stage_key = 'color'`,
            { replacements: [projectId], type: sequelize.QueryTypes.UPDATE }
        );
        res.json({ message: 'Questionnaire submitted' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================
// COLOR ROUTES
// ============================================
app.get('/api/color/:projectId', requireAuth, async (req, res) => {
    try {
        const [row] = await sequelize.query(
            `SELECT * FROM color_selections WHERE project_id = ?`,
            { replacements: [req.params.projectId], type: sequelize.QueryTypes.SELECT }
        );
        res.json(row || { exists: false });
    } catch { res.status(500).json({ error: 'Failed to fetch colors' }); }
});

app.post('/api/color/:projectId', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { primary, secondary, accent, neutral } = req.body;
        const [existing] = await sequelize.query(
            `SELECT id FROM color_selections WHERE project_id = ?`,
            { replacements: [projectId], type: sequelize.QueryTypes.SELECT }
        );
        if (existing) {
            await sequelize.query(
                `UPDATE color_selections SET primary_color=?,secondary_color=?,accent_color=?,neutral_color=? WHERE project_id=?`,
                { replacements: [primary, secondary, accent, neutral, projectId], type: sequelize.QueryTypes.UPDATE }
            );
        } else {
            await sequelize.query(
                `INSERT INTO color_selections (project_id,primary_color,secondary_color,accent_color,neutral_color) VALUES (?,?,?,?,?)`,
                { replacements: [projectId, primary, secondary, accent, neutral], type: sequelize.QueryTypes.INSERT }
            );
        }
        res.json({ message: 'Colors saved' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/color/:projectId/approve', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        await sequelize.query(`UPDATE color_selections SET is_approved=TRUE WHERE project_id=?`,
            { replacements: [projectId], type: sequelize.QueryTypes.UPDATE });
        await sequelize.query(`UPDATE project_stages SET status='approved' WHERE project_id=? AND stage_key='color'`,
            { replacements: [projectId], type: sequelize.QueryTypes.UPDATE });
        await sequelize.query(`UPDATE project_stages SET status='pending' WHERE project_id=? AND stage_key='logo'`,
            { replacements: [projectId], type: sequelize.QueryTypes.UPDATE });
        res.json({ message: 'Colors approved' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================
// LOGO ROUTES
// ============================================
app.get('/api/logo/:projectId', requireAuth, async (req, res) => {
    try {
        const logos = await sequelize.query(
            `SELECT * FROM logo_designs WHERE project_id=? ORDER BY concept_index`,
            { replacements: [req.params.projectId], type: sequelize.QueryTypes.SELECT }
        );
        res.json(logos);
    } catch { res.status(500).json({ error: 'Failed to fetch logos' }); }
});

app.post('/api/logo/:projectId/feedback', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { conceptIndex, feedback } = req.body;
        await sequelize.query(
            `UPDATE logo_designs SET feedback=? WHERE project_id=? AND concept_index=?`,
            { replacements: [String(feedback || '').slice(0, 2000), projectId, conceptIndex], type: sequelize.QueryTypes.UPDATE }
        );
        res.json({ message: 'Feedback saved' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logo/:projectId/approve', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { conceptIndex } = req.body;
        await sequelize.query(`UPDATE logo_designs SET is_approved=TRUE WHERE project_id=? AND concept_index=?`,
            { replacements: [projectId, conceptIndex], type: sequelize.QueryTypes.UPDATE });
        await sequelize.query(`UPDATE project_stages SET status='approved' WHERE project_id=? AND stage_key='logo'`,
            { replacements: [projectId], type: sequelize.QueryTypes.UPDATE });
        await sequelize.query(`UPDATE project_stages SET status='pending' WHERE project_id=? AND stage_key='menu'`,
            { replacements: [projectId], type: sequelize.QueryTypes.UPDATE });
        res.json({ message: 'Logo approved' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logo/:projectId/reset', requireAuth, async (req, res) => {
    try {
        await sequelize.query(`UPDATE logo_designs SET is_approved=0 WHERE project_id=?`,
            { replacements: [req.params.projectId], type: sequelize.QueryTypes.UPDATE });
        res.json({ message: 'Logos reset' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================
// UPLOADS ROUTES
// ============================================
const VALID_STAGE_KEYS = ['menu','brochure','social','packaging','deliverables'];

app.get('/api/uploads/:projectId/:key', requireAuth, async (req, res) => {
    try {
        const uploads = await sequelize.query(
            `SELECT * FROM uploads WHERE project_id=? AND upload_key=?`,
            { replacements: [req.params.projectId, req.params.key], type: sequelize.QueryTypes.SELECT }
        );
        res.json(uploads);
    } catch { res.status(500).json({ error: 'Failed to fetch uploads' }); }
});

app.post('/api/uploads/:projectId', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { uploadKey, fileName, filePath, fileType, fileSize } = req.body;
        await sequelize.query(
            `INSERT INTO uploads (project_id,upload_key,file_name,file_path,file_type,file_size) VALUES (?,?,?,?,?,?)`,
            { replacements: [projectId, uploadKey, sanitize(fileName), sanitize(filePath), sanitize(fileType), parseInt(fileSize)||0], type: sequelize.QueryTypes.INSERT }
        );
        res.json({ message: 'File record saved' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/uploads/:uploadId', requireAuth, async (req, res) => {
    try {
        await sequelize.query(`DELETE FROM uploads WHERE id=?`,
            { replacements: [req.params.uploadId], type: sequelize.QueryTypes.DELETE });
        res.json({ message: 'File deleted' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/uploads/:projectId/:stageKey/approve', requireAuth, async (req, res) => {
    try {
        const { projectId, stageKey } = req.params;
        if (!VALID_STAGE_KEYS.includes(stageKey)) {
            return res.status(400).json({ error: 'Invalid stage key' });
        }
        await sequelize.query(
            `UPDATE project_stages SET status='approved' WHERE project_id=? AND stage_key=?`,
            { replacements: [projectId, stageKey], type: sequelize.QueryTypes.UPDATE }
        );
        const nextStageMap = { menu:'brochure', brochure:'social', social:'packaging', packaging:'deliverables' };
        const next = nextStageMap[stageKey];
        if (next) {
            await sequelize.query(`UPDATE project_stages SET status='pending' WHERE project_id=? AND stage_key=?`,
                { replacements: [projectId, next], type: sequelize.QueryTypes.UPDATE });
        }
        res.json({ message: `${stageKey} approved` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================
// ADMIN ROUTES
// ============================================
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({ attributes: { exclude: ['password_hash'] }, order: [['created_at', 'DESC']] });
        res.json(users);
    } catch { res.status(500).json({ error: 'Failed to fetch users' }); }
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const { full_name, email, password, company_name, is_active } = req.body;
        const cleanEmail = sanitize((email || '').toLowerCase());

        if (!full_name || !cleanEmail || !password) {
            return res.status(400).json({ error: 'Name, email and password are required' });
        }
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

        const existing = await User.findOne({ where: { email: cleanEmail } });
        if (existing) return res.status(409).json({ error: 'Email already registered' });

        const password_hash = await bcrypt.hash(password, 12);
        const user = await User.create({
            full_name: sanitize(full_name), email: cleanEmail, password_hash,
            company_name: sanitize(company_name || ''), role: 'client',
            is_active: is_active !== undefined ? !!is_active : true
        });
        res.status(201).json(safeUser(user));
    } catch (e) {
        console.error('Admin create user error:', e);
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
        const { full_name, email, company_name, is_active, password } = req.body;
        const user = await User.findByPk(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const updateData = {
            full_name:    sanitize(full_name    || user.full_name),
            email:        sanitize((email || user.email).toLowerCase()),
            company_name: sanitize(company_name !== undefined ? company_name : user.company_name),
            is_active:    is_active !== undefined ? !!is_active : user.is_active
        };

        if (password && password.length >= 6) {
            updateData.password_hash = await bcrypt.hash(password, 12);
        }

        await user.update(updateData);
        res.json(safeUser(user));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
        if (parseInt(req.params.id) === req.admin.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }
        const user = await User.findByPk(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        await user.destroy();
        res.json({ message: 'User deleted' });
    } catch { res.status(500).json({ error: 'Failed to delete user' }); }
});

app.get('/api/admin/projects', requireAdmin, async (req, res) => {
    try {
        const projects = await sequelize.query(
            `SELECT p.*, u.full_name AS client_name, u.company_name
             FROM projects p LEFT JOIN users u ON p.client_id = u.id
             ORDER BY p.created_at DESC`,
            { type: sequelize.QueryTypes.SELECT }
        );
        res.json(projects);
    } catch { res.status(500).json({ error: 'Failed to fetch projects' }); }
});

// Admin create project for a client
app.post('/api/admin/projects', requireAdmin, async (req, res) => {
    try {
        const { client_id, project_name, project_description } = req.body;
        if (!client_id || !project_name) {
            return res.status(400).json({ error: 'client_id and project_name are required' });
        }
        const project = await Project.create({
            client_id, project_name: sanitize(project_name),
            project_description: sanitize(project_description || '', 2000),
            status: 'active', current_stage: 'questionnaire'
        });

        // Create default stages
        const stages = ['questionnaire','color','logo','menu','brochure','social','packaging','deliverables'];
        const stageNames = ['Brand Questionnaire','Color Selection','Logo Design','Menu Design','Brochure Design','Social Media Kit','Packaging Design','Final Deliverables'];
        for (let i = 0; i < stages.length; i++) {
            await sequelize.query(
                `INSERT INTO project_stages (project_id, stage_key, stage_name, status, order_index) VALUES (?,?,?,?,?)`,
                { replacements: [project.id, stages[i], stageNames[i], i === 0 ? 'pending' : 'locked', i], type: sequelize.QueryTypes.INSERT }
            );
        }
        // Create questionnaire placeholder rows (10 questions)
        for (let i = 0; i < 10; i++) {
            await sequelize.query(
                `INSERT INTO questionnaires (project_id, question_index, answer_value, is_submitted) VALUES (?,?,'',FALSE)`,
                { replacements: [project.id, i], type: sequelize.QueryTypes.INSERT }
            );
        }
        res.status(201).json(project);
    } catch (e) {
        console.error('Admin create project error:', e);
        res.status(500).json({ error: e.message });
    }
});

// ============================================
// 404 HANDLER
// ============================================
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ============================================
// GLOBAL ERROR HANDLER
// ============================================
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: isProd ? 'Internal server error' : err.message });
});

// ============================================
// START SERVER
// ============================================
async function startServer() {
    try {
        await sequelize.authenticate();
        console.log('✅ MySQL Database connected');
        app.listen(PORT, () => {
            console.log(`\n🚀 D'zine Portal API — http://localhost:${PORT}`);
            console.log(`📍 Health: http://localhost:${PORT}/api/health`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}\n`);
        });
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        if (isProd) {
            console.error('Cannot start without database in production.');
            process.exit(1);
        }
        console.warn('⚠️  Starting without DB (dev mode)...');
        app.listen(PORT, () => {
            console.log(`\n🚀 Server on http://localhost:${PORT} (no DB)`);
        });
    }
}

startServer();
module.exports = app;

// ============================================
// FEEDBACK ROUTES (menu, brochure, social, packaging)
// ============================================
app.post('/api/feedback/:projectId', requireAuth, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { sectionKey, feedbackText, userName } = req.body;

        if (!feedbackText || !sectionKey) {
            return res.status(400).json({ error: 'sectionKey and feedbackText are required' });
        }

        await sequelize.query(
            `INSERT INTO feedback (project_id, section_key, feedback_text, user_name, created_at, updated_at)
             VALUES (?, ?, ?, ?, NOW(), NOW())`,
            {
                replacements: [
                    projectId,
                    sanitize(sectionKey, 50),
                    sanitize(feedbackText, 2000),
                    sanitize(userName || 'Client', 100)
                ],
                type: sequelize.QueryTypes.INSERT
            }
        );

        // Update stage to in_review
        await sequelize.query(
            `UPDATE project_stages SET status = 'in_review'
             WHERE project_id = ? AND stage_key = ? AND status = 'pending'`,
            { replacements: [projectId, sectionKey], type: sequelize.QueryTypes.UPDATE }
        );

        res.json({ message: 'Feedback saved' });
    } catch (e) {
        console.error('Feedback error:', e);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/feedback/:projectId', requireAuth, async (req, res) => {
    try {
        const rows = await sequelize.query(
            `SELECT * FROM feedback WHERE project_id = ? ORDER BY created_at DESC`,
            { replacements: [req.params.projectId], type: sequelize.QueryTypes.SELECT }
        );
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ============================================
// DELETE PROJECT (Admin)
// ============================================
app.delete('/api/admin/projects/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const project = await Project.findByPk(id);
        if (!project) return res.status(404).json({ error: 'Project not found' });

        // Cascade deletes handle related records (stages, questionnaires, etc.)
        await project.destroy();
        res.json({ message: 'Project deleted successfully' });
    } catch (e) {
        console.error('Delete project error:', e);
        res.status(500).json({ error: e.message });
    }
});

// ============================================
// ADMIN DELIVERABLES — real data from DB
// ============================================
app.get('/api/admin/deliverables', requireAdmin, async (req, res) => {
    try {
        const projects = await sequelize.query(
            `SELECT p.id, p.project_name, p.status, p.progress_percentage,
                    u.full_name AS client_name, u.company_name,
                    (SELECT COUNT(*) FROM project_stages ps
                     WHERE ps.project_id = p.id AND ps.status = 'approved') AS stages_done,
                    (SELECT COUNT(*) FROM project_stages ps2
                     WHERE ps2.project_id = p.id) AS stages_total,
                    (SELECT COUNT(*) FROM uploads up
                     WHERE up.project_id = p.id) AS file_count
             FROM projects p
             LEFT JOIN users u ON p.client_id = u.id
             ORDER BY p.created_at DESC`,
            { type: sequelize.QueryTypes.SELECT }
        );
        res.json(projects);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Upload a deliverable file link (admin side)
app.post('/api/admin/deliverables/:projectId', requireAdmin, async (req, res) => {
    try {
        const { projectId } = req.params;
        const { uploadKey, fileName, filePath, fileType } = req.body;

        await sequelize.query(
            `INSERT INTO uploads (project_id, upload_key, file_name, file_path, file_type, file_size, created_at)
             VALUES (?, ?, ?, ?, ?, 0, NOW())`,
            {
                replacements: [projectId, sanitize(uploadKey, 50), sanitize(fileName, 255),
                               sanitize(filePath, 500), sanitize(fileType, 50)],
                type: sequelize.QueryTypes.INSERT
            }
        );
        res.json({ message: 'Deliverable added' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
