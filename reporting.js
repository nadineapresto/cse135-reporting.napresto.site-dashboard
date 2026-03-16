require('dotenv').config({ path: '/var/www/reporting.napresto.site/api/.env' }); // To pull from .env for the MYSQL credentials and the sessionMiddleware secret

const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.set('trust proxy', true);
const PORT = 3006;

// MySQL connection (pull credentials from .env file)
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
});

// Session middleware (pull credentials from .env file)
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 60 * 60 * 1000, // 1 hour
    },
});

app.use(express.json());
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, 'public')));

// Authentication guard
function requireAuth(req, res, next) {
    if (req.session && req.session.user) return next();
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    return res.redirect('/login');
}

// Authorization guard for roles (owner vs. analyst vs. viewer permissions)
function requireRole(...roles) {
    return function (req, res, next) {
        if (!req.session.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        if (!roles.includes(req.session.user.role)) {
            if (req.path.startsWith('/api/')) {
                return res.status(403).json({ success: false, error: 'Forbidden' });
            }
            // Redirect users w/ invalid authorization to 403 forbidden page
            return res.status(403).sendFile(path.join(__dirname, 'public', '403.html'));
        }
        next();
    };
}

// Authorization guard for analyst roles and which reports they can access
function requireSection(section) {
    return function (req, res, next) {
        var user = req.session.user;
        // Owner/admin bypass section checks entirely
        if (user.role === 'owner') return next();
        // Analysts must have this section in their allowed list to access the report page
        if (user.role === 'analyst' && user.sections && user.sections.includes(section)) {
            return next();
        }
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({ success: false, error: 'Section access denied' });
        }
        // Redirect analysts w/ invalid authorization to a specific section to 403 forbidden page
        return res.status(403).sendFile(path.join(__dirname, 'public', '403.html'));
    };
}

// Serve login page (public, no auth required)
app.get('/login', async (req, res) => {
    if (req.session && req.session.user) return res.redirect('/dashboard');
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve saved-reports page (auth required, all roles access (owner, analysts, viewer))
app.get('/saved-reports', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'saved-reports.html'))
});

// Serve dashboard page (auth required, owner & analyst roles access)
app.get('/dashboard', requireAuth, requireRole('owner', 'analyst'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Serve traffic analytics page (auth required, owner & analyst w/ 'traffic' roles access)
app.get('/traffic', requireAuth, requireRole('owner', 'analyst'), requireSection('traffic'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'traffic.html'));
});

// Serve performance analytics page (auth required, owner & analyst w/ 'performance' roles access)
app.get('/performance', requireAuth, requireRole('owner', 'analyst'), requireSection('performance'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'performance.html'));
});

// Serve errors analytics page (auth required, owner & analyst w/ 'errors' roles access)
app.get('/errors', requireAuth, requireRole('owner', 'analyst'), requireSection('errors'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'errors.html'));
});

// Server admin panel page (auth required, owner role access only)
app.get('/admin-panel', requireAuth, requireOwner, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-panel.html'))
});

// CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin',  '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

// POST /api/login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password required' });
    }
    try {
        const [rows] = await pool.execute(
            'SELECT id, email, password_hash, display_name, role FROM users WHERE email = ?', [email]
        );
        if (rows.length === 0 || !(await bcrypt.compare(password, rows[0].password_hash))) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        const user = rows[0];
        // Identify which section an analyst user is assigned to
        const [sections] = await pool.execute('SELECT section FROM analyst_sections WHERE user_id = ?', [user.id]        );
        req.session.user = { 
            id: user.id, 
            email: user.email, 
            displayName: user.display_name, 
            role: user.role, 
            sections: sections.map(r => r.section)
        };
        res.json({ 
            success: true, 
            data: req.session.user,
            // If user is a 'viewer', redirect them to /saved-reports (they cannot access any other pages)
            redirect: user.role === 'viewer' ? '/saved-reports' : '/dashboard'
        });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

// GET /api/me (auth check used by the dashboard)
app.get('/api/me', requireAuth, (req, res) => {
    res.json({ 
        success: true, 
        data: { 
            displayName: req.session.user.displayName, 
            role: req.session.user.role,
            sections: req.session.user.sections || []   // Checks for an analyst role's sections they have access to
        } 
    });
});

// Helper: parse date range from query params
function getDateRange(query) {
    const end = query.end || new Date().toISOString().slice(0, 10);
    const start = query.start || new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    return [start + ' 00:00:00', end + ' 23:59:59'];
}

/* =======================================================
    The following Rest Endpoints were implemented for HW4:
    GET all, GET at an id, POST, PUT at an id, and DELETE
    endpoints for all tables in MYSQL `analytics` database:
    - `sessions`
    - `pageviews`
    - `performance`
    - `events`
    - `errors`
========================================================== */

// =========== SESSIONS REST ENDPOINTS =======================================
// GET all rows from table sessions
app.get('/api/sessions', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM sessions ORDER BY id DESC');
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// GET specific id from table sessions
app.get('/api/sessions/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM sessions WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, error: 'id not found' });
        res.json({ success: true, data: rows[0] });   // ← this line was missing
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST to sessions
app.post('/api/sessions', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'INSERT INTO sessions (session_id, first_page, last_page, start_time, last_activity) VALUES (?, ?, ?, NOW(), NOW())',
            [req.body.session_id, req.body.first_page, req.body.last_page]
        );
        const [rows] = await pool.execute('SELECT * FROM sessions WHERE id = ?', [result.insertId]);
        res.status(201).json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// PUT (update) sessions at an id
app.put('/api/sessions/:id', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'UPDATE sessions SET last_page = ?, last_activity = NOW() WHERE id = ?',
            [req.body.last_page, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        const [rows] = await pool.execute('SELECT * FROM sessions WHERE id = ?', [req.params.id]);
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// DELETE sessions at an id
app.delete('/api/sessions/:id', async (req, res) => {
    try {
        const [result] = await pool.execute('DELETE FROM sessions WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        res.sendStatus(204);
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// =========== PAGEVIEWS REST ENDPOINTS =======================================
// GET all pageviews
app.get('/api/pageviews', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM pageviews ORDER BY id DESC');
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// GET pageviews at an id
app.get('/api/pageviews/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM pageviews WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, error: 'Not found' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST to pageviews
app.post('/api/pageviews', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'INSERT INTO pageviews (session_id, url, server_timestamp) VALUES (?, ?, NOW())',
            [req.body.session_id, req.body.url]
        );
        const [rows] = await pool.execute('SELECT * FROM pageviews WHERE id = ?', [result.insertId]);
        res.status(201).json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// UPDATE pageviews at an id
app.put('/api/pageviews/:id', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'UPDATE pageviews SET url = ? WHERE id = ?',
            [req.body.url, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        const [rows] = await pool.execute('SELECT * FROM pageviews WHERE id = ?', [req.params.id]);
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// DELETE pageviews at an id
app.delete('/api/pageviews/:id', async (req, res) => {
    try {
        const [result] = await pool.execute('DELETE FROM pageviews WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        res.sendStatus(204);
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// =========== PERFORMANCE REST ENDPOINTS =======================================
// GET all performance stats
app.get('/api/performance', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM performance ORDER BY id DESC');
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// GET performance stats at an id
app.get('/api/performance/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM performance WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, error: 'Not found' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST performance stats
app.post('/api/performance', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'INSERT INTO performance (session_id, url, server_timestamp) VALUES (?, ?, NOW())',
            [req.body.session_id, req.body.url]
        );
        const [rows] = await pool.execute('SELECT * FROM performance WHERE id = ?', [result.insertId]);
        res.status(201).json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// PUT (update) perforamnce stats at an id
app.put('/api/performance/:id', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'UPDATE performance SET url = ? WHERE id = ?',
            [req.body.url, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        const [rows] = await pool.execute('SELECT * FROM performance WHERE id = ?', [req.params.id]);
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// DELETE performance stats at an id
app.delete('/api/performance/:id', async (req, res) => {
    try {
        const [result] = await pool.execute('DELETE FROM performance WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        res.sendStatus(204);
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// =========== EVENTS REST ENDPOINTS =======================================
// GET all events stats
app.get('/api/events', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM events ORDER BY id DESC');
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// GET events stats at an id
app.get('/api/events/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM events WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, error: 'Not found' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST events stats
app.post('/api/events', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'INSERT INTO events (session_id, url, event_name, server_timestamp) VALUES (?, ?, ?, NOW())',
            [req.body.session_id, req.body.url, req.body.event_name]
        );
        const [rows] = await pool.execute('SELECT * FROM events WHERE id = ?', [result.insertId]);
        res.status(201).json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// PUT (update) events stats at an id
app.put('/api/events/:id', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'UPDATE events SET event_name = ? WHERE id = ?',
            [req.body.event_name, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        const [rows] = await pool.execute('SELECT * FROM events WHERE id = ?', [req.params.id]);
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// DELETE (update) events stats at an id
app.delete('/api/events/:id', async (req, res) => {
    try {
        const [result] = await pool.execute('DELETE FROM events WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        res.sendStatus(204);
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// === Errors REST Endpoints =======================================
// GET all error stats
app.get('/api/errors', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM errors ORDER BY id DESC');
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// GET error stats at an id
app.get('/api/errors/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM errors WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, error: 'Not found' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST error stats
app.post('/api/errors', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'INSERT INTO errors (session_id, url, error_message, server_timestamp) VALUES (?, ?, ?, NOW())',
            [req.body.session_id, req.body.url, req.body.error_message]
        );
        const [rows] = await pool.execute('SELECT * FROM errors WHERE id = ?', [result.insertId]);
        res.status(201).json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// PUT (update) error stats at an id
app.put('/api/errors/:id', async (req, res) => {
    try {
        const [result] = await pool.execute(
            'UPDATE errors SET error_message = ? WHERE id = ?',
            [req.body.error_message, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        const [rows] = await pool.execute('SELECT * FROM errors WHERE id = ?', [req.params.id]);
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// DELETE error stats at an id
app.delete('/api/errors/:id', async (req, res) => {
    try {
        const [result] = await pool.execute('DELETE FROM errors WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ success: false, error: 'Not found' });
        res.sendStatus(204);
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});


/* =======================================================
    The following endpoints and functions are used to
    serve the data for the rendering of the charts and
    graphs in the dashboard & report pages.
========================================================== */

/* =======================================================
    Admin Panel:
    Admin panel page is ONLY accessible to the owner role.
    CRUD endpoints for managing user account data from
    the MYSQL database's `users` table.    
========================================================== */
function requireOwner(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'owner') {
        return res.status(403).json({ success: false, error: 'Owner access required' });
    }
    next();
}

// GET (read) users for admin panel 
app.get('/api/users', requireAuth, requireOwner, async (req, res) => {
    try {
        const [users] = await pool.execute(
            'SELECT id, email, display_name, role, created_at, last_login FROM users ORDER BY created_at'
        );
        res.json({ success: true, data: users });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST (create) users for admin panel 
app.post('/api/users', requireAuth, requireOwner, async (req, res) => {
    try {
        const { email, displayName, password, role } = req.body;
        if (!email || !displayName || !password) {
            return res.status(400).json({ success: false, error: 'All fields required' });
        }
        const validRoles = ['owner', 'analyst', 'viewer'];
        const userRole = validRoles.includes(role) ? role : 'viewer';
        const passwordHash = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password_hash, display_name, role) VALUES (?, ?, ?, ?)',
            [email, passwordHash, displayName, userRole]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        // Prevent creation of a user account w/ the same email as another existing user
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, error: 'Email already exists' });
        }
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST (update) users for admin panel
app.put('/api/users/:id', requireAuth, requireOwner, async (req, res) => {
    try {
        const { displayName, role } = req.body;
        const validRoles = ['owner', 'analyst', 'viewer'];
        const fields = [], params = [];
        if (displayName) { fields.push('display_name = ?'); params.push(displayName); }
        if (role && validRoles.includes(role)) { fields.push('role = ?'); params.push(role); }
        if (fields.length === 0) {
            return res.status(400).json({ success: false, error: 'Nothing to update' });
        }
        params.push(req.params.id);
        await pool.execute(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, params);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// DELETE users for admin panel
app.delete('/api/users/:id', requireAuth, requireOwner, async (req, res) => {
    try {
        if (String(req.session.user.id) === String(req.params.id)) {
            return res.status(400).json({ success: false, error: 'Cannot delete yourself' });
        }
        await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

/* =======================================================
    GET /api/dashboard (summary metric cards):

    Gets data from MYSQL database for charts and tables
    in overview page of the dashboard.
    
    Accessible by owner & all analysts.
========================================================== */
app.get('/api/dashboard', requireAuth, requireRole('owner', 'analyst'), async (req, res) => {
    try {
        const [start, end] = getDateRange(req.query);
        const [[summary]] = await pool.execute(`
            SELECT
                (SELECT COUNT(*) FROM pageviews
                 WHERE server_timestamp BETWEEN ? AND ?) AS total_pageviews,
                (SELECT COUNT(DISTINCT session_id) FROM pageviews
                 WHERE server_timestamp BETWEEN ? AND ?) AS total_sessions,
                (SELECT ROUND(AVG(total_load_time)) FROM performance
                 WHERE server_timestamp BETWEEN ? AND ?) AS avg_load_time_ms,
                (SELECT COUNT(*) FROM errors
                 WHERE server_timestamp BETWEEN ? AND ?) AS total_errors
        `, [start, end, start, end, start, end, start, end]);

        const [topPages] = await pool.execute(
            `SELECT url, COUNT(*) AS views FROM pageviews
                WHERE server_timestamp BETWEEN ? AND ?
                GROUP BY url ORDER BY views DESC LIMIT 10`,
                [start, end]
        );

        const [[sessionStats]] = await pool.execute(
            `SELECT
                ROUND(AVG(duration_seconds)) AS avg_duration_sec,
                ROUND(AVG(page_count), 1)    AS avg_pages,
                ROUND(SUM(CASE WHEN page_count = 1 THEN 1 ELSE 0 END) / COUNT(*) * 100, 1) AS bounce_rate_pct
            FROM sessions WHERE start_time BETWEEN ? AND ?`,
            [start, end]
        );

        const [byDay] = await pool.execute(
            `SELECT DATE(server_timestamp) AS day, COUNT(*) AS views
            FROM pageviews WHERE server_timestamp BETWEEN ? AND ?
            GROUP BY day ORDER BY day`,
            [start, end]
        );

        res.json({ success: true, data: { ...summary, ...sessionStats, topPages, byDay } });
    } catch (err) {
        console.error('Dashboard error:', err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

/* =======================================================
    GET /api/analytics/traffic:

    Gets data from MYSQL database for charts and tables
    in traffic report page of the dashboard.
    
    Accessible by owner & analysts assigned to 'traffic'.
========================================================== */
app.get('/api/analytics/traffic', requireAuth, requireRole('owner', 'analyst'), requireSection('traffic'), async (req, res) => {
    try {
        const [start, end] = getDateRange(req.query);
        const [byDay] = await pool.execute(
            `SELECT DATE(server_timestamp) AS day, COUNT(*) AS views
             FROM pageviews WHERE server_timestamp BETWEEN ? AND ?
             GROUP BY day ORDER BY day`,
            [start, end]
        );
        const [topPages] = await pool.execute(
            `SELECT url, COUNT(*) AS views FROM pageviews
             WHERE server_timestamp BETWEEN ? AND ?
             GROUP BY url ORDER BY views DESC LIMIT 10`,
            [start, end]
        );
        const [[stats]] = await pool.execute(
            `SELECT
                ROUND(AVG(duration_seconds)) AS avg_duration_sec,
                ROUND(AVG(page_count), 1)    AS avg_pages,
                ROUND(SUM(CASE WHEN page_count = 1 THEN 1 ELSE 0 END) / COUNT(*) * 100, 1) AS bounce_rate_pct
             FROM sessions WHERE start_time BETWEEN ? AND ?`,
            [start, end]
        );
        res.json({ success: true, data: { byDay, topPages, stats } });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

/* =======================================================
    GET /api/analytics/performance:

    Gets data from MYSQL database for charts and tables
    in performance report page of the dashboard.
    
    Accessible by owner & analysts assigned to 'performance'.
========================================================== */
app.get('/api/analytics/performance', requireAuth, requireRole('owner', 'analyst'), requireSection('performance'), async (req, res) => {
    try {
        const [start, end] = getDateRange(req.query);
        const [byDay] = await pool.execute(
            `SELECT DATE(server_timestamp) AS day,
                    ROUND(AVG(total_load_time)) AS avg_load_ms
             FROM performance WHERE server_timestamp BETWEEN ? AND ?
             GROUP BY day ORDER BY day`,
            [start, end]
        );
        const [byPage] = await pool.execute(
            `SELECT url,
                    ROUND(AVG(total_load_time)) AS avg_load_ms,
                    ROUND(AVG(ttfb))            AS avg_ttfb_ms,
                    ROUND(AVG(lcp))             AS avg_lcp,
                    ROUND(AVG(dom_complete))    AS avg_dom_ms,
                    COUNT(*)                    AS samples
             FROM performance WHERE server_timestamp BETWEEN ? AND ?
             GROUP BY url ORDER BY avg_load_ms DESC LIMIT 10`,
            [start, end]
        );
        res.json({ success: true, data: { byDay, byPage } });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

/* =======================================================
    GET /api/analytics/errors:

    Gets data from MYSQL database for charts and tables
    in errors report page of the dashboard.
    
    Accessible by owner & analysts assigned to 'performance'.
========================================================== */
app.get('/api/analytics/errors', requireAuth, requireRole('owner', 'analyst'), requireSection('errors'), async (req, res) => {
    try {
        const [start, end] = getDateRange(req.query);
        const [trend] = await pool.execute(
            `SELECT DATE(server_timestamp) AS day, COUNT(*) AS error_count
             FROM errors WHERE server_timestamp BETWEEN ? AND ?
             GROUP BY day ORDER BY day`,
            [start, end]
        );
        const [byMessage] = await pool.execute(
            `SELECT error_message,
                    COUNT(*) AS occurrences,
                    MAX(server_timestamp) AS last_seen,
                    url AS sample_url
             FROM errors WHERE server_timestamp BETWEEN ? AND ?
             GROUP BY error_message, url ORDER BY occurrences DESC LIMIT 20`,
            [start, end]
        );
        res.json({ success: true, data: { trend, byMessage } });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

/* =======================================================
    Saved Reports:
    Saved reports page is accessible to all roles, even 
    the 'viewer' role. 'viewer' roles will only be able to
    view the saved reports and comments left by analysts
    or admin/owner roles. Only analyst and owner roles
    can use the CRUD endpoints for managing and creating
    saved reports in the MYSQL database's `saved_reports` 
    table.
========================================================== */
// GET all saved reports (all authenticated roles can access)
app.get('/api/saved-reports', requireAuth, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT sr.id, sr.title, sr.report_type, sr.date_start, sr.date_end,
                    sr.created_at, sr.analyst_comment, sr.snapshot,
                    u.display_name AS created_by_name
             FROM saved_reports sr
             JOIN users u ON sr.created_by = u.id
             ORDER BY sr.created_at DESC`
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// POST (create) a new saved report (owner & analysts have access)
app.post('/api/saved-reports', requireAuth, requireRole('owner', 'analyst'), async (req, res) => {
    try {
        const { title, report_type, date_start, date_end, snapshot } = req.body;
        if (!title || !report_type || !date_start || !date_end || !snapshot) {
            return res.status(400).json({ success: false, error: 'Missing required fields' });
        }
        const [result] = await pool.execute(
            `INSERT INTO saved_reports (title, report_type, date_start, date_end, created_by, snapshot)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [title, report_type, date_start, date_end, req.session.user.id, JSON.stringify(snapshot)]
        );
        res.status(201).json({ success: true, id: result.insertId });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// PATCH (update) analyst comment (owner & analysts have access)
app.patch('/api/saved-reports/:id', requireAuth, requireRole('owner', 'analyst'), async (req, res) => {
    try {
        const { analyst_comment } = req.body;
        if (analyst_comment === undefined) {
            return res.status(400).json({ success: false, error: 'analyst_comment required' });
        }
        const [result] = await pool.execute(
            'UPDATE saved_reports SET analyst_comment = ? WHERE id = ?',
            [analyst_comment, req.params.id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, error: 'Report not found' });
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// DELETE saved report (only owner has access)
app.delete('/api/saved-reports/:id', requireAuth, requireOwner, async (req, res) => {
    try {
        const [result] = await pool.execute(
            'DELETE FROM saved_reports WHERE id = ?', [req.params.id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, error: 'Report not found' });
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// Serve 403 forbidden page routes (not errors w/ api routes)
// (api routes already return JSON 403, so this is for forbidden pages encountered from browser navigation)
app.use(function (req, res, next) {
    // This won't be reached for API routes since they return JSON above
    // This is a fallback for any unmatched page routes
    next();
});

// Serve 404 error page
app.use(function (req, res) {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.listen(PORT, () => console.log(`Reporting API listening on port ${PORT}`));