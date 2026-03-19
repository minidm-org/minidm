/*

MiniDM - Open-Source Mobile Device Management
Copyright (C) 2026 Paul Wright / MiniDM.org

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const session = require('express-session');
const path = require('path');
const yaml = require('js-yaml');
const axios = require('axios');
const multer = require('multer');
const { XMLParser } = require('fast-xml-parser');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

// Configure Multer for in-memory file uploads with a strict 2MB limit per file
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024 } // 2 MB limit
});

const app = express();
app.use(express.json());

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-dev-secret-change-me', 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 3600000 }
}));

// Serve static files from 'public' (where login.html lives)
app.use(express.static('public'));

let db; 
let serverKeys = { publicKey: '', privateKey: '' };

// Auth Middleware
const requireAuth = (req, res, next) => {
    if (req.session && req.session.authenticated) {
        return next();
    }
    if (req.path.startsWith('/api/')) {
        return res.status(403).json({ error: 'Unauthorized. Please login.' });
    }
    res.redirect('/login'); 
};

// Database Initialization & Key Management
async function initializeServer() {
    console.log('Initializing SQLite Database...');
    
    db = await open({
        filename: './minidm.db',
        driver: sqlite3.Database
    });

    await db.run('PRAGMA foreign_keys = ON;');

    await db.exec(`
        CREATE TABLE IF NOT EXISTS server_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            client_public_key TEXT NOT NULL,
            device_name TEXT,
            enrollment_date TEXT NOT NULL,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_inventory (
            device_id TEXT PRIMARY KEY,
            serial_number TEXT,
            processor TEXT,
            ram_mb INTEGER,
            last_updated TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS device_software (
            device_id TEXT NOT NULL,
            app_name TEXT NOT NULL,
            app_id TEXT NOT NULL,
            version TEXT,
            source TEXT,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (device_id, app_id),
            FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS winget_packages (
            package_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            download_url TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            installer_type TEXT,
            silent_flags TEXT,
            last_synced TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS policy_library (
            policy_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            category TEXT,
            registry_key TEXT NOT NULL,
            value_name TEXT,             -- This can be null if elements define their own valueNames
            policy_type TEXT,
            elements TEXT                -- JSON array of required inputs (text, decimal, enum, list)
        );

        CREATE TABLE IF NOT EXISTS device_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_group_members (
            device_id TEXT NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY (device_id, group_id),
            FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
            FOREIGN KEY(group_id) REFERENCES device_groups(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS deploy_bundles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS deploy_bundle_items (
            bundle_id INTEGER NOT NULL,
            package_id TEXT NOT NULL,
            PRIMARY KEY (bundle_id, package_id),
            FOREIGN KEY(bundle_id) REFERENCES deploy_bundles(id) ON DELETE CASCADE,
            FOREIGN KEY(package_id) REFERENCES winget_packages(package_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS policy_bundles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS group_deploy_bundles (
            group_id INTEGER NOT NULL,
            bundle_id INTEGER NOT NULL,
            PRIMARY KEY (group_id, bundle_id),
            FOREIGN KEY(group_id) REFERENCES device_groups(id) ON DELETE CASCADE,
            FOREIGN KEY(bundle_id) REFERENCES deploy_bundles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS group_policy_bundles (
            group_id INTEGER NOT NULL,
            bundle_id INTEGER NOT NULL,
            PRIMARY KEY (group_id, bundle_id),
            FOREIGN KEY(group_id) REFERENCES device_groups(id) ON DELETE CASCADE,
            FOREIGN KEY(bundle_id) REFERENCES policy_bundles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS policy_bundle_items (
            bundle_id INTEGER NOT NULL,
            policy_id TEXT NOT NULL,
            base_state INTEGER NOT NULL DEFAULT 1,
            configured_elements TEXT, -- Stores the JSON array of custom parameters
            PRIMARY KEY (bundle_id, policy_id),
            FOREIGN KEY(bundle_id) REFERENCES policy_bundles(id) ON DELETE CASCADE,
            FOREIGN KEY(policy_id) REFERENCES policy_library(policy_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tenant_data (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            company_name TEXT,
            enrollment_key TEXT,
            key_created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS command_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            action TEXT NOT NULL,
            payload TEXT,
            status TEXT DEFAULT 'Queued',     -- 'Queued', 'Sent', 'Completed', 'Failed'
            queued_at TEXT NOT NULL,
            sent_at TEXT,                     -- When the agent picked it up
            completed_at TEXT,                -- When the agent reported back
            exit_code INTEGER,                -- E.g., msiexec exit codes (0, 1641, 3010)
            result_message TEXT               -- Human-readable success/error logs
        );

    `);

const adminCount = await db.get('SELECT COUNT(*) as count FROM admins');
    if (adminCount.count === 0) {
        console.log('No admins found. Creating default admin (admin / password123%)...');
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.scryptSync('password123%', salt, 64).toString('hex');
        await db.run('INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)', ['admin', hash, salt]);
    }

    const tenant = await db.get('SELECT * FROM tenant_data WHERE id = 1');
    if (!tenant) {
        console.log('No tenant data found. Generating default Enrollment Key...');
        // Generate a random 32-character hex string for the enrollment key
        const defaultKey = crypto.randomBytes(16).toString('hex'); 
        await db.run(
            'INSERT INTO tenant_data (id, company_name, enrollment_key, key_created_at) VALUES (1, ?, ?, ?)',
            ['Default Organization', defaultKey, new Date().toISOString()]
        );
        console.log(`[!] Initial Enrollment Key generated: ${defaultKey}`);
    }

    const config = await db.get('SELECT public_key, private_key FROM server_config WHERE id = 1');
    
if (config) {
        console.log('Loaded existing Server RSA Keys from database.');
        serverKeys.publicKey = config.public_key;
        serverKeys.privateKey = config.private_key;
    } else {
        console.log('No keys found. Generating new Server RSA Key Pair...');
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        await db.run('INSERT INTO server_config (id, public_key, private_key) VALUES (1, ?, ?)', [publicKey, privateKey]);
        
        serverKeys.publicKey = publicKey;
        serverKeys.privateKey = privateKey;
        console.log('New Server Keys generated and saved to database.');
    }
}

// --- Endpoints ---

// Root Redirect to Dashboard
app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

// Clean Login Route
app.get('/login', (req, res) => {
    if (req.session && req.session.authenticated) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login API (Database-backed)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const admin = await db.get('SELECT password_hash, salt FROM admins WHERE username = ?', [username]);
        
        if (admin) {
            const hash = crypto.scryptSync(password, admin.salt, 64).toString('hex');
            const isValid = crypto.timingSafeEqual(Buffer.from(admin.password_hash, 'hex'), Buffer.from(hash, 'hex'));
            
            if (isValid) {
                req.session.authenticated = true;
                return res.status(200).json({ status: 'success' });
            }
        }
        res.status(401).json({ error: 'Invalid credentials' });
        
    } catch (err) {
        console.error('Login database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout API
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
            return res.status(500).json({ error: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ status: 'success' });
    });
});

// Protected Web UI Routes
app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'index.html'));
});

app.get('/devices', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'devices.html'));
});

app.get('/apps', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'apps.html'));
});

app.get('/policy', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'policy.html'));
});

// Admin API Endpoints (Protected)

app.get('/api/admin/devices', requireAuth, async (req, res) => {
    try {
        const devices = await db.all(`
            SELECT 
                d.device_id, d.device_name, d.status, d.enrollment_date, d.last_seen,
                i.serial_number, i.processor, i.ram_mb,
                g.name as group_name, g.id as group_id
            FROM devices d
            LEFT JOIN device_inventory i ON d.device_id = i.device_id
            LEFT JOIN device_group_members m ON d.device_id = m.device_id
            LEFT JOIN device_groups g ON m.group_id = g.id
            ORDER BY d.enrollment_date DESC
        `);
        res.status(200).json(devices);
    } catch (err) {
        console.error('Failed to fetch devices:', err.message);
        res.status(500).json({ error: 'Failed to fetch devices' });
    }
});


// Dashboard analytics endpoint

app.get('/api/admin/stats/charts', requireAuth, async (req, res) => {
    try {
        // 1. Aggregate Device Statuses
        const deviceStats = await db.all('SELECT status, COUNT(*) as count FROM devices GROUP BY status');
        
        // 2. Aggregate Command Queue (Telemetry) Statuses
        const telemetryStats = await db.all('SELECT status, COUNT(*) as count FROM command_queue GROUP BY status');

        res.status(200).json({
            deviceStats,
            telemetryStats
        });
    } catch (err) {
        console.error('Failed to fetch chart stats:', err.message);
        res.status(500).json({ error: 'Failed to fetch chart data.' });
    }
});


// Device approval and Management endpoints

app.post('/api/admin/devices/:deviceId/approve', requireAuth, async (req, res) => {
    try {
        await db.run('UPDATE devices SET status = ? WHERE device_id = ?', ['Active', req.params.deviceId]);
        res.status(200).json({ status: 'success' });
    } catch (err) {
        console.error('Failed to approve device:', err.message);
        res.status(500).json({ error: 'Failed to approve device.' });
    }
});

app.delete('/api/admin/devices/:deviceId', requireAuth, async (req, res) => {
    try {
        // Manually clear the command queue first to avoid orphaned records, then delete the device
        await db.run('DELETE FROM command_queue WHERE device_id = ?', [req.params.deviceId]);
        await db.run('DELETE FROM devices WHERE device_id = ?', [req.params.deviceId]);
        
        res.status(200).json({ status: 'success' });
    } catch (err) {
        console.error('Failed to delete device:', err.message);
        res.status(500).json({ error: 'Failed to delete device.' });
    }
});

// Settings page

app.get('/settings', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'settings.html'));
});

// Password Reset

app.post('/api/admin/password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new passwords are required.' });
    }

    try {
        // Fetch the first admin (since MiniDM is currently single-tenant)
        const admin = await db.get('SELECT username, password_hash, salt FROM admins LIMIT 1');
        if (!admin) return res.status(500).json({ error: 'Admin account not found.' });

        // 1. Verify the current password
        const hash = crypto.scryptSync(currentPassword, admin.salt, 64).toString('hex');
        const isValid = crypto.timingSafeEqual(Buffer.from(admin.password_hash, 'hex'), Buffer.from(hash, 'hex'));
        
        if (!isValid) return res.status(401).json({ error: 'Incorrect current password.' });

        // 2. Generate new salt and hash for the new password
        const newSalt = crypto.randomBytes(16).toString('hex');
        const newHash = crypto.scryptSync(newPassword, newSalt, 64).toString('hex');

        // 3. Update the database
        await db.run('UPDATE admins SET password_hash = ?, salt = ? WHERE username = ?', [newHash, newSalt, admin.username]);
        
        console.log(`[Security] Password updated for admin: ${admin.username}`);
        res.status(200).json({ status: 'success', message: 'Password updated successfully.' });

    } catch (err) {
        console.error('Password reset error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Enrollment Endpoints

// Get the current tenant details and deployment URL code
app.get('/api/admin/tenant', requireAuth, async (req, res) => {
    try {
        const tenant = await db.get('SELECT company_name, enrollment_key FROM tenant_data WHERE id = 1');
        if (!tenant) return res.status(404).json({ error: 'Tenant data not found.' });

        // Hash the key to create a unique, unguessable URL code (32 chars)
        const deployCode = crypto.createHash('sha256').update(tenant.enrollment_key).digest('hex').substring(0, 32);
        
        res.status(200).json({
            companyName: tenant.company_name,
            enrollmentKey: tenant.enrollment_key,
            deployCode: deployCode
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch tenant data.' });
    }
});

// Regenerate the Enrollment Key
app.post('/api/admin/tenant/regenerate', requireAuth, async (req, res) => {
    try {
        const newKey = crypto.randomBytes(16).toString('hex');
        await db.run('UPDATE tenant_data SET enrollment_key = ?, key_created_at = ? WHERE id = 1', [newKey, new Date().toISOString()]);
        
        // Return the new code so the UI can update immediately
        const deployCode = crypto.createHash('sha256').update(newKey).digest('hex').substring(0, 32);
        res.status(200).json({ status: 'success', newKey, deployCode });
    } catch (err) {
        res.status(500).json({ error: 'Failed to regenerate key.' });
    }
});


// Deployment endpoints

// Serves the dynamic deploy.ps1 script without authentication
app.get('/api/deploy/:uniqueCode/deploy.ps1', async (req, res) => {
    const { uniqueCode } = req.params;
    
    try {
        const tenant = await db.get('SELECT enrollment_key FROM tenant_data WHERE id = 1');
        if (!tenant) return res.status(404).send('Not Found');

        // Re-calculate the expected hash to verify the URL
        const expectedCode = crypto.createHash('sha256').update(tenant.enrollment_key).digest('hex').substring(0, 32);

        // If it doesn't match perfectly, return 404 to obscure the existence of the endpoint
        if (uniqueCode !== expectedCode) {
            return res.status(404).send('Not Found');
        }

        // Dynamically resolve the in-use domain (handles reverse proxies like Nginx/Cloudflare)
        const protocol = req.headers['x-forwarded-proto'] || req.protocol;
        const host = req.get('host');
        const serverUrl = `${protocol}://${host}`;

        const ps1Script = `
# MiniDM Deployment Config Script (Run as Administrator)

$registryPath = "HKLM:\\SOFTWARE\\MiniDM"
$serverUrl = "${serverUrl}"
$enrollmentKey = "${tenant.enrollment_key}"

# Check if running as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You do not have Administrator rights. Please open PowerShell as Administrator and try again."
    break
}

# Create the MiniDM registry key if it doesn't exist
if (!(Test-Path $registryPath)) {
    Write-Host "Creating registry key at $registryPath..." -ForegroundColor Cyan
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the ServerUrl and EnrollmentKey values
Write-Host "Setting ServerUrl to $serverUrl..." -ForegroundColor Cyan
New-ItemProperty -Path $registryPath -Name "ServerUrl" -Value $serverUrl -PropertyType String -Force | Out-Null

Write-Host "Setting EnrollmentKey to $enrollmentKey..." -ForegroundColor Cyan
New-ItemProperty -Path $registryPath -Name "EnrollmentKey" -Value $enrollmentKey -PropertyType String -Force | Out-Null

Write-Host "MiniDM registry configuration complete!" -ForegroundColor Green
Write-Host "You can now run the C# agent to test the bootstrap process." -ForegroundColor Green
`;

        // Send the file as a downloadable attachment
        res.setHeader('Content-Disposition', 'attachment; filename="deploy.ps1"');
        res.setHeader('Content-Type', 'application/octet-stream');
        res.status(200).send(ps1Script.trim());

    } catch (err) {
        console.error('Script generation error:', err);
        res.status(500).send('Server Error');
    }
});


// --- Group Management Endpoints ---

// Get all groups with their device counts
app.get('/api/admin/groups', requireAuth, async (req, res) => {
    try {
        const groups = await db.all(`
            SELECT g.id, g.name, g.description, COUNT(m.device_id) as device_count
            FROM device_groups g
            LEFT JOIN device_group_members m ON g.id = m.group_id
            GROUP BY g.id
            ORDER BY g.name ASC
        `);
        res.status(200).json(groups);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch groups.' });
    }
});

// Create a new group
app.post('/api/admin/groups', requireAuth, async (req, res) => {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Group name is required.' });

    try {
        await db.run(
            'INSERT INTO device_groups (name, description, created_at) VALUES (?, ?, ?)',
            [name, description || '', new Date().toISOString()]
        );
        res.status(200).json({ status: 'success' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create group. Name might already exist.' });
    }
});

// Assign (or Unassign) a device to a group
app.post('/api/admin/groups/assign', requireAuth, async (req, res) => {
    const { deviceId, groupId } = req.body;
    
    if (!deviceId) return res.status(400).json({ error: 'Device ID is required.' });

    try {
        // Always clear existing membership first
        await db.run('DELETE FROM device_group_members WHERE device_id = ?', [deviceId]);
        
        // If a groupId was provided (i.e., not "-- Unassigned --"), insert the new one
        if (groupId) {
            await db.run(
                'INSERT INTO device_group_members (device_id, group_id) VALUES (?, ?)',
                [deviceId, groupId]
            );
        }
        res.status(200).json({ status: 'success' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update group assignment.' });
    }
});

// Get all devices assigned to a specific group
app.get('/api/admin/groups/:groupId/devices', requireAuth, async (req, res) => {
    try {
        const devices = await db.all(`
            SELECT d.device_id, d.device_name, d.status
            FROM devices d
            JOIN device_group_members m ON d.device_id = m.device_id
            WHERE m.group_id = ?
        `, [req.params.groupId]);
        res.status(200).json(devices);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Remove a device from a group
app.delete('/api/admin/groups/:groupId/devices/:deviceId', requireAuth, async (req, res) => {
    try {
        await db.run('DELETE FROM device_group_members WHERE group_id = ? AND device_id = ?',
            [req.params.groupId, req.params.deviceId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete a Device Group
app.delete('/api/admin/groups/:groupId', requireAuth, async (req, res) => {
    try {
        await db.run('DELETE FROM device_groups WHERE id = ?', [req.params.groupId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete a Deploy Bundle
app.delete('/api/admin/deploy-bundles/:bundleId', requireAuth, async (req, res) => {
    try {
        await db.run('DELETE FROM deploy_bundles WHERE id = ?', [req.params.bundleId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete a Policy Bundle
app.delete('/api/admin/policy-bundles/:bundleId', requireAuth, async (req, res) => {
    try {
        await db.run('DELETE FROM policy_bundles WHERE id = ?', [req.params.bundleId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// Enforcement Endpoint

app.post('/api/admin/groups/:groupId/enforce', requireAuth, async (req, res) => {
    const groupId = req.params.groupId;

    try {
        // 1. Get all devices currently in this group
        const devices = await db.all('SELECT device_id FROM device_group_members WHERE group_id = ?', [groupId]);
        if (devices.length === 0) return res.status(400).json({ error: 'No devices in this group.' });

        // 2. Gather all Apps from the group's Deploy Bundles
        const apps = await db.all(`
            SELECT w.* FROM winget_packages w
            JOIN deploy_bundle_items dbi ON w.package_id = dbi.package_id
            JOIN group_deploy_bundles gdb ON dbi.bundle_id = gdb.bundle_id
            WHERE gdb.group_id = ?
        `, [groupId]);

        // 3. Gather all Policies from the group's Policy Bundles
        const policies = await db.all(`
            SELECT pl.*, pbi.base_state, pbi.configured_elements 
            FROM policy_library pl
            JOIN policy_bundle_items pbi ON pl.policy_id = pbi.policy_id
            JOIN group_policy_bundles gpb ON pbi.bundle_id = gpb.bundle_id
            WHERE gpb.group_id = ?
        `, [groupId]);

        // 4. Bulk Queue the commands for each device
        for (const device of devices) {
            
            // Queue Application Deployments
            for (const app of apps) {
                const payload = {
                    Action: 'InstallApp',
                    Name: app.name,
                    Url: app.download_url,
                    Hash: app.sha256_hash,
                    Arguments: app.silent_flags
                };
                await db.run(
                    'INSERT INTO command_queue (device_id, action, payload, queued_at) VALUES (?, ?, ?, ?)',
                    [device.device_id, 'InstallApp', JSON.stringify(payload), new Date().toISOString()]
                );
            }

            // Queue Policy Enforcements
            for (const pol of policies) {
                const payload = {
                    Action: 'SetRegistryComplex',
                    PolicyName: pol.display_name,
                    BaseRegistryKey: pol.registry_key,
                    RegistryEdits: []
                };

                // Add Base State Toggle
                if (pol.value_name) {
                    payload.RegistryEdits.push({
                        ValueName: pol.value_name,
                        Value: pol.base_state,
                        ValueType: 'DWORD'
                    });
                }

                // Add Custom Configured Elements
                const elements = JSON.parse(pol.configured_elements || '[]');
                elements.forEach(elem => {
                    if (elem.valueName && elem.value !== "") {
                        payload.RegistryEdits.push({
                            ValueName: elem.valueName,
                            Value: elem.type === 'DWORD' ? parseInt(elem.value, 10) : elem.value,
                            ValueType: elem.type
                        });
                    }
                });

                await db.run(
                    'INSERT INTO command_queue (device_id, action, payload, queued_at) VALUES (?, ?, ?, ?)',
                    [device.device_id, 'SetRegistryComplex', JSON.stringify(payload), new Date().toISOString()]
                );
            }
        }

        res.status(200).json({ status: 'success', message: `Queued enforcement for ${devices.length} device(s).` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to enforce group state.' });
    }
});



app.post('/api/admin/commands', requireAuth, async (req, res) => {
    const { deviceId, action, payload } = req.body;
    if (!deviceId || !action) return res.status(400).json({ error: 'Device ID and Action are required.' });

    try {
        await db.run(
            'INSERT INTO command_queue (device_id, action, payload, queued_at) VALUES (?, ?, ?, ?)',
            [deviceId, action, JSON.stringify(payload || {}), new Date().toISOString()]
        );
        res.status(200).json({ status: 'success', message: 'Command queued successfully.' });
    } catch (err) {
        console.error('Failed to queue command:', err.message);
        res.status(500).json({ error: 'Failed to queue command' });
    }
});

app.post('/api/admin/deploy', requireAuth, async (req, res) => {
    // 1. Extract the new installTiming flag from the request body
    const { deviceId, packageId, installTiming } = req.body;

    try {
        const pkg = await db.get('SELECT * FROM winget_packages WHERE package_id = ?', [packageId]);
        if (!pkg) return res.status(404).json({ error: 'Package not found in catalog.' });

        // 2. Add InstallTiming to the payload (defaulting to Immediate if omitted)
        const commandPayload = {
            Action: 'InstallApp',
            Name: pkg.name,
            Url: pkg.download_url,
            Hash: pkg.sha256_hash,
            Arguments: pkg.silent_flags,
            InstallTiming: installTiming || 'Immediate' 
        };

        await db.run(
            'INSERT INTO command_queue (device_id, action, payload, queued_at) VALUES (?, ?, ?, ?)',
            [deviceId, 'InstallApp', JSON.stringify(commandPayload), new Date().toISOString()]
        );

        res.status(200).json({ status: 'success' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// Get all Deploy Bundles
app.get('/api/admin/deploy-bundles', requireAuth, async (req, res) => {
    try {
        const bundles = await db.all(`
            SELECT b.id, b.name, b.description, COUNT(i.package_id) as item_count
            FROM deploy_bundles b
            LEFT JOIN deploy_bundle_items i ON b.id = i.bundle_id
            GROUP BY b.id ORDER BY b.name ASC
        `);
        res.status(200).json(bundles);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create a new Deploy Bundle
app.post('/api/admin/deploy-bundles', requireAuth, async (req, res) => {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Bundle name is required.' });
    try {
        await db.run('INSERT INTO deploy_bundles (name, description) VALUES (?, ?)', [name, description || '']);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: 'Failed to create bundle. Name may exist.' }); }
});

// Get current bundle assignments for a specific app
app.get('/api/admin/deploy-bundles/assignments/:packageId', requireAuth, async (req, res) => {
    try {
        const assignments = await db.all(
            'SELECT bundle_id FROM deploy_bundle_items WHERE package_id = ?', 
            [req.params.packageId]
        );
        res.status(200).json(assignments.map(a => a.bundle_id));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Assign an app to multiple Deploy Bundles
app.post('/api/admin/deploy-bundles/assign', requireAuth, async (req, res) => {
    const { packageId, bundleIds } = req.body; // bundleIds is an array
    if (!packageId || !Array.isArray(bundleIds)) return res.status(400).json({ error: 'Invalid payload.' });

    try {
        // Clear old assignments for this specific app
        await db.run('DELETE FROM deploy_bundle_items WHERE package_id = ?', [packageId]);
        
        // Insert new ones
        for (const bId of bundleIds) {
            await db.run('INSERT INTO deploy_bundle_items (bundle_id, package_id) VALUES (?, ?)', [bId, packageId]);
        }
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// Get all bundle assignments for a specific group
app.get('/api/admin/groups/:groupId/bundles', requireAuth, async (req, res) => {
    try {
        const deploy = await db.all('SELECT bundle_id FROM group_deploy_bundles WHERE group_id = ?', [req.params.groupId]);
        const policy = await db.all('SELECT bundle_id FROM group_policy_bundles WHERE group_id = ?', [req.params.groupId]);
        
        res.status(200).json({
            deployBundles: deploy.map(d => d.bundle_id),
            policyBundles: policy.map(p => p.bundle_id)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update bundle assignments for a specific group
app.post('/api/admin/groups/:groupId/bundles', requireAuth, async (req, res) => {
    const groupId = req.params.groupId;
    const { deployBundles, policyBundles } = req.body; // Arrays of bundle IDs

    try {
        // Wrap in a transaction to ensure clean wipes and inserts
        await db.run('BEGIN TRANSACTION');
        
        // Wipe and replace Deploy Bundles
        await db.run('DELETE FROM group_deploy_bundles WHERE group_id = ?', [groupId]);
        if (deployBundles && deployBundles.length > 0) {
            for (const bId of deployBundles) {
                await db.run('INSERT INTO group_deploy_bundles (group_id, bundle_id) VALUES (?, ?)', [groupId, bId]);
            }
        }

        // Wipe and replace Policy Bundles
        await db.run('DELETE FROM group_policy_bundles WHERE group_id = ?', [groupId]);
        if (policyBundles && policyBundles.length > 0) {
            for (const bId of policyBundles) {
                await db.run('INSERT INTO group_policy_bundles (group_id, bundle_id) VALUES (?, ?)', [groupId, bId]);
            }
        }

        await db.run('COMMIT');
        res.status(200).json({ status: 'success' });
    } catch (err) {
        await db.run('ROLLBACK');
        res.status(500).json({ error: err.message });
    }
});



app.post('/api/admin/sync', requireAuth, async (req, res) => {
    const { packageId } = req.body;
    
    if (!packageId) return res.status(400).json({ error: 'Package ID is required.' });

    try {
        const recipe = await syncWinGetPackage(packageId);
        res.status(200).json({ status: 'success', recipe });
    } catch (err) {
        console.error('Crawler failed:', err.message);
        res.status(500).json({ error: 'Sync failed: ' + err.message });
    }
});

app.get('/api/admin/catalog', requireAuth, async (req, res) => {
    try {
        const catalog = await db.all('SELECT * FROM winget_packages ORDER BY name ASC');
        res.status(200).json(catalog);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch software catalog' });
    }
});

app.get('/api/admin/search', requireAuth, async (req, res) => {
    const query = req.query.q;
    if (!query) return res.status(400).json({ error: 'Search query required.' });

    try {
        const searchUrl = `https://api.github.com/search/code?q=${encodeURIComponent(query)}+in:path+path:manifests+repo:microsoft/winget-pkgs`;
        
        const response = await fetch(searchUrl, {
            headers: { 
                'User-Agent': 'MiniDM-Admin-Dashboard',
                'Authorization': `Bearer ${GITHUB_TOKEN}` // <-- Added Auth Header
            }
        });

        if (!response.ok) throw new Error(`GitHub API Error: ${response.status}`);
        
        const data = await response.json();
        const packageIds = new Set();
        
        data.items.forEach(item => {
            const fileName = item.name;
            if (fileName.endsWith('.yaml')) {
                const pkgId = fileName.replace('.installer.yaml', '')
                                      .replace('.locale.yaml', '')
                                      .replace('.yaml', '');
                packageIds.add(pkgId);
            }
        });

        res.status(200).json(Array.from(packageIds).slice(0, 15));
    } catch (err) {
        console.error('Search failed:', err.message);
        res.status(500).json({ error: 'Search failed. Check your GitHub token.' });
    }
});

// --- Secure Telemetry / Audit Endpoint ---
app.post('/api/telemetry', async (req, res) => {
    const { deviceId, payload, signature } = req.body;
    
    if (!deviceId || !payload || !signature) {
        return res.status(400).json({ error: 'Malformed secure payload.' });
    }

    try {
        const device = await db.get('SELECT status, client_public_key FROM devices WHERE device_id = ?', [deviceId]);
        
        if (!device) return res.status(401).json({ error: 'Device not enrolled.' });
        if (device.status !== 'Active') return res.status(403).json({ error: 'Device pending administrator approval.' });

        // --- MUTUAL AUTHENTICATION: Verify the Agent's Signature ---
        const verify = crypto.createVerify('SHA256');
        verify.update(payload);
        verify.end();
        
        const publicKeyObject = {
            key: Buffer.from(device.client_public_key, 'base64'),
            format: 'der',
            type: 'pkcs1'
        };
        
        const isValid = verify.verify(publicKeyObject, signature, 'base64');
        
        if (!isValid) {
            console.log(`[CRITICAL] Telemetry signature verification failed for Device ID: ${deviceId}`);
            return res.status(401).json({ error: 'Invalid signature. Identity verification failed.' });
        }

        // --- Update the Command Queue Ledger ---
        const parsedPayload = JSON.parse(payload);
        const { commandId, executionStatus, exitCode, resultMessage } = parsedPayload;

        if (!commandId || !executionStatus) {
            return res.status(400).json({ error: 'Command ID and executionStatus are required in payload.' });
        }

        await db.run(`
            UPDATE command_queue 
            SET status = ?, exit_code = ?, result_message = ?, completed_at = ?
            WHERE id = ? AND device_id = ?
        `, [
            executionStatus,          // e.g., 'Completed' or 'Failed'
            exitCode || 0, 
            resultMessage || '', 
            new Date().toISOString(), 
            commandId, 
            deviceId
        ]);

        console.log(`[Telemetry] Updated command ${commandId} for device ${deviceId} to ${executionStatus}`);
        res.status(200).json({ status: 'success' });

    } catch (err) {
        console.error('Database error during telemetry update:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});


// Get all Policy Bundles
app.get('/api/admin/policy-bundles', requireAuth, async (req, res) => {
    try {
        const bundles = await db.all(`
            SELECT b.id, b.name, b.description, COUNT(i.policy_id) as item_count
            FROM policy_bundles b
            LEFT JOIN policy_bundle_items i ON b.id = i.bundle_id
            GROUP BY b.id ORDER BY b.name ASC
        `);
        res.status(200).json(bundles);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create a new Policy Bundle
app.post('/api/admin/policy-bundles', requireAuth, async (req, res) => {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Bundle name is required.' });
    try {
        await db.run('INSERT INTO policy_bundles (name, description) VALUES (?, ?)', [name, description || '']);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: 'Failed to create bundle. Name may exist.' }); }
});

// Get current bundle assignments for a specific policy
app.get('/api/admin/policy-bundles/assignments/:policyId', requireAuth, async (req, res) => {
    try {
        const assignments = await db.all(
            'SELECT bundle_id FROM policy_bundle_items WHERE policy_id = ?', 
            [req.params.policyId]
        );
        res.status(200).json(assignments.map(a => a.bundle_id));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Assign and Configure a policy across Policy Bundles
app.post('/api/admin/policy-bundles/assign', requireAuth, async (req, res) => {
    const { policyId, bundleIds, baseState, configuredElements } = req.body; 
    
    if (!policyId || !Array.isArray(bundleIds)) {
        return res.status(400).json({ error: 'Invalid payload.' });
    }

    try {
        // 1. Wipe old bundle assignments for this policy
        await db.run('DELETE FROM policy_bundle_items WHERE policy_id = ?', [policyId]);
        
        // 2. Insert new assignments WITH their configured parameters
        for (const bId of bundleIds) {
            await db.run(
                'INSERT INTO policy_bundle_items (bundle_id, policy_id, base_state, configured_elements) VALUES (?, ?, ?, ?)', 
                [bId, policyId, baseState, JSON.stringify(configuredElements || [])]
            );
        }
        res.status(200).json({ status: 'success' });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});


app.post('/api/admin/policy/import', requireAuth, upload.fields([{ name: 'admx', maxCount: 1 }, { name: 'adml', maxCount: 1 }]), async (req, res) => {
    try {
        if (!req.files || !req.files.admx || !req.files.adml) {
            return res.status(400).json({ error: 'Both ADMX and ADML files are required.' });
        }

        // fast-xml-parser configuration to capture XML attributes (which contain the Registry paths)
        const parser = new XMLParser({
            ignoreAttributes: false,
            attributeNamePrefix: "@_"
        });

        // 1. Parse the ADML (Language File) to build our String Dictionary
        const admlRaw = req.files.adml[0].buffer.toString('utf8');
        const admlData = parser.parse(admlRaw);
        
        const stringDictionary = {};
        
        // Safely navigate the ADML XML tree to find the string table
        const stringTable = admlData?.policyDefinitionResources?.resources?.stringTable?.string;
        if (stringTable) {
            // fast-xml-parser returns an object if there's only one item, or an array if multiple.
            const strings = Array.isArray(stringTable) ? stringTable : [stringTable];
            strings.forEach(str => {
                if (str['@_id'] && str['#text']) {
                    stringDictionary[str['@_id']] = str['#text'];
                }
            });
        }

        // 2. Parse the ADMX (Logic File)
        const admxRaw = req.files.admx[0].buffer.toString('utf8');
        const admxData = parser.parse(admxRaw);

        const policies = admxData?.policyDefinitions?.policies?.policy;
        if (!policies) {
            return res.status(400).json({ error: 'No policies found in the provided ADMX file.' });
        }

        const policyArray = Array.isArray(policies) ? policies : [policies];
        let importCount = 0;

        // 3. Loop through policies, match strings, extract elements, and insert to SQLite
        for (const pol of policyArray) {
            const policyId = pol['@_name'];
            const category = pol['@_class']; 
            const registryKey = pol['@_key'];
            const baseValueName = pol['@_valueName'] || null;

            if (!registryKey) continue; // Every policy must target a base registry key

            // Resolve the Main Policy Display Name
            let rawDisplayName = pol['@_displayName'] || policyId;
            let displayName = rawDisplayName;
            if (rawDisplayName.startsWith('$(string.') && rawDisplayName.endsWith(')')) {
                const stringKey = rawDisplayName.substring(9, rawDisplayName.length - 1);
                displayName = stringDictionary[stringKey] || stringKey;
            }

            const parsedElements = [];
            if (pol.elements) {
                for (const [elemType, elemData] of Object.entries(pol.elements)) {
                    if (elemType.startsWith('@_')) continue;

                    const elemArray = Array.isArray(elemData) ? elemData : [elemData];
                    
                    elemArray.forEach(e => {
                        const elemId = e['@_id'];
                        let elemLabel = elemId;
                        if (elemId && stringDictionary[elemId]) {
                            elemLabel = stringDictionary[elemId];
                        }

                        parsedElements.push({
                            type: elemType,             // e.g., 'text', 'decimal', 'enum', 'list'
                            id: elemId,                 // The internal ADMX ID
                            label: elemLabel,           // The human-readable label from ADML
                            valueName: e['@_valueName'] // The specific registry value to write this element to
                        });
                    });
                }
            }

            // Serialize the elements array to JSON for SQLite storage
            const elementsJson = JSON.stringify(parsedElements);

            // UPSERT into the database
            await db.run(`
                INSERT INTO policy_library (policy_id, display_name, category, registry_key, value_name, policy_type, elements)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(policy_id) DO UPDATE SET
                    display_name = excluded.display_name,
                    category = excluded.category,
                    registry_key = excluded.registry_key,
                    value_name = excluded.value_name,
                    elements = excluded.elements
            `, [policyId, displayName, category, registryKey, baseValueName, 'Complex', elementsJson]);

            importCount++;
        }


        res.status(200).json({ status: 'success', imported: importCount });

    } catch (err) {
        console.error('Policy Import Error:', err);
        res.status(500).json({ error: 'Failed to process policy templates. Ensure files are valid XML.' });
    }
});

app.get('/api/admin/policy', requireAuth, async (req, res) => {
    try {
        const policies = await db.all('SELECT * FROM policy_library ORDER BY display_name ASC');
        res.status(200).json(policies);
    } catch (err) {
        console.error('Failed to fetch policies:', err.message);
        res.status(500).json({ error: 'Failed to fetch policy library.' });
    }
});

app.post('/api/admin/policy/deploy', requireAuth, async (req, res) => {
    const { deviceId, policyId, baseState, configuredElements } = req.body;

    try {
        const policy = await db.get('SELECT * FROM policy_library WHERE policy_id = ?', [policyId]);
        if (!policy) return res.status(404).json({ error: 'Policy not found.' });

        // Build the complex payload for the C# Agent
        const commandPayload = {
            Action: 'SetRegistryComplex',
            PolicyName: policy.display_name,
            BaseRegistryKey: policy.registry_key,
            RegistryEdits: []
        };

        // Add the Base Policy Toggle (if a base valueName exists)
        if (policy.value_name) {
            commandPayload.RegistryEdits.push({
                ValueName: policy.value_name,
                Value: baseState,
                ValueType: 'DWORD'
            });
        }

        // Add the dynamic elements the admin filled out
        if (configuredElements && configuredElements.length > 0) {
            configuredElements.forEach(elem => {
                if (elem.valueName && elem.value !== "") {
                    commandPayload.RegistryEdits.push({
                        ValueName: elem.valueName,
                        Value: elem.type === 'DWORD' ? parseInt(elem.value, 10) : elem.value,
                        ValueType: elem.type
                    });
                }
            });
        }

        // Queue it for the agent
        await db.run(
            'INSERT INTO command_queue (device_id, action, payload, queued_at) VALUES (?, ?, ?, ?)',
            [deviceId, 'SetRegistryComplex', JSON.stringify(commandPayload), new Date().toISOString()]
        );

        res.status(200).json({ status: 'success', message: 'Complex policy queued.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



// Delete / Remove endpoints

// Get all apps inside a specific Deploy Bundle
app.get('/api/admin/deploy-bundles/:bundleId/items', requireAuth, async (req, res) => {
    try {
        const items = await db.all(`
            SELECT w.* FROM winget_packages w
            JOIN deploy_bundle_items dbi ON w.package_id = dbi.package_id
            WHERE dbi.bundle_id = ?
        `, [req.params.bundleId]);
        res.status(200).json(items);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Remove an app from a Deploy Bundle
app.delete('/api/admin/deploy-bundles/:bundleId/items/:packageId', requireAuth, async (req, res) => {
    try {
        await db.run('DELETE FROM deploy_bundle_items WHERE bundle_id = ? AND package_id = ?',
            [req.params.bundleId, req.params.packageId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete an app entirely from the Catalog
app.delete('/api/admin/catalog/:packageId', requireAuth, async (req, res) => {
    try {
        // ON DELETE CASCADE in SQLite will automatically remove it from deploy_bundle_items
        await db.run('DELETE FROM winget_packages WHERE package_id = ?', [req.params.packageId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get all policies inside a specific Policy Bundle
app.get('/api/admin/policy-bundles/:bundleId/items', requireAuth, async (req, res) => {
    try {
        const items = await db.all(`
            SELECT pl.* FROM policy_library pl
            JOIN policy_bundle_items pbi ON pl.policy_id = pbi.policy_id
            WHERE pbi.bundle_id = ?
        `, [req.params.bundleId]);
        res.status(200).json(items);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Remove a policy from a Policy Bundle
app.delete('/api/admin/policy-bundles/:bundleId/items/:policyId', requireAuth, async (req, res) => {
    try {
        await db.run('DELETE FROM policy_bundle_items WHERE bundle_id = ? AND policy_id = ?',
            [req.params.bundleId, req.params.policyId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete a policy entirely from the Library
app.delete('/api/admin/policy/:policyId', requireAuth, async (req, res) => {
    try {
        // ON DELETE CASCADE will automatically remove it from policy_bundle_items
        await db.run('DELETE FROM policy_library WHERE policy_id = ?', [req.params.policyId]);
        res.status(200).json({ status: 'success' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- Public/Agent API Endpoints ---
app.post('/api/enroll', async (req, res) => {
    const { enrollmentKey, clientPublicKey, deviceName } = req.body;
    console.log(`[${new Date().toISOString()}] Enrollment request received for device: ${deviceName || 'Unknown'}`);

    if (!clientPublicKey) return res.status(400).json({ error: 'Client Public Key is required.' });

    // Fetch the active key from tenant_data
    let validKey = null;
    try {
        const tenant = await db.get('SELECT enrollment_key FROM tenant_data WHERE id = 1');
        if (tenant) validKey = tenant.enrollment_key;
    } catch (err) {
        console.error('Failed to fetch tenant data during enrollment:', err);
    }

    let status = 'Pending';
    // Compare the submitted key to the database key
    if (validKey && enrollmentKey === validKey) {
        status = 'Active';
        console.log(`Device auto-approved using valid tenant enrollment key.`);
    } else {
         console.log(`Device marked as Pending. Invalid or missing enrollment key.`);
    }

    const deviceId = crypto.randomUUID();

    try {
        await db.run(
            'INSERT INTO devices (device_id, status, client_public_key, device_name, enrollment_date, last_seen) VALUES (?, ?, ?, ?, ?, ?)',
            [deviceId, status, clientPublicKey, deviceName, new Date().toISOString(), new Date().toISOString()]
        );
        res.status(200).json({ status: 'success', message: 'Enrollment successful.', deviceId, serverPublicKey: serverKeys.publicKey });
    } catch (err) {
        console.error('Database error during enrollment:', err.message);
        res.status(500).json({ error: 'Internal server error during enrollment.' });
    }
});

app.post('/api/checkin', async (req, res) => {
    const { deviceId, payload, signature } = req.body;
    
    if (!deviceId || !payload || !signature) {
        return res.status(400).json({ error: 'Malformed secure payload.' });
    }

    console.log(`[${new Date().toISOString()}] Secure check-in attempt from Device ID: ${deviceId}`);

    try {
        const device = await db.get('SELECT status, client_public_key FROM devices WHERE device_id = ?', [deviceId]);
        
        if (!device) return res.status(401).json({ error: 'Device not enrolled.' });
        if (device.status !== 'Active') return res.status(403).json({ error: 'Device pending administrator approval.' });

        // --- MUTUAL AUTHENTICATION: Verify the Agent's Signature ---
        const verify = crypto.createVerify('SHA256');
        verify.update(payload);
        verify.end();
        
        const publicKeyObject = {
            key: Buffer.from(device.client_public_key, 'base64'),
            format: 'der',
            type: 'pkcs1'
        };
        
        const isValid = verify.verify(publicKeyObject, signature, 'base64');
        
        if (!isValid) {
            console.log(`[CRITICAL] Signature verification failed for Device ID: ${deviceId}`);
            return res.status(401).json({ error: 'Invalid signature. Identity verification failed.' });
        }
        console.log(`Identity verified for Device ID: ${deviceId}`);

        await db.run('UPDATE devices SET last_seen = ? WHERE device_id = ?', [new Date().toISOString(), deviceId]);

        // --- Process Heartbeat Payload Data ---
        try {
            const parsedPayload = JSON.parse(payload);
            
            if (parsedPayload.inventory) {
                const { SerialNumber, Processor, RamMb } = parsedPayload.inventory;
                
                await db.run(`
                    INSERT INTO device_inventory (device_id, serial_number, processor, ram_mb, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET
                        serial_number = excluded.serial_number,
                        processor = excluded.processor,
                        ram_mb = excluded.ram_mb,
                        last_updated = excluded.last_updated
                `, [deviceId, SerialNumber, Processor, RamMb, new Date().toISOString()]);
            }
        } catch (parseErr) {
            console.error(`[WARNING] Failed to parse payload or update inventory for ${deviceId}:`, parseErr.message);
        }

        // --- Fetch Pending Commands from the Queue ---
        const pendingRows = await db.all("SELECT id, action, payload FROM command_queue WHERE device_id = ? AND status = 'Queued' ORDER BY queued_at ASC", [deviceId]);        const pendingCommands = [];

        for (const row of pendingRows) {
            const commandPayload = { Action: row.action, ...JSON.parse(row.payload) };
            const rawPayloadString = JSON.stringify(commandPayload);

            const sign = crypto.createSign('SHA256');
            sign.update(rawPayloadString);
            sign.end(); 
            const serverSignature = sign.sign(serverKeys.privateKey, 'base64');

        // pass the ID to the agent
        pendingCommands.push({ 
            commandId: row.id, 
            rawPayload: rawPayloadString, 
            signature: serverSignature 
        });

        // Update status to 'Sent'
        await db.run(
            'UPDATE command_queue SET status = ?, sent_at = ? WHERE id = ?', 
            ['Sent', new Date().toISOString(), row.id]
        );
        }
        
        res.status(200).json({ status: 'success', pendingCommands });

    } catch (err) {
        console.error('Database error during checkin:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

async function syncWinGetPackage(packageId) {
    const char = packageId.charAt(0).toLowerCase();
    const packagePath = packageId.split('.').join('/');
    
    const apiDirUrl = `https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/${char}/${packagePath}`;
    console.log(`[Crawler] Fetching versions from: ${apiDirUrl}`);
    
    const dirResponse = await fetch(apiDirUrl, {
        headers: { 
            'User-Agent': 'MiniDM-Agent-Crawler',
            'Authorization': `Bearer ${GITHUB_TOKEN}`
        }
    });

    if (!dirResponse.ok) throw new Error(`GitHub API Error: ${dirResponse.status}`);

    const files = await dirResponse.json();
    
    // 1. Filter out non-version folders (must start with a digit)
    const versions = files.filter(f => f.type === 'dir' && /^\d/.test(f.name));
    if (versions.length === 0) throw new Error('No valid version directories found.');

    // 2. Sort numerically (so 133.0 comes AFTER 99.0)
    versions.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }));
    
    const latestVersion = versions[versions.length - 1].name;
    console.log(`[Crawler] Resolved latest version: ${latestVersion}`);

    const manifestUrl = `https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/${char}/${packagePath}/${latestVersion}/${packageId}.installer.yaml`;
    console.log(`[Crawler] Fetching manifest: ${manifestUrl}`);
    
    const manifestResponse = await fetch(manifestUrl);
    if (!manifestResponse.ok) throw new Error(`Failed to fetch manifest: ${manifestResponse.status}`);
    
    const rawYaml = await manifestResponse.text(); 
    const data = yaml.load(rawYaml);

    const installer = data.Installers.find(i => i.Architecture === 'x64') || data.Installers[0];
    if (!installer) throw new Error('No valid installer found in manifest.');

    const rootSwitches = data.InstallerSwitches || {};
    const installerSwitches = installer.InstallerSwitches || {};

    // 1. Determine the exact packaging engine
    const type = (installer.InstallerType || data.InstallerType || '').toLowerCase();
    
    // 2. Build a context-aware fallback based on the engine's known standards
    let fallbackSilent = '/silent'; // Generic fallback for unknown EXEs
    
    if (type.includes('msi') || type.includes('wix')) {
        fallbackSilent = '/qn /norestart';
    } else if (type.includes('nullsoft')) {
        fallbackSilent = '/S'; // Must be capital S
    } else if (type.includes('inno')) {
        fallbackSilent = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART';
    } else if (type.includes('burn')) {
        fallbackSilent = '-quiet -norestart';
    }

    // 3. Prefer explicit manifest switches, but use our smart fallback if missing
    const silentFlags = installerSwitches.Silent 
                     || rootSwitches.Silent 
                     || installerSwitches.SilentWithProgress 
                     || rootSwitches.SilentWithProgress 
                     || fallbackSilent;


    const recipe = {
        package_id: packageId,
        name: data.PackageName || packageId,
        version: data.PackageVersion || latestVersion,
        download_url: installer.InstallerUrl,
        sha256_hash: installer.InstallerSha256,
        installer_type: installer.InstallerType || data.InstallerType || 'unknown', // Also grab root type!
        silent_flags: silentFlags
    };

    await db.run(`
        INSERT INTO winget_packages (package_id, name, version, download_url, sha256_hash, installer_type, silent_flags, last_synced)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(package_id) DO UPDATE SET
            version = excluded.version,
            download_url = excluded.download_url,
            sha256_hash = excluded.sha256_hash,
            silent_flags = excluded.silent_flags,
            last_synced = excluded.last_synced
    `, [recipe.package_id, recipe.name, recipe.version, recipe.download_url, recipe.sha256_hash, recipe.installer_type, recipe.silent_flags, new Date().toISOString()]);

    return recipe;
}


// --- Start Server ---
const PORT = process.env.PORT || 6112;
initializeServer().then(() => {
    app.listen(PORT, () => console.log(`MiniDM Backend running on http://localhost:${PORT}`));
}).catch(err => {
    console.error('Failed to initialize server:', err);
    process.exit(1);
});