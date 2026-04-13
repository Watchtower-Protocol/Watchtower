const express = require('express');
const http = require('http');
const crypto = require('crypto');
const cors = require('cors'); 
const { exec } = require('child_process');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Will restrict this to frontend domain later
        methods: ["GET", "POST"]
    }
});

const port = process.env.WATCHTOWER_API_PORT || 3000;

// ------------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------------
const BIND_ADDRESS = process.env.WATCHTOWER_BIND_ADDRESS || '0.0.0.0'; 
const API_KEY = process.env.WATCHTOWER_API_KEY || "WATCHTOWER_DEFAULT_KEY"; 
let c2Queue = {};

console.log(`[Watchtower Command Center] Active API Key: ${API_KEY}`);
console.log(`[Watchtower API Gateway] Listening on ${BIND_ADDRESS}:${port}`);

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.raw({ type: 'application/zip', limit: '50mb' }));
app.use('/updates', express.static(__dirname + '/updates'));
app.use('/assets', express.static(path.join(__dirname, '../assets')));

// SECURITY: IP Whitelisting Middleware
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip === "169.254.204.75" || ip === "::ffff:169.254.204.75" || ip.includes("100.")) {
        next();
    } else {
        console.warn(`[SECURITY] Blocked unauthorized access attempt from IP: ${ip}`);
        res.status(403).send("403 Forbidden: Access restricted to Tailscale/Local network.");
    }
});

// ------------------------------------------------------------------
// IN-MEMORY DATABASE (MVP)
// ------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const DB_FILE = process.env.WATCHTOWER_DB_PATH || path.join(__dirname, '../data/watchtower_db.json');
if (!fs.existsSync(path.dirname(DB_FILE))) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
}


let alertsDB = [];
let threatDB = [];
let assetRegistry = {}; // New Device/User Catalog
let globalInventory = {}; // { Hostname: [ {name, hash, uptime...} ] }
let groupDB = {
    "Default": {
        "ENABLE_FIM": true, "ENABLE_ORACLE": true, "ENABLE_BEHAVIORAL": true, "ENABLE_DECOY": true,
        "ENABLE_COMPLIANCE": true, "ENABLE_ROLLBACK": true, "ENABLE_YARA": true, "ENABLE_NDR": true,
        "WATCHTOWER_AUDIT_MODE": true
    }
};
let deviceGroupMap = {}; // { Hostname: "Group_Name" }

if (fs.existsSync(DB_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        alertsDB = data.alerts || [];
        threatDB = data.threats || [];
        assetRegistry = data.assets || {};
        groupDB = data.groups || groupDB;
        deviceGroupMap = data.deviceGroups || {};
        console.log(`[Watchtower DB] Loaded ${alertsDB.length} alerts, ${threatDB.length} threats, and ${Object.keys(assetRegistry).length} known assets.`);
    } catch (e) {
        console.error('[Watchtower DB] Failed to load DB, starting fresh.');
    }
}

function saveDB() {
    fs.writeFileSync(DB_FILE, JSON.stringify({ alerts: alertsDB, threats: threatDB, assets: assetRegistry, groups: groupDB, deviceGroups: deviceGroupMap }, null, 2));
}

function registerAsset(source, ip) {
    const key = source || ip || 'UnknownDevice';
    if (!assetRegistry[key]) {
        assetRegistry[key] = {
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            incident_count: 1
        };
        console.log(`[ASSET CATALOG] Discovered new network entity: ${key}`);
        io.emit('new_asset_discovered', { id: key, data: assetRegistry[key] });
    } else {
        assetRegistry[key].last_seen = new Date().toISOString();
        assetRegistry[key].incident_count++;
    }
}

// ------------------------------------------------------------------
// WEBSOCKETS (Task 1.2)
// ------------------------------------------------------------------

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (token === API_KEY) {
        return next();
    }
    console.warn(`[WebSocket Auth] Blocked unauthorized connection attempt from ${socket.id}`);
    return next(new Error('Authentication error'));
});

io.on('connection', (socket) => {
    console.log(`[WebSocket] Client connected: ${socket.id}`);
    
    // Send initial state upon connection
    socket.emit('sync_state', {
        alerts: alertsDB.slice(0, 50),
        threats: threatDB.slice(0, 50),
        assets: assetRegistry,
        inventory: globalInventory,
        groups: groupDB,
        deviceGroups: deviceGroupMap
    });

    
    socket.on('c2_command', (cmd) => {
    console.log(`[C2 COMMAND RECEIVED] Action: ${cmd.action}, Target: ${cmd.target}, Host: ${cmd.host}`);
    
    // If it's a remote host, queue it for the beacon
    if (cmd.host && cmd.host !== 'mac-mini-hub' && cmd.host !== 'Local-Node' && cmd.host !== 'localhost' && cmd.host !== 'Austins-Mac-mini.local') {
        if (!c2Queue[cmd.host]) c2Queue[cmd.host] = [];
        c2Queue[cmd.host].push({ action: cmd.action, target: cmd.target, timestamp: Date.now() });
        console.log(`[C2 QUEUED] Command queued for remote host: ${cmd.host}`);
        
        io.emit('new_threat_intel', {
            id: crypto.randomUUID(),
            ingested_at: new Date().toISOString(),
            source: "Watchtower Command",
            title: `C2 Queued for ${cmd.host}: ${cmd.action.toUpperCase()}`,
            ai_verdict: "PENDING_BEACON",
            ai_reason: `Waiting for ${cmd.host} to check in and pull the command...`,
            severity: "warning"
        });
        return;
    }

    // Local execution
    const scriptPath = path.join(__dirname, '../core/watchtower_quarantine.py');
    const venvPython = process.env.PYTHON_BIN || 'python3';
    const { execFile } = require('child_process');
    
    execFile(venvPython, [scriptPath, '--action', cmd.action, '--target', cmd.target], (err, stdout, stderr) => {
        const resultText = stdout || stderr || err?.message || 'Unknown Error';
        if (err) console.error(`[C2 ERROR] ${resultText}`);
        else console.log(`[C2 SUCCESS] ${resultText}`);
        io.emit('c2_result', { action: cmd.action, target: cmd.target, result: resultText.trim() });
        
        io.emit('new_threat_intel', {
            id: crypto.randomUUID(),
            ingested_at: new Date().toISOString(),
            source: "Watchtower Command",
            title: `C2 Execution: ${cmd.action.toUpperCase()}`,
            ai_verdict: "RESOLVED",
            ai_reason: resultText.trim(),
            severity: "success"
        });
    });
});

socket.on('disconnect', () => {
        console.log(`[WebSocket] Client disconnected: ${socket.id}`);
    });
});

// ------------------------------------------------------------------
// MIDDLEWARE (API AUTH ONLY)
// ------------------------------------------------------------------
const authenticate = (req, res, next) => {
    const clientKey = req.headers['x-api-key'];
    if (req.method === 'GET' && (req.path === '/api/alerts' || req.path.startsWith('/api/memory/search'))) {
        return next();
    }

    if (!clientKey || clientKey !== API_KEY) {
        console.warn(`[Auth Failure] IP: ${req.ip}. Received Key: '${clientKey ? clientKey.substring(0,5)+'...' : 'None'}'`);
        return res.status(401).json({ error: 'Unauthorized: Invalid or missing API Key' });
    }
    next();
};

// ------------------------------------------------------------------
// ROUTES - API V1 (Legacy Support)
// ------------------------------------------------------------------
app.get('/api/v1/heartbeat', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

app.get('/api/agents', (req, res) => {
    res.json([{ id: 'mac-studio', hostname: 'Austins-Mac-mini.local', status: 'online', last_seen: new Date().toISOString() }]);
});

app.post('/api/alerts', authenticate, (req, res) => {
    const alert = req.body;
    const enrichedAlert = {
        id: crypto.randomUUID(),
        received_at: new Date().toISOString(),
        ...alert
    };
    alertsDB.unshift(enrichedAlert);
    if (alertsDB.length > 500) alertsDB.pop();
    saveDB();
    
    console.log(`[ALERT V1] ${alert.device?.hostname || 'Unknown'} | File: ${alert.file_path} | Event: ${alert.event_type}`);
    io.emit('new_fim_alert', enrichedAlert); // Emit to websocket
    
    res.status(201).json({ status: 'received', id: enrichedAlert.id });
});

app.get('/api/alerts', (req, res) => {
    res.json(alertsDB);
});

// ------------------------------------------------------------------
// ROUTES - API V2 (Task 1.3 & Network Topography)
// ------------------------------------------------------------------
app.post('/api/v2/infrastructure', authenticate, (req, res) => {
    const payload = req.body;
    const infraPath = path.join(__dirname, '../data/infrastructure.json');
    let infra = [];
    if (fs.existsSync(infraPath)) {
        try { infra = JSON.parse(fs.readFileSync(infraPath, 'utf8')); } catch(e){}
    }
    // Prevent duplicates
    infra = infra.filter(i => i.ip !== payload.ip);
    infra.push(payload);
    fs.writeFileSync(infraPath, JSON.stringify(infra, null, 2));
    res.json({ status: 'ok', msg: 'Infrastructure added securely.' });
});

app.delete('/api/v2/infrastructure', authenticate, (req, res) => {
    const infraPath = path.join(__dirname, '../data/infrastructure.json');
    if (fs.existsSync(infraPath)) fs.unlinkSync(infraPath);
    res.json({ status: 'ok', msg: 'Infrastructure cleared.' });
});

app.get('/api/v2/topology', authenticate, (req, res) => {
    const topoPath = path.join(__dirname, '../data/detailed_network_topology.csv');
    if (!fs.existsSync(topoPath)) return res.json([]);
    const data = fs.readFileSync(topoPath, 'utf8');
    const lines = data.split('\n').filter(l => l.trim().length > 0);
    if(lines.length < 2) return res.json([]);
    const headers = lines[0].split(',');
    const results = [];
    for(let i=1; i<lines.length; i++) {
        const obj = {};
        const currentline = lines[i].split(',');
        for(let j=0; j<headers.length; j++){
            obj[headers[j]] = currentline[j];
        }
        results.push(obj);
    }
    res.json(results);
});

app.delete('/api/v2/topology', authenticate, (req, res) => {
    const topoPath = path.join(__dirname, '../data/detailed_network_topology.csv');
    const jsonPath = path.join(__dirname, '../data/historical_topology.json');
    if (fs.existsSync(topoPath)) fs.unlinkSync(topoPath);
    if (fs.existsSync(jsonPath)) fs.unlinkSync(jsonPath);
    
    // Also clear raw dumps
    const dumpsDir = path.join(__dirname, '../data/raw_mac_dumps');
    if (fs.existsSync(dumpsDir)) {
        fs.readdirSync(dumpsDir).forEach(f => fs.unlinkSync(path.join(dumpsDir, f)));
    }
    
    res.json({ status: 'ok', msg: 'Topology cache cleared.' });
});

app.post('/api/v2/ingest/fim', authenticate, (req, res) => {
    const payload = req.body;
    const enrichedPayload = {
        id: crypto.randomUUID(),
        ingested_at: new Date().toISOString(),
        ...payload
    };
    alertsDB.unshift(enrichedPayload);
    registerAsset(enrichedPayload.source, enrichedPayload.ip);
    if (alertsDB.length > 500) alertsDB.pop();
    saveDB();

    console.log(`[INGEST V2 FIM] Received telemetry from ${payload.source || 'unknown sensor'}`);
    io.emit('new_fim_alert', enrichedPayload);
    
    res.status(201).json({ status: 'ingested', id: enrichedPayload.id });
});

app.post('/api/v2/ingest/inventory', authenticate, (req, res) => {
    const payload = req.body;
    const host = payload.source;
    if (!host) return res.status(400).json({error: "Missing source"});
    
    globalInventory[host] = payload.inventory;
    io.emit('new_inventory_update', { host: host, inventory: payload.inventory });
    res.status(200).json({ status: 'ingested' });
});


app.get('/api/v2/c2/beacon', authenticate, (req, res) => {
    const host = req.query.host;
    if (!host) return res.status(400).json({ error: 'Host parameter required' });
    
    // Auto-enroll unseen beacons into Default Map
    if(!deviceGroupMap[host]) {
        deviceGroupMap[host] = "Default";
        saveDB();
        io.emit('policy_sync', { groups: groupDB, deviceGroups: deviceGroupMap });
    }
    
    const commands = c2Queue[host] || [];
    c2Queue[host] = []; // clear after fetching
    
    res.json({ status: 'ok', commands });
});

app.get('/api/v2/policies/sync', authenticate, (req, res) => {
    const host = req.query.host;
    if (!host) return res.status(400).json({ error: 'Host parameter required' });
    
    if(!deviceGroupMap[host]) {
        deviceGroupMap[host] = "Default";
        saveDB();
    }
    
    const groupName = deviceGroupMap[host];
    const policy = groupDB[groupName] || groupDB["Default"];
    
    res.json({ status: 'ok', policy: policy, group: groupName });
});

app.post('/api/v2/policies/update', authenticate, (req, res) => {
    const { group, policy, host, newGroup } = req.body;
    
    if (host && newGroup) {
        if (!groupDB[newGroup]) groupDB[newGroup] = {...groupDB["Default"]};
        deviceGroupMap[host] = newGroup;
        saveDB();
        
        if (!c2Queue[host]) c2Queue[host] = [];
        c2Queue[host].push({ action: "UPDATE_POLICY", target: "Refresh", timestamp: Date.now() });
        console.log(`[POLICY] Assigned ${host} to Group '${newGroup}'`);
        
    } else if (group && policy) {
        groupDB[group] = policy;
        saveDB();
        
        Object.keys(deviceGroupMap).forEach(h => {
             if (deviceGroupMap[h] === group) {
                 if (!c2Queue[h]) c2Queue[h] = [];
                 c2Queue[h].push({ action: "UPDATE_POLICY", target: "Refresh", timestamp: Date.now() });
             }
        });
        console.log(`[POLICY] Updated group '${group}'`);
    }
    
    io.emit('policy_sync', { groups: groupDB, deviceGroups: deviceGroupMap });
    res.json({ status: 'ok' });
});

app.post('/api/v2/ota/upload', authenticate, (req, res) => {
    const groupName = req.query.group;
    if (!groupName) return res.status(400).json({ error: 'Group parameter required' });

    const otaDir = __dirname + '/updates';
    if (!fs.existsSync(otaDir)) fs.mkdirSync(otaDir, { recursive: true });
    
    // We expect the payload to be the raw buffer of the zip file handled by express.raw
    const zipPath = otaDir + '/update_core.zip';
    
    try {
        fs.writeFileSync(zipPath, req.body);
        
        // Generate HMAC signature natively using API_KEY
        const crypto = require('crypto');
        const fileHmac = crypto.createHmac('sha256', API_KEY).update(req.body).digest('hex');
        
        let hostsUpdated = 0;
        const targetUrl = `http://${req.headers.host}/updates/update_core.zip`;
        
        Object.keys(deviceGroupMap).forEach(h => {
             if (deviceGroupMap[h] === groupName || groupName === "ALL") {
                 if (!c2Queue[h]) c2Queue[h] = [];
                 c2Queue[h].push({ action: "UPDATE_CORE", target: targetUrl, hmac: fileHmac, timestamp: Date.now() });
                 hostsUpdated++;
             }
        });
        
        console.log(`[OTA] Queued UPDATE_CORE for ${hostsUpdated} host(s) in group ${groupName}`);
        res.json({ status: 'ok', hostsUpdated });
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/v2/ingest/threat', authenticate, (req, res) => {
    const payload = req.body;
    const enrichedPayload = {
        id: crypto.randomUUID(),
        ingested_at: new Date().toISOString(),
        ...payload
    };
    threatDB.unshift(enrichedPayload);
    registerAsset(enrichedPayload.source, enrichedPayload.ip);
    if (threatDB.length > 500) threatDB.pop();
    saveDB();

    console.log(`[INGEST V2 THREAT] Received intel from ${payload.source || 'unknown sensor'}`);
    io.emit('new_threat_intel', enrichedPayload);
    
    // TIER 1: AUTONOMOUS REMEDIATION (THE BRAIN)
    if (process.env.AUTO_REMEDIATE === 'true' && (enrichedPayload.ai_verdict === 'MALICIOUS' || (enrichedPayload.severity === 'high' && enrichedPayload.event_type?.includes('AD_SECURITY_EVENT')))) {
        const host = enrichedPayload.source;
        // Attempt to extract target from title/filepath, fallback to unknown
        const target = enrichedPayload.file_path || "UnknownTarget"; 
        
        console.log(`[!] AUTONOMOUS REMEDIATION TRIGGERED for ${host}. Threat level: HIGH.`);
        
        if (host && host !== 'mac-mini-hub' && host !== 'Local-Node' && host !== 'Austins-Mac-mini.local' && host !== 'localhost') {
            if (!c2Queue[host]) c2Queue[host] = [];
            
            // Queue quarantine/disable command automatically
            const action = enrichedPayload.event_type?.includes('AD') ? 'disable_user' : 'quarantine';
            c2Queue[host].push({ action: action, target: target, timestamp: Date.now() });
            
            console.log(`[C2 AUTO-QUEUED] ${action} command queued for ${host}`);
            
            io.emit('new_threat_intel', {
                id: crypto.randomUUID(),
                ingested_at: new Date().toISOString(),
                source: "Watchtower Autonomous Responder",
                title: `Auto-Remediation Triggered: ${action.toUpperCase()}`,
                ai_verdict: "PENDING_BEACON",
                ai_reason: `AI flagged event as Malicious/High Severity. Command queued for remote host: ${host}.`,
                severity: "warning"
            });
        }
    }
    
    res.status(201).json({ status: 'ingested', id: enrichedPayload.id });
});

// --- SOVEREIGN COGNITIVE ENGINE (SCE) ENDPOINT ---
app.get('/api/memory/search', authenticate, (req, res) => {
    const query = req.query.q;
    if (!query) {
        return res.status(400).json({ error: 'Query parameter "q" is required.' });
    }

    const scriptPath = path.join(__dirname, '../core/search_vector_index.py');
    const venvPython = process.env.PYTHON_BIN || 'python3';
    
    const { execFile } = require('child_process');
    execFile(venvPython, [scriptPath, query], (error, stdout, stderr) => {
        if (error) {
            console.error(`[SCE] Search Error: ${error}`);
            return res.status(500).json({ error: 'Failed to execute search script.', details: stderr });
        }
        try {
            const jsonStart = stdout.indexOf('{');
            if(jsonStart === -1) throw new Error("No JSON found in output");
            const cleanJson = stdout.substring(jsonStart);
            
            const results = JSON.parse(cleanJson);
            res.json(results);
        } catch (parseError) {
            console.error(`[SCE] JSON Parse Error: ${parseError}`);
            res.status(500).json({ error: 'Failed to parse search script output.', details: stdout });
        }
    });
});

// ------------------------------------------------------------------
// START
// ------------------------------------------------------------------
server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.error(`[FATAL] Port ${port} is occupied. Retrying in 3 seconds...`);
        setTimeout(() => {
            server.close();
            server.listen(port, BIND_ADDRESS);
        }, 3000);
    }
});

server.listen(port, BIND_ADDRESS, () => {
    console.log(`[Watchtower Command Center API] Server listening on http://${BIND_ADDRESS}:${port}`);
    console.log(`[Watchtower Command Center API] WebSocket Server attached.`);
});