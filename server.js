const express = require("express");
const os = require("os");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { spawn, exec } = require("child_process");
const pty = require("node-pty");
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const osu = require("os-utils");
const bcrypt = require("bcrypt");
const si = require('systeminformation');
const bodyParser = require('body-parser');
const app = express();
app.use(express.json());
var expressWs = require('express-ws')(app);
let systemSettings = {};
const ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  GUEST: 'guest'
};
const jobs = new Map();
const JOBS_FILE = path.join(path.join(os.homedir(), '.mrserver'), 'jobs.json');

function loadJobs() {
  try {
    if (fs.existsSync(JOBS_FILE)) {
      const jobsData = JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8'));
      jobsData.forEach(job => {
        try {
          const task = cron.schedule(job.schedule, () => {
            exec(job.command, (error, stdout, stderr) => {
              if (error) {
                console.error(`Error executing job ${job.name}: ${error.message}`);
                return;
              }
              console.log(`Job ${job.name} executed successfully`);
            });
          }, {
            scheduled: job.running
          });
          
          jobs.set(job.id, {
            ...job,
            task
          });
        } catch (err) {
          console.error(`Failed to schedule job ${job.name}: ${err.message}`);
        }
      });
      console.log(`Loaded ${jobs.size} jobs from storage`);
    }
  } catch (err) {
    console.error('Error loading jobs:', err);
  }
}

function saveJobs() {
  try {
    const jobsData = Array.from(jobs.values()).map(job => ({
      id: job.id,
      name: job.name,
      command: job.command,
      schedule: job.schedule,
      running: job.running,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt
    }));
    fs.writeFileSync(JOBS_FILE, JSON.stringify(jobsData, null, 2));
  } catch (err) {
    console.error('Error saving jobs:', err);
  }
}

function getNextRunTime(cronExpression) {
  try {
    return cron.validate(cronExpression) ? 
      new Date(cron.schedule(cronExpression).nextDates().toISOString()) : null;
  } catch (err) {
    return null;
  }
}

function formatNextRunTime(date) {
  if (!date) return 'Invalid schedule';
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

const authenticate = async (req, res, next) => {
  const username = req.headers.username;
  const password = req.headers.password;

  if (!username || !password) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const usersPath = `${os.homedir()}/.mrserver/users.json`;
    if (!fs.existsSync(usersPath)) {
      return res.status(500).json({ error: 'Users database not found' });
    }
    const users = JSON.parse(fs.readFileSync(usersPath));
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const passwordMatch = (password == user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

const authorize = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (allowedRoles.includes(req.user.role)) {
      next();
    } else {
      res.status(403).json({ error: 'Insufficient permissions' });
    }
  };
};

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, username, password");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

app.use(bodyParser.json());

app.post("/api/login", async (req, res) => {
  const username = req.headers.username;
  const password = req.headers.password;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const usersPath = `${os.homedir()}/.mrserver/users.json`;
    if (!fs.existsSync(usersPath)) {
      return res.status(500).json({ error: 'Users database not found' });
    }
    const users = JSON.parse(fs.readFileSync(usersPath));
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const passwordMatch = (password == user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({ 
      username: user.username, 
      role: user.role || ROLES.USER,
      success: true 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get("/api/system", async (req, res) => {
  try {
    const [
      cpuLoad,
      memory,
      osInfo,
      network,
      disk,
      temps,
      battery,
      versions,
      system
    ] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.osInfo(),
      si.networkInterfaces(),
      si.fsSize(),
      si.cpuTemperature(),
      si.battery(),
      si.versions(),
      si.system()
    ]);
    const response = {
      os: {
        platform: osInfo.platform,
        distro: osInfo.distro,
        version: osInfo.release,
        kernel: osInfo.kernel,
        arch: osInfo.arch,
        hostname: osInfo.hostname,
        logofile: osInfo.logofile
      },

      hardware: {
        manufacturer: system.manufacturer,
        model: system.model,
        version: system.version,
        serial: system.serial,
        uuid: system.uuid,
        sku: system.sku,
        virtual: system.virtual
      },

      cpu: {
        manufacturer: cpuLoad.manufacturer,
        brand: cpuLoad.brand,
        speed: cpuLoad.speed,
        cores: cpuLoad.cores,
        physical_cores: cpuLoad.physicalCores,
        processors: cpuLoad.processors,
        load: cpuLoad.currentLoad,
        load_user: cpuLoad.currentLoadUser,
        load_system: cpuLoad.currentLoadSystem,
        temperature: temps.main
      },

      memory: {
        total: memory.total,
        free: memory.free,
        used: memory.used,
        active: memory.active,
        swap_total: memory.swaptotal,
        swap_used: memory.swapused,
        swap_free: memory.swapfree
      },

      storage: {
        disks: disk.map(d => ({
          fs: d.fs,
          type: d.type,
          size: d.size,
          used: d.used,
          available: d.available,
          mount: d.mount
        }))
      },

      network: {
        interfaces: network.map(n => ({
          iface: n.iface,
          ip4: n.ip4,
          ip6: n.ip6,
          mac: n.mac,
          speed: n.speed
        }))
      },

      status: {
        battery: battery.hasBattery ? {
          level: battery.percent,
          charging: battery.isCharging,
          remaining: battery.timeRemaining
        } : null
      },

      software: {
        node: versions.node,
        npm: versions.npm,
        yarn: versions.yarn,
        docker: versions.docker
      }
    };

    res.json(response);

  } catch (error) {
    console.error('System info error:', error);
    res.status(500).json({ error: 'Failed to get system information' });
  }
});

app.get("/api/users", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  const users = JSON.parse(fs.readFileSync(`${os.homedir()}/.mrserver/users.json`));
  const safeUsers = users.map(user => ({
    username: user.username,
    role: user.role || ROLES.USER,
  }));
  res.json(safeUsers);
});

app.post("/api/users", authenticate, authorize([ROLES.ADMIN]), async (req, res) => {
  const { username, password, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  if (!Object.values(ROLES).includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  try {
    const usersPath = `${os.homedir()}/.mrserver/users.json`;
    let users = [];
    
    if (fs.existsSync(usersPath)) {
      users = JSON.parse(fs.readFileSync(usersPath));
    } else {
      if (!fs.existsSync(`${os.homedir()}/.mrserver`)) {
        fs.mkdirSync(`${os.homedir()}/.mrserver`, { recursive: true });
      }
    }

    const existingUserIndex = users.findIndex(u => u.username === username);
    const hashedPassword = await bcrypt.hash(password, 10);
    if (existingUserIndex >= 0) {
      users[existingUserIndex] = {
        ...users[existingUserIndex],
        password: hashedPassword,
        role
      };
    } else {
      users.push({
        username,
        password: hashedPassword,
        role
      });
    }

    fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
    res.json({ success: true });
  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ error: 'Failed to create/update user' });
  }
});

app.delete("/api/users/:username", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  const usernameToDelete = req.params.username;
  if (usernameToDelete === req.user.username) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  try {
    const usersPath = `${os.homedir()}/.mrserver/users.json`;
    if (!fs.existsSync(usersPath)) {
      return res.status(404).json({ error: 'Users database not found' });
    }

    let users = JSON.parse(fs.readFileSync(usersPath));
    const initialLength = users.length;
    users = users.filter(u => u.username !== usernameToDelete);
    
    if (users.length === initialLength) {
      return res.status(404).json({ error: 'User not found' });
    }

    fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
    res.json({ success: true });
  } catch (error) {
    console.error('User deletion error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.post("/api/system_settings", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  systemSettings = { auto_update: req.body.auto_update, timezone: req.body.timezone };
  res.json({ settings: systemSettings });
});

app.get("/api/file_manager/list", authenticate, authorize([ROLES.ADMIN, ROLES.USER]), (req, res) => {
  let target = req.query.path || ".";
  fs.readdir(target, (err, files) => {
    if (err) return res.status(500).json({ error: "Unable to read directory" });
    let items = [];
    let pending = files.length;
    if (!pending) return res.json(items);
    files.forEach((file) => {
      let fullPath = path.join(target, file);
      fs.stat(fullPath, (err, stats) => {
        items.push({ name: file, path: fullPath, is_dir: stats && stats.isDirectory() });
        pending--;
        if (!pending) res.json(items);
      });
    });
  });
});
app.get("/api/file_manager/download", (req, res) => {
  let filePath = req.query.path;
  let username = req.query.username;
  let password = req.query.password;
  if (!username || !password) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  const usersPath = `${os.homedir()}/.mrserver/users.json`;
  if (!fs.existsSync(usersPath)) {
    return res.status(500).json({ error: 'Users database not found' });
  }
  const users = JSON.parse(fs.readFileSync(usersPath));
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const passwordMatch = (password == user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.role !== ROLES.ADMIN && user.role !== ROLES.USER) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  if (user.role === ROLES.GUEST) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  if (user.role === ROLES.USER && !filePath.startsWith(os.homedir())) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  res.download(filePath);
});

app.get("/api/file_manager/content", authenticate, authorize([ROLES.ADMIN, ROLES.USER]), (req, res) => {
  let filePath = req.query.path;
  res.send(fs.readFileSync(filePath));
});

app.post("/api/file_manager/write", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  let filePath = req.body.path;
  let content = req.body.content;
  console.log(filePath);
  console.log(content);
  fs.writeFile(filePath, content);
  res.end();
});

app.post("/api/file_manager/operate", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  let op = req.body.operation;
  let source = req.body.source;
  if (op === "delete") {
    fs.stat(source, (err, stats) => {
      if (err) return res.status(500).end();
      if (stats.isDirectory()) {
        fs.rmdir(source, { recursive: true }, (err) => {
          if (err) return res.status(500).end();
          res.end();
        });
      } else {
        fs.unlink(source, (err) => {
          if (err) return res.status(500).end();
          res.end();
        });
      }
    });
	} else if (op === "//TODO") { //TODO
    res.end();
  } else {
    res.status(400).end();
  }
});
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      let target = req.body.path || __dirname;
      if (!fs.existsSync(target)) fs.mkdirSync(target, { recursive: true });
      cb(null, target);
    },
    filename: (req, file, cb) => {
      cb(null, file.originalname);
    }
  })
});
app.post("/api/file_manager/upload", authenticate, authorize([ROLES.ADMIN, ROLES.USER]), upload.single("file"), (req, res) => {
  res.end();
});
app.get("/api/terminal_stream", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  let command = req.query.command;
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive"
  });
  let proc = spawn(command, [], { shell: true });
  proc.stdout.on("data", (data) => {
    res.write("data: " + data.toString() + "\n\n");
  });
  proc.stderr.on("data", (data) => {
    res.write("data: " + data.toString() + "\n\n");
  });
  proc.on("close", () => {
    res.end();
  });
});

app.get("/api/terminal_exec", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  let command = req.query.command;
  let proc = spawn(command, [], { shell: true });
  proc.stdout.on("data", (data) => {
    res.write(data.toString());
  });
  proc.stderr.on("data", (data) => {
    res.write(data.toString());
  });
  proc.on("close", (code) => {
    res.end();
  });
});

app.get('/api/processes', authenticate, authorize([ROLES.ADMIN, ROLES.USER]), (req, res) => {
    let command;
    if (process.platform === 'win32') {
        command = 'tasklist /fo csv';
    } else {
        command = 'ps aux';
    }
    
    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        
        const processes = [];
        if (process.platform === 'win32') {
            const lines = stdout.split('\n').slice(1);
            lines.forEach(line => {
                if (line.trim()) {
                    const parts = line.split('","');
                    if (parts.length >= 5) {
                        const name = parts[0].replace('"', '');
                        const pid = parseInt(parts[1]);
                        const memUsage = parseFloat(parts[4].replace(/[^\d.-]/g, ''));
                        processes.push({
                            pid,
                            name,
                            cpu: Math.random() * 5,
                            memory: memUsage / 1024,
                            status: 'Running'
                        });
                    }
                }
            });
        } else {
            const lines = stdout.split('\n').slice(1);
            lines.forEach(line => {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 11) {
                    const user = parts[0];
                    const pid = parseInt(parts[1]);
                    const cpu = parseFloat(parts[2]);
                    const mem = parseFloat(parts[3]);
                    const status = parts[7];
                    const command = parts.slice(10).join(' ');
                    
                    processes.push({
                        pid,
                        name: command.length > 30 ? command.substring(0, 30) + '...' : command,
                        cpu,
                        memory: mem,
                        status
                    });
                }
            });
        }
        
        res.json({ processes });
    });
});

app.post("/api/kill", authenticate, authorize([ROLES.ADMIN]), (req, res) => {
	const { pid } = req.body;
    if (!pid) {
        return res.status(400).json({ success: false, error: 'PID is required' });
    }
    let command;
    if (process.platform === 'win32') {
        command = `taskkill /F /PID ${pid}`;
    } else {
        command = `kill -9 ${pid}`;
    }
    
    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }
        res.json({ success: true, message: `Process with PID ${pid} has been terminated` });
    });
});

app.get('/api/cron/jobs', authenticate, authorize([ROLES.ADMIN, ROLES.USER]), (req, res) => {
  try {
    const jobsArray = Array.from(jobs.values()).map(job => {
      const nextRun = job.running ? 
        formatNextRunTime(getNextRunTime(job.schedule)) : 'Paused';
      return {
        id: job.id,
        name: job.name,
        command: job.command,
        schedule: job.schedule,
        running: job.running,
        nextRun,
        createdAt: job.createdAt,
        updatedAt: job.updatedAt
      };
    });
    res.json({ success: true, jobs: jobsArray });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/cron/job/:id', authenticate, authorize([ROLES.ADMIN, ROLES.USER]), (req, res) => {
  try {
    const job = jobs.get(req.params.id);
    if (!job) {
      return res.status(404).json({ success: false, error: 'Job not found' });
    }
    const nextRun = job.running ? 
      formatNextRunTime(getNextRunTime(job.schedule)) : 'Paused';
    res.json({
      success: true,
      job: {
        id: job.id,
        name: job.name,
        command: job.command,
        schedule: job.schedule,
        running: job.running,
        nextRun,
        createdAt: job.createdAt,
        updatedAt: job.updatedAt
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/cron/add', authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  try {
    const { name, command, schedule } = req.body;
    if (!name || !command || !schedule) {
      return res.status(400).json({ 
        success: false, 
        error: 'Name, command, and schedule are required' 
      });
    }
    if (!cron.validate(schedule)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid cron schedule expression' 
      });
    }
    const id = uuidv4();
    const now = new Date();
    try {
      const task = cron.schedule(schedule, () => {
        exec(command, (error, stdout, stderr) => {
          if (error) {
            console.error(`Error executing job ${name}: ${error.message}`);
            return;
          }
          console.log(`Job ${name} executed successfully`);
        });
      });
      const job = {
        id,
        name,
        command,
        schedule,
        running: true,
        task,
        createdAt: now,
        updatedAt: now
      };
      jobs.set(id, job);
      saveJobs();
      res.json({ 
        success: true, 
        message: 'Job created successfully',
        id
      });
    } catch (err) {
      res.status(400).json({ 
        success: false, 
        error: `Error scheduling job: ${err.message}` 
      });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/cron/update/:id', authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  try {
    const { name, command, schedule } = req.body;
    const id = req.params.id;
    if (!jobs.has(id)) {
      return res.status(404).json({ success: false, error: 'Job not found' });
    }
    if (!name || !command || !schedule) {
      return res.status(400).json({ 
        success: false, 
        error: 'Name, command, and schedule are required' 
      });
    }
    if (!cron.validate(schedule)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid cron schedule expression' 
      });
    }
    const job = jobs.get(id);
    if (job.task) {
      job.task.stop();
    }
    try {
      const task = cron.schedule(schedule, () => {
        exec(command, (error, stdout, stderr) => {
          if (error) {
            console.error(`Error executing job ${name}: ${error.message}`);
            return;
          }
          console.log(`Job ${name} executed successfully`);
        });
      }, {
        scheduled: job.running
      });
      const updatedJob = {
        ...job,
        name,
        command,
        schedule,
        task,
        updatedAt: new Date()
      };
      jobs.set(id, updatedJob);
      saveJobs();
      res.json({ 
        success: true, 
        message: 'Job updated successfully' 
      });
    } catch (err) {
      res.status(400).json({ 
        success: false, 
        error: `Error scheduling job: ${err.message}` 
      });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/cron/delete/:id', authenticate, authorize([ROLES.ADMIN]), (req, res) => {
  try {
    const id = req.params.id;
    if (!jobs.has(id)) {
      return res.status(404).json({ success: false, error: 'Job not found' });
    }
    const job = jobs.get(id);
    if (job.task) {
      job.task.stop();
    }
    jobs.delete(id);
    saveJobs();
    res.json({ 
      success: true, 
      message: 'Job deleted successfully' 
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/cron/pause/:id', (req, res) => {
  try {
    const id = req.params.id;
    if (!jobs.has(id)) {
      return res.status(404).json({ success: false, error: 'Job not found' });
    }
    const job = jobs.get(id);
    if (job.task) {
      job.task.stop();
    }
    job.running = false;
    job.updatedAt = new Date();
    jobs.set(id, job);
    saveJobs();
    res.json({ 
      success: true, 
      message: 'Job paused successfully' 
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/cron/resume/:id', (req, res) => {
  try {
    const id = req.params.id;
    if (!jobs.has(id)) {
      return res.status(404).json({ success: false, error: 'Job not found' });
    }
    const job = jobs.get(id);
    if (job.task) {
      job.task.start();
    }
    job.running = true;
    job.updatedAt = new Date();
    jobs.set(id, job);
    saveJobs();
    res.json({ 
      success: true, 
      message: 'Job resumed successfully' 
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

const terminals = new Map();

app.ws('/api/terminal', async (ws, req) => {
  console.log('[BACKEND] WebSocket connection established');
  if (!req.query.username || !req.query.password) {
    ws.send(JSON.stringify({ error: 'Authentication required' }));
    return ws.close();
  }
  const { username, password } = req.query;
  
  if (!username || !password) {
    ws.send(JSON.stringify({ error: 'Authentication required' }));
    return ws.close();
  }
  
  try {
    const usersPath = `${os.homedir()}/.mrserver/users.json`;
    if (!fs.existsSync(usersPath)) {
      ws.send(JSON.stringify({ error: 'Users database not found' }));
      return ws.close();
    }

    const users = JSON.parse(fs.readFileSync(usersPath));
    const user = users.find(u => u.username === username);

    if (!user) {
      ws.send(JSON.stringify({ error: 'Invalid credentials' }));
      return ws.close();
    }

    const passwordMatch = (password == user.password);
    if (!passwordMatch) {
      ws.send(JSON.stringify({ error: 'Invalid credentials' }));
      return ws.close();
    }

    if (user.role !== ROLES.ADMIN) {
      ws.send(JSON.stringify({ error: `Insufficient permissions. Got: ${user.role}` }));
      console.log(`[BACKEND] ${user.role} tried to access the terminal.`);
      return ws.close();
    }
    
    console.log('[BACKEND] WebSocket connection authenticated');
    let shell = os.platform() === "win32" ? "cmd.exe" : "bash";
    let sessionId = req.query.id || Math.random().toString(36).substr(2, 9);
    let termProcess;
    
    if (terminals.has(sessionId)) {
      console.log(`[BACKEND] Reattaching to session: ${sessionId}`);
      termProcess = terminals.get(sessionId);
    } else {
      console.log(`[BACKEND] Starting new session: ${sessionId}`);
      termProcess = pty.spawn(shell, [], { name: 'xterm-color', cols: 120, rows: 40 });
      terminals.set(sessionId, termProcess);
    }
    
    termProcess.on('data', (data) => {
      if (ws.readyState === ws.OPEN) {
        ws.send(data);
      }
    });

    ws.on('message', (msg) => {
      const parsedMsg = JSON.parse(msg);
      if (parsedMsg.type === 'resize') {
        const { cols, rows } = parsedMsg;
        termProcess.resize(cols, rows);
        console.log(`[BACKEND] Resized terminal to: ${cols}x${rows}`);
      } else {
        termProcess.write(parsedMsg.key);
      }
    });

    ws.on('close', () => {
      console.log(`[BACKEND] Client disconnected from session: ${sessionId}`);
      setTimeout(() => {
        if (terminals.get(sessionId) === termProcess) {
          terminals.delete(sessionId);
        }
      }, 30000);
    });

    ws.send(JSON.stringify({ sessionId }));
  } catch (error) {
    console.error('WebSocket authentication error:', error);
    ws.send(JSON.stringify({ error: 'Authentication failed' }));
    return ws.close();
  }
});

app.listen(9091, () => {
  console.log("[BACKEND] STATUS:LISTENING\n[BACKEND] PORT:9091");
});
