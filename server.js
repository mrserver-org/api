const express = require("express");
const os = require("os");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { spawn } = require("child_process");
const pty = require("node-pty");
const osu = require("os-utils");
const bcrypt = require("bcrypt");
const si = require('systeminformation');
const app = express();
app.use(express.json());
var expressWs = require('express-ws')(app);
let systemSettings = {};

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

app.get("/api/system", async (req, res) => {
  try {
    const [
      cpuLoad,
      memory,
      osInfo,
      network,
      disk,
      processes,
      temps,
      battery,
      versions,
      users,
      services,
      system
    ] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.osInfo(),
      si.networkInterfaces(),
      si.fsSize(),
      si.processes(),
      si.cpuTemperature(),
      si.battery(),
      si.versions(),
      si.users(),
      si.services('*'),
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
        uptime: osInfo.uptime,
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
        processes: processes.all,
        running: processes.running,
        blocked: processes.blocked,
        sleeping: processes.sleeping,
        users: users.length,
        services: services.length,
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

app.get("/api/users", (req, res) => {
  res.json(JSON.parse(fs.readFileSync(`${os.homedir()}/.mrserver/users.json`)));
});

app.post("/api/system_settings", (req, res) => {
  systemSettings = { auto_update: req.body.auto_update, timezone: req.body.timezone };
  res.json({ settings: systemSettings });
});
app.get("/api/file_manager/list", (req, res) => {
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
  res.download(filePath);
});

app.get("/api/file_manager/content", (req, res) => {
  let filePath = req.query.path;
  res.send(fs.readFileSync(filePath));
});

app.post("/api/file_manager/write", (req, res) => {
  let filePath = req.body.path;
  let content = req.body.content;
  console.log(filePath);
  console.log(content);
  fs.writeFile(filePath, content);
  res.end();
});

app.post("/api/file_manager/operate", (req, res) => {
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
  } else if (op === "set_wallpaper") {
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
app.post("/api/file_manager/upload", upload.single("file"), (req, res) => {
  res.end();
});
app.get("/api/terminal_stream", (req, res) => {
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

app.get("/api/terminal_exec", (req, res) => {
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

const terminals = new Map();

app.ws('/api/terminal', (ws, req) => {
  console.log('[BACKEND] WebSocket connection received');
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
});


app.listen(9091, () => {
  console.log("[BACKEND] STATUS:LISTENING\n[BACKEND] PORT:9091");
});
