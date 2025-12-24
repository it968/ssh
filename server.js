const express = require('express');
const { Client } = require('ssh2');
const app = express();

app.use(express.json());

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const validToken = process.env.API_SECRET || 'change-me-in-production';
  
  if (token === validToken) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

app.post('/ssh/execute', authenticate, async (req, res) => {
  const { host, port = 22, username, password, privateKey, command } = req.body;

  if (!host || !username || !command) {
    return res.status(400).json({ 
      error: 'Missing required fields',
      required: ['host', 'username', 'command']
    });
  }

  if (!password && !privateKey) {
    return res.status(400).json({ 
      error: 'Either password or privateKey must be provided'
    });
  }

  const conn = new Client();

  try {
    const result = await executeSSH(conn, {
      host,
      port: parseInt(port),
      username,
      password,
      privateKey
    }, command);

    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message
    });
  }
});

function executeSSH(conn, credentials, command) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';

    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          conn.end();
          return reject(err);
        }

        stream
          .on('close', (code) => {
            conn.end();
            resolve({
              stdout: stdout.trim(),
              stderr: stderr.trim(),
              exitCode: code,
              command,
              host: credentials.host
            });
          })
          .on('data', (data) => {
            stdout += data.toString();
          })
          .stderr.on('data', (data) => {
            stderr += data.toString();
          });
      });
    })
    .on('error', reject)
    .connect(credentials);
  });
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SSH Gateway running on port ${PORT}`);
  console.log(`Set API_SECRET environment variable for security`);
});
