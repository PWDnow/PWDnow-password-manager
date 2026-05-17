const path = require('path');
const AUTH_DATA_DIR = path.join(__dirname, 'auth_data');

module.exports = {
  apps: [
    {
      name: 'pwdnow',
      script: 'server.js',
      node_args: '',
      // H-01 fix: pin to a single worker (exec_mode: fork) because the server
      // holds in-memory session and rate-limit state. Cluster mode with 'max'
      // instances causes state fragmentation across processes.
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'development',
        PORT: 1234,
        VAULT_SOCKET: '/run/vault-daemon/vault.sock',
        VAULT_DATA_DIR: AUTH_DATA_DIR
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 1234,
        VAULT_SOCKET: '/run/vault-daemon/vault.sock',
        // server.js:29 defaults to /var/lib/vault-server in production; that path
        // needs root to create. Pin to the existing auth_data/ dir which already
        // holds user records, so PM2 production restarts don't EACCES on mkdir.
        VAULT_DATA_DIR: AUTH_DATA_DIR
      },
      max_memory_restart: '1G',
      // wait_ready: PM2 waits for process.send('ready') before marking as online.
      // This prevents Nginx from routing to a worker that hasn't bound its port yet.
      wait_ready: true,
      listen_timeout: 10000,   // ms: how long to wait for process.send('ready')
      // kill_timeout must exceed DRAIN_TIMEOUT_MS (25 000) in server.js so PM2
      // doesn't SIGKILL during graceful drain.
      kill_timeout: 30000,
      error_file: 'logs/err.log',
      out_file: 'logs/out.log',
      log_file: 'logs/combined.log',
      time: true
    }
  ]
};
