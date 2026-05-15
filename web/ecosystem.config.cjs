module.exports = {
  apps: [
    {
      name: 'pwdnow',
      script: 'server.js',
      node_args: '',
      instances: 'max', // Run in cluster mode utilizing all CPUs
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'development',
        PORT: 1234,
        VAULT_SOCKET: '/tmp/vault-daemon-run/vault.sock'
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 1234,
        VAULT_SOCKET: '/tmp/vault-daemon-run/vault.sock'
      },
      max_memory_restart: '1G',
      error_file: 'logs/err.log',
      out_file: 'logs/out.log',
      log_file: 'logs/combined.log',
      time: true
    }
  ]
};
