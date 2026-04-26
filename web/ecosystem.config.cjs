module.exports = {
  apps: [
    {
      name: 'pwdnow',
      script: 'server.js',
      node_args: '--expose-gc',
      instances: 'max', // Run in cluster mode utilizing all CPUs
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      max_memory_restart: '1G',
      error_file: 'logs/err.log',
      out_file: 'logs/out.log',
      log_file: 'logs/combined.log',
      time: true
    }
  ]
};
