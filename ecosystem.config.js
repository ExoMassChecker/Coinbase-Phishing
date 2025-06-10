module.exports = {
  apps: [
    {
      name: 'phishing-main',
      script: 'index.js',
      env: {
        NODE_ENV: 'production',
        PORT: 5000
      },
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      max_memory_restart: '500M',
      error_file: './logs/main-error.log',
      out_file: './logs/main-out.log',
      log_file: './logs/main-combined.log',
      time: true,
      restart_delay: 2000,
      max_restarts: 10,
      min_uptime: '10s'
    },
    {
      name: 'membership-server',
      script: 'membership-server.js',
      env: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      max_memory_restart: '300M',
      error_file: './logs/membership-error.log',
      out_file: './logs/membership-out.log',
      log_file: './logs/membership-combined.log',
      time: true,
      restart_delay: 2000,
      max_restarts: 10,
      min_uptime: '10s'
    },
    {
      name: 'discord-bot',
      script: 'discord-bot.js',
      env: {
        NODE_ENV: 'production'
      },
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      max_memory_restart: '200M',
      error_file: './logs/discord-error.log',
      out_file: './logs/discord-out.log',
      log_file: './logs/discord-combined.log',
      time: true,
      restart_delay: 5000,
      max_restarts: 5,
      min_uptime: '30s'
    }
  ]
}; 