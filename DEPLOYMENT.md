# SecTools Deployment Guide

Complete guide for deploying SecTools Rails 8.0 application to an Ubuntu VPS with a subdomain.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Server Setup](#server-setup)
- [Application Deployment](#application-deployment)
- [SSL Configuration](#ssl-configuration)
- [Process Management](#process-management)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Local Requirements
- Git installed locally
- SSH access to your VPS
- Domain DNS configured to point to your VPS IP

### VPS Requirements
- Ubuntu 20.04 LTS or newer
- Minimum 2GB RAM (4GB recommended)
- 20GB disk space
- Root or sudo access
- Subdomain DNS record pointing to VPS IP (e.g., `sectools.yourdomain.com`)

---

## Server Setup

### 1. Initial Server Configuration

SSH into your VPS:
```bash
ssh root@your-vps-ip
# or
ssh your-user@your-vps-ip
```

Update system packages:
```bash
sudo apt update
sudo apt upgrade -y
```

Create deployment user (if not exists):
```bash
sudo adduser deploy
sudo usermod -aG sudo deploy
```

Switch to deploy user:
```bash
su - deploy
```

### 2. Install Required Dependencies

#### Install Ruby 3.3+ using rbenv
```bash
# Install dependencies
sudo apt install -y git curl libssl-dev libreadline-dev zlib1g-dev \
  autoconf bison build-essential libyaml-dev libreadline-dev \
  libncurses5-dev libffi-dev libgdbm-dev

# Install rbenv
curl -fsSL https://github.com/rbenv/rbenv-installer/raw/HEAD/bin/rbenv-installer | bash

# Add rbenv to bash profile
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc
source ~/.bashrc

# Install Ruby 3.3.0
rbenv install 3.3.0
rbenv global 3.3.0

# Verify installation
ruby -v
```

#### Install Node.js (for JavaScript assets)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node -v
npm -v
```

#### Install PostgreSQL (Database)
```bash
sudo apt install -y postgresql postgresql-contrib libpq-dev

# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database user
sudo -u postgres createuser -s deploy
sudo -u postgres psql -c "ALTER USER deploy WITH PASSWORD 'your_secure_password';"
```

#### Install Nginx (Web Server)
```bash
sudo apt install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

#### Install Redis (Optional - for background jobs)
```bash
sudo apt install -y redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

### 3. Install Application Gems

```bash
gem install bundler
gem install rails -v 8.0.0
```

---

## Application Deployment

### 1. Clone Repository

```bash
cd /home/deploy
git clone https://github.com/yourusername/SecTools.git
# or if using SSH keys:
# git clone git@github.com:yourusername/SecTools.git

cd SecTools
```

### 2. Configure Environment

Create production environment file:
```bash
nano .env.production
```

Add the following (customize values):
```bash
RAILS_ENV=production
SECRET_KEY_BASE=$(rails secret)
DATABASE_URL=postgresql://deploy:your_secure_password@localhost/sectools_production
RAILS_SERVE_STATIC_FILES=true
RAILS_LOG_TO_STDOUT=true

# Optional: Configure mailer if needed
# SMTP_ADDRESS=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=your_email@gmail.com
# SMTP_PASSWORD=your_app_password
```

Generate a secure secret key base:
```bash
rails secret
# Copy the output and add to .env.production as SECRET_KEY_BASE
```

### 3. Install Dependencies

```bash
# Install Ruby gems
bundle config set --local deployment 'true'
bundle config set --local without 'development test'
bundle install

# Install for PDF generation (Prawn gem)
sudo apt install -y libxml2-dev libxslt1-dev
```

### 4. Setup Database

```bash
# Create database
RAILS_ENV=production bundle exec rails db:create

# Run migrations
RAILS_ENV=production bundle exec rails db:migrate

# Optional: Load seed data
RAILS_ENV=production bundle exec rails db:seed
```

### 5. Precompile Assets

```bash
RAILS_ENV=production bundle exec rails assets:precompile
```

### 6. Test Application

Test that the app runs:
```bash
RAILS_ENV=production bundle exec rails server -b 0.0.0.0 -p 3000
```

Visit `http://your-vps-ip:3000` to verify. Press Ctrl+C to stop.

---

## Nginx Configuration

### 1. Create Nginx Site Configuration

```bash
sudo nano /etc/nginx/sites-available/sectools
```

Add the following configuration:
```nginx
upstream sectools_app {
    server 127.0.0.1:3000 fail_timeout=0;
}

server {
    listen 80;
    server_name sectools.yourdomain.com;

    root /home/deploy/SecTools/public;

    # Logs
    access_log /var/log/nginx/sectools_access.log;
    error_log /var/log/nginx/sectools_error.log;

    # Serve static files directly
    location ~ ^/(assets|packs)/ {
        gzip_static on;
        expires max;
        add_header Cache-Control public;
    }

    # Pass requests to Puma
    location / {
        proxy_pass http://sectools_app;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        # Timeouts for long-running scans
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
        send_timeout 300;
    }

    # Error pages
    error_page 500 502 503 504 /500.html;
    location = /500.html {
        root /home/deploy/SecTools/public;
    }
}
```

### 2. Enable Site

```bash
# Create symlink
sudo ln -s /etc/nginx/sites-available/sectools /etc/nginx/sites-enabled/

# Remove default site
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

---

## SSL Configuration

### Install Certbot for Let's Encrypt SSL

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d sectools.yourdomain.com

# Follow prompts:
# - Enter email address
# - Agree to terms
# - Choose to redirect HTTP to HTTPS (recommended)

# Test auto-renewal
sudo certbot renew --dry-run
```

Certbot will automatically update your Nginx configuration with SSL settings.

---

## Process Management

### Option 1: Systemd Service (Recommended)

Create systemd service file:
```bash
sudo nano /etc/systemd/system/sectools.service
```

Add the following:
```ini
[Unit]
Description=SecTools Rails Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/home/deploy/SecTools
Environment="RAILS_ENV=production"
Environment="PORT=3000"
EnvironmentFile=/home/deploy/SecTools/.env.production
ExecStart=/home/deploy/.rbenv/shims/bundle exec puma -C config/puma.rb
Restart=always
RestartSec=10
StandardOutput=append:/home/deploy/SecTools/log/puma.stdout.log
StandardError=append:/home/deploy/SecTools/log/puma.stderr.log

[Install]
WantedBy=multi-user.target
```

### Configure Puma

Create Puma configuration:
```bash
nano config/puma.rb
```

Add/modify:
```ruby
# Change to match your setup
max_threads_count = ENV.fetch("RAILS_MAX_THREADS") { 5 }
min_threads_count = ENV.fetch("RAILS_MIN_THREADS") { max_threads_count }
threads min_threads_count, max_threads_count

# Specifies the `port` that Puma will listen on to receive requests
port ENV.fetch("PORT") { 3000 }

# Specifies the `environment` that Puma will run in
environment ENV.fetch("RAILS_ENV") { "production" }

# Specifies the number of `workers` to boot in clustered mode
workers ENV.fetch("WEB_CONCURRENCY") { 2 }

# Use the `preload_app!` method when specifying a `workers` number
preload_app!

# Allow puma to be restarted by `rails restart` command
plugin :tmp_restart

# Specify PID file location
pidfile ENV.fetch("PIDFILE") { "tmp/pids/puma.pid" }
```

### Start and Enable Service

```bash
# Create log directory
mkdir -p /home/deploy/SecTools/log

# Reload systemd
sudo systemctl daemon-reload

# Start service
sudo systemctl start sectools

# Enable on boot
sudo systemctl enable sectools

# Check status
sudo systemctl status sectools

# View logs
sudo journalctl -u sectools -f
```

### Service Management Commands

```bash
# Start
sudo systemctl start sectools

# Stop
sudo systemctl stop sectools

# Restart
sudo systemctl restart sectools

# Status
sudo systemctl status sectools

# View logs (real-time)
sudo journalctl -u sectools -f

# View last 100 lines
sudo journalctl -u sectools -n 100
```

### Option 2: Screen/Tmux (Quick & Simple)

For quick deployments without systemd:

Using Screen:
```bash
screen -S sectools
cd /home/deploy/SecTools
RAILS_ENV=production bundle exec rails server -b 0.0.0.0 -p 3000

# Detach: Ctrl+A, then D
# Reattach: screen -r sectools
```

Using Tmux:
```bash
tmux new -s sectools
cd /home/deploy/SecTools
RAILS_ENV=production bundle exec rails server -b 0.0.0.0 -p 3000

# Detach: Ctrl+B, then D
# Reattach: tmux attach -t sectools
```

---

## Updating the Application

### 1. Pull Latest Changes

```bash
cd /home/deploy/SecTools
git pull origin main
```

### 2. Update Dependencies

```bash
bundle install --deployment --without development test
```

### 3. Run Migrations

```bash
RAILS_ENV=production bundle exec rails db:migrate
```

### 4. Precompile Assets

```bash
RAILS_ENV=production bundle exec rails assets:precompile
```

### 5. Restart Application

```bash
sudo systemctl restart sectools
```

### Complete Update Script

Create an update script:
```bash
nano ~/update-sectools.sh
```

Add:
```bash
#!/bin/bash

set -e

echo "🔄 Updating SecTools..."

cd /home/deploy/SecTools

echo "📥 Pulling latest code..."
git pull origin main

echo "💎 Installing gems..."
bundle install --deployment --without development test

echo "🗄️  Running migrations..."
RAILS_ENV=production bundle exec rails db:migrate

echo "🎨 Precompiling assets..."
RAILS_ENV=production bundle exec rails assets:precompile

echo "🔄 Restarting service..."
sudo systemctl restart sectools

echo "✅ Update complete!"
echo "🌐 Visit: https://sectools.yourdomain.com"
```

Make executable:
```bash
chmod +x ~/update-sectools.sh
```

Run updates:
```bash
~/update-sectools.sh
```

---

## Maintenance

### Database Backup

Create backup script:
```bash
nano ~/backup-sectools-db.sh
```

Add:
```bash
#!/bin/bash

BACKUP_DIR="/home/deploy/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="sectools_production"

mkdir -p $BACKUP_DIR

echo "🗄️  Backing up database..."
pg_dump $DB_NAME | gzip > $BACKUP_DIR/sectools_backup_$DATE.sql.gz

echo "✅ Backup saved to: $BACKUP_DIR/sectools_backup_$DATE.sql.gz"

# Keep only last 7 days of backups
find $BACKUP_DIR -name "sectools_backup_*.sql.gz" -mtime +7 -delete
```

Make executable and run:
```bash
chmod +x ~/backup-sectools-db.sh
~/backup-sectools-db.sh
```

### Automated Daily Backups

```bash
crontab -e
```

Add:
```bash
# Daily backup at 2 AM
0 2 * * * /home/deploy/backup-sectools-db.sh
```

### Log Rotation

Create logrotate config:
```bash
sudo nano /etc/logrotate.d/sectools
```

Add:
```
/home/deploy/SecTools/log/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
}
```

### Monitor Disk Space

```bash
df -h
du -sh /home/deploy/SecTools
```

### Clear Old Logs

```bash
cd /home/deploy/SecTools
RAILS_ENV=production bundle exec rails log:clear
```

---

## Troubleshooting

### Check Application Status

```bash
# Service status
sudo systemctl status sectools

# Application logs
tail -f /home/deploy/SecTools/log/production.log

# Puma logs
sudo journalctl -u sectools -f

# Nginx logs
sudo tail -f /var/log/nginx/sectools_error.log
sudo tail -f /var/log/nginx/sectools_access.log
```

### Common Issues

#### 1. Application Won't Start

Check logs:
```bash
sudo journalctl -u sectools -n 100
cat /home/deploy/SecTools/log/production.log
```

Verify permissions:
```bash
ls -la /home/deploy/SecTools
# Should be owned by deploy user
```

#### 2. Database Connection Errors

Test database connection:
```bash
psql -U deploy -d sectools_production -h localhost
```

Check DATABASE_URL in `.env.production`:
```bash
cat /home/deploy/SecTools/.env.production | grep DATABASE_URL
```

#### 3. 502 Bad Gateway

Check if Rails is running:
```bash
sudo systemctl status sectools
```

Check Nginx configuration:
```bash
sudo nginx -t
```

Restart both:
```bash
sudo systemctl restart sectools
sudo systemctl restart nginx
```

#### 4. Assets Not Loading

Precompile assets:
```bash
cd /home/deploy/SecTools
RAILS_ENV=production bundle exec rails assets:precompile
sudo systemctl restart sectools
```

#### 5. SSL Certificate Issues

Renew certificate manually:
```bash
sudo certbot renew
sudo systemctl reload nginx
```

#### 6. Out of Memory

Check memory usage:
```bash
free -h
```

Reduce Puma workers in `config/puma.rb`:
```ruby
workers ENV.fetch("WEB_CONCURRENCY") { 1 }
```

### Performance Optimization

#### 1. Enable Gzip Compression

Add to Nginx config:
```nginx
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml font/truetype font/opentype application/vnd.ms-fontobject image/svg+xml;
```

#### 2. Add Swap Space (If Low RAM)

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Make permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

#### 3. Monitor Resources

```bash
# CPU and Memory
htop

# Disk I/O
iotop

# Network
iftop
```

---

## Security Best Practices

### 1. Firewall Configuration

```bash
# Install UFW
sudo apt install -y ufw

# Allow SSH
sudo ufw allow OpenSSH

# Allow HTTP/HTTPS
sudo ufw allow 'Nginx Full'

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

### 2. Secure PostgreSQL

```bash
sudo nano /etc/postgresql/*/main/pg_hba.conf
```

Ensure local connections require password:
```
local   all   all   md5
```

### 3. Regular Updates

```bash
# Update system packages weekly
sudo apt update && sudo apt upgrade -y

# Update Ruby gems
cd /home/deploy/SecTools
bundle update --conservative
```

### 4. Fail2Ban (Optional)

```bash
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## Quick Reference

### Essential Commands

```bash
# View application
https://sectools.yourdomain.com

# Restart app
sudo systemctl restart sectools

# View logs
sudo journalctl -u sectools -f
tail -f /home/deploy/SecTools/log/production.log

# Update app
cd /home/deploy/SecTools && git pull && bundle install && RAILS_ENV=production rails db:migrate assets:precompile && sudo systemctl restart sectools

# Backup database
pg_dump sectools_production | gzip > backup_$(date +%Y%m%d).sql.gz

# Rails console (production)
cd /home/deploy/SecTools
RAILS_ENV=production bundle exec rails console

# Check disk space
df -h

# Check memory
free -h
```

### Important Paths

- Application: `/home/deploy/SecTools`
- Logs: `/home/deploy/SecTools/log/`
- Nginx config: `/etc/nginx/sites-available/sectools`
- Systemd service: `/etc/systemd/system/sectools.service`
- SSL certificates: `/etc/letsencrypt/live/sectools.yourdomain.com/`

---

## Support

For issues or questions:
- Check logs first: `sudo journalctl -u sectools -f`
- Review Rails logs: `tail -f /home/deploy/SecTools/log/production.log`
- Check Nginx errors: `tail -f /var/log/nginx/sectools_error.log`

## License

This deployment guide is provided as-is for the SecTools application.
