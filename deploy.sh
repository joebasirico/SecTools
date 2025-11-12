#!/bin/bash

# SecTools Deployment Script for Ubuntu VPS
# This script automates the deployment of SecTools to a fresh Ubuntu server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_USER="deploy"
APP_NAME="sectools"
APP_DIR="/home/$DEPLOY_USER/SecTools"
RUBY_VERSION="3.3.0"

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║       SecTools Deployment Script                 ║"
echo "║       Rails 8.0 Security Tools Application       ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print step
print_step() {
    echo -e "${GREEN}▶ $1${NC}"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Please do not run as root. Run as a sudo user instead."
    exit 1
fi

# Get configuration from user
echo ""
print_step "Configuration"
echo ""

read -p "Enter your subdomain (e.g., sectools.yourdomain.com): " SUBDOMAIN
read -p "Enter your email for SSL certificate: " SSL_EMAIL
read -sp "Enter PostgreSQL password for deploy user: " DB_PASSWORD
echo ""
read -p "Enter your GitHub repository URL: " REPO_URL

echo ""
print_warning "Please ensure:"
echo "  1. DNS record for $SUBDOMAIN points to this server"
echo "  2. Ports 80 and 443 are open in firewall"
echo "  3. You have sudo privileges"
echo ""
read -p "Press Enter to continue or Ctrl+C to abort..."

# Update system
print_step "Updating system packages..."
sudo apt update
sudo apt upgrade -y

# Install basic dependencies
print_step "Installing dependencies..."
sudo apt install -y git curl libssl-dev libreadline-dev zlib1g-dev \
    autoconf bison build-essential libyaml-dev libreadline-dev \
    libncurses5-dev libffi-dev libgdbm-dev nodejs npm \
    postgresql postgresql-contrib libpq-dev nginx redis-server \
    libxml2-dev libxslt1-dev

# Install rbenv if not already installed
if [ ! -d "$HOME/.rbenv" ]; then
    print_step "Installing rbenv..."
    curl -fsSL https://github.com/rbenv/rbenv-installer/raw/HEAD/bin/rbenv-installer | bash

    # Add to bashrc
    echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(rbenv init -)"' >> ~/.bashrc

    # Load rbenv
    export PATH="$HOME/.rbenv/bin:$PATH"
    eval "$(rbenv init -)"
else
    print_warning "rbenv already installed, skipping..."
fi

# Install Ruby
if ! rbenv versions | grep -q "$RUBY_VERSION"; then
    print_step "Installing Ruby $RUBY_VERSION (this may take a while)..."
    rbenv install $RUBY_VERSION
    rbenv global $RUBY_VERSION
else
    print_warning "Ruby $RUBY_VERSION already installed, skipping..."
fi

# Install Rails
print_step "Installing Rails 8.0..."
gem install bundler rails -v 8.0.0 --no-document

# Configure PostgreSQL
print_step "Configuring PostgreSQL..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database user if doesn't exist
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DEPLOY_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $DEPLOY_USER WITH PASSWORD '$DB_PASSWORD' CREATEDB;"

# Clone repository
if [ ! -d "$APP_DIR" ]; then
    print_step "Cloning repository..."
    git clone "$REPO_URL" "$APP_DIR"
else
    print_warning "Application directory already exists, pulling latest changes..."
    cd "$APP_DIR"
    git pull origin main
fi

cd "$APP_DIR"

# Create .env.production
print_step "Creating production environment file..."
SECRET_KEY=$(openssl rand -hex 64)
cat > .env.production << EOF
RAILS_ENV=production
SECRET_KEY_BASE=$SECRET_KEY
DATABASE_URL=postgresql://$DEPLOY_USER:$DB_PASSWORD@localhost/${APP_NAME}_production
RAILS_SERVE_STATIC_FILES=true
RAILS_LOG_TO_STDOUT=true
EOF

print_step "Installing Ruby gems..."
bundle config set --local deployment 'true'
bundle config set --local without 'development test'
bundle install

# Setup database
print_step "Setting up database..."
RAILS_ENV=production bundle exec rails db:create
RAILS_ENV=production bundle exec rails db:migrate

# Precompile assets
print_step "Precompiling assets..."
RAILS_ENV=production bundle exec rails assets:precompile

# Configure Puma
print_step "Configuring Puma..."
cat > config/puma.rb << 'EOF'
max_threads_count = ENV.fetch("RAILS_MAX_THREADS") { 5 }
min_threads_count = ENV.fetch("RAILS_MIN_THREADS") { max_threads_count }
threads min_threads_count, max_threads_count

port ENV.fetch("PORT") { 3000 }
environment ENV.fetch("RAILS_ENV") { "production" }
workers ENV.fetch("WEB_CONCURRENCY") { 2 }

preload_app!
plugin :tmp_restart
pidfile ENV.fetch("PIDFILE") { "tmp/pids/puma.pid" }
EOF

# Create systemd service
print_step "Creating systemd service..."
sudo tee /etc/systemd/system/$APP_NAME.service > /dev/null << EOF
[Unit]
Description=SecTools Rails Application
After=network.target

[Service]
Type=simple
User=$DEPLOY_USER
WorkingDirectory=$APP_DIR
Environment="RAILS_ENV=production"
Environment="PORT=3000"
EnvironmentFile=$APP_DIR/.env.production
ExecStart=$HOME/.rbenv/shims/bundle exec puma -C config/puma.rb
Restart=always
RestartSec=10
StandardOutput=append:$APP_DIR/log/puma.stdout.log
StandardError=append:$APP_DIR/log/puma.stderr.log

[Install]
WantedBy=multi-user.target
EOF

# Create log directory
mkdir -p "$APP_DIR/log"

# Configure Nginx
print_step "Configuring Nginx..."
sudo tee /etc/nginx/sites-available/$APP_NAME > /dev/null << EOF
upstream ${APP_NAME}_app {
    server 127.0.0.1:3000 fail_timeout=0;
}

server {
    listen 80;
    server_name $SUBDOMAIN;

    root $APP_DIR/public;

    access_log /var/log/nginx/${APP_NAME}_access.log;
    error_log /var/log/nginx/${APP_NAME}_error.log;

    location ~ ^/(assets|packs)/ {
        gzip_static on;
        expires max;
        add_header Cache-Control public;
    }

    location / {
        proxy_pass http://${APP_NAME}_app;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;

        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
        send_timeout 300;
    }

    error_page 500 502 503 504 /500.html;
    location = /500.html {
        root $APP_DIR/public;
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/$APP_NAME /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx config
print_step "Testing Nginx configuration..."
sudo nginx -t

# Start services
print_step "Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable $APP_NAME
sudo systemctl start $APP_NAME
sudo systemctl restart nginx

# Wait for application to start
print_step "Waiting for application to start..."
sleep 5

# Check if app is running
if systemctl is-active --quiet $APP_NAME; then
    print_step "Application started successfully!"
else
    print_error "Application failed to start. Check logs with: sudo journalctl -u $APP_NAME -n 50"
    exit 1
fi

# Install Certbot and configure SSL
print_step "Installing SSL certificate with Let's Encrypt..."
sudo apt install -y certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d "$SUBDOMAIN" --non-interactive --agree-tos --email "$SSL_EMAIL" --redirect

# Create update script
print_step "Creating update script..."
cat > ~/update-$APP_NAME.sh << 'UPDATESCRIPT'
#!/bin/bash
set -e
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
UPDATESCRIPT

chmod +x ~/update-$APP_NAME.sh

# Create backup script
print_step "Creating backup script..."
cat > ~/backup-$APP_NAME.sh << 'BACKUPSCRIPT'
#!/bin/bash
BACKUP_DIR="$HOME/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="sectools_production"
mkdir -p $BACKUP_DIR
echo "🗄️  Backing up database..."
pg_dump $DB_NAME | gzip > $BACKUP_DIR/${APP_NAME}_backup_$DATE.sql.gz
echo "✅ Backup saved to: $BACKUP_DIR/${APP_NAME}_backup_$DATE.sql.gz"
find $BACKUP_DIR -name "${APP_NAME}_backup_*.sql.gz" -mtime +7 -delete
BACKUPSCRIPT

chmod +x ~/backup-$APP_NAME.sh

# Configure firewall (UFW)
print_step "Configuring firewall..."
if command -v ufw &> /dev/null; then
    sudo ufw allow OpenSSH
    sudo ufw allow 'Nginx Full'
    echo "y" | sudo ufw enable || true
fi

# Final status check
print_step "Checking service status..."
sudo systemctl status $APP_NAME --no-pager -l

echo ""
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                  🎉 Deployment Complete! 🎉                       ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "${GREEN}✅ SecTools is now running at: https://$SUBDOMAIN${NC}"
echo ""
echo "Useful commands:"
echo "  • View logs:          sudo journalctl -u $APP_NAME -f"
echo "  • Restart app:        sudo systemctl restart $APP_NAME"
echo "  • Update app:         ~/update-$APP_NAME.sh"
echo "  • Backup database:    ~/backup-$APP_NAME.sh"
echo "  • Rails console:      cd $APP_DIR && RAILS_ENV=production bundle exec rails console"
echo ""
echo "Configuration files:"
echo "  • Application:        $APP_DIR"
echo "  • Environment:        $APP_DIR/.env.production"
echo "  • Nginx:              /etc/nginx/sites-available/$APP_NAME"
echo "  • Service:            /etc/systemd/system/$APP_NAME.service"
echo ""
print_warning "Important: Save your database password somewhere secure!"
echo "Database password: $DB_PASSWORD"
echo ""
echo "For more information, see: DEPLOYMENT.md"
echo ""
