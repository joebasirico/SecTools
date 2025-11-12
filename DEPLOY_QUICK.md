# Quick Deployment Guide

Deploy SecTools to Ubuntu VPS in minutes using the automated deployment script.

## Prerequisites

- Fresh Ubuntu 20.04+ VPS with 2GB+ RAM
- Domain/subdomain pointing to VPS IP address
- SSH access with sudo privileges
- GitHub repository access

## One-Command Deployment

### Step 1: Prepare DNS

Point your subdomain to your VPS IP:
```
Type: A Record
Host: sectools (or your chosen subdomain)
Value: YOUR_VPS_IP
TTL: 3600
```

Verify DNS propagation:
```bash
dig sectools.yourdomain.com
# or
nslookup sectools.yourdomain.com
```

### Step 2: SSH to Your Server

```bash
ssh your-user@your-vps-ip
```

### Step 3: Download and Run Deployment Script

```bash
# Download the deployment script
curl -o deploy.sh https://raw.githubusercontent.com/YOUR_USERNAME/SecTools/main/deploy.sh

# Make it executable
chmod +x deploy.sh

# Run the script
./deploy.sh
```

### Step 4: Follow the Prompts

The script will ask for:
1. **Subdomain**: `sectools.yourdomain.com`
2. **Email**: For SSL certificate notifications
3. **Database Password**: Choose a secure password
4. **Repository URL**: Your GitHub repository URL

Example:
```
Enter your subdomain: sectools.example.com
Enter your email: admin@example.com
Enter PostgreSQL password: [secure-password]
Enter your GitHub repository URL: https://github.com/username/SecTools.git
```

### Step 5: Wait for Completion

The script will automatically:
- ✅ Install Ruby, Node.js, PostgreSQL, Nginx, Redis
- ✅ Clone your repository
- ✅ Install dependencies
- ✅ Setup database
- ✅ Configure Nginx
- ✅ Install SSL certificate (Let's Encrypt)
- ✅ Start the application

Total time: ~15-20 minutes

## Post-Deployment

### Access Your Application

Visit: `https://sectools.yourdomain.com`

### Quick Commands

```bash
# View application logs
sudo journalctl -u sectools -f

# Restart application
sudo systemctl restart sectools

# Update application (created by script)
~/update-sectools.sh

# Backup database (created by script)
~/backup-sectools.sh

# Check service status
sudo systemctl status sectools
```

### Rails Console

```bash
cd /home/deploy/SecTools
RAILS_ENV=production bundle exec rails console
```

## Manual Deployment

If you prefer manual deployment or the script fails, see [DEPLOYMENT.md](DEPLOYMENT.md) for detailed step-by-step instructions.

## Troubleshooting

### Check if application is running
```bash
sudo systemctl status sectools
```

### View error logs
```bash
sudo journalctl -u sectools -n 100
tail -f /home/deploy/SecTools/log/production.log
```

### Test Nginx configuration
```bash
sudo nginx -t
```

### Restart everything
```bash
sudo systemctl restart sectools
sudo systemctl restart nginx
```

### SSL certificate issues
```bash
sudo certbot renew
sudo systemctl reload nginx
```

## Updating the Application

### Using the update script (recommended)
```bash
~/update-sectools.sh
```

### Manual update
```bash
cd /home/deploy/SecTools
git pull origin main
bundle install --deployment --without development test
RAILS_ENV=production bundle exec rails db:migrate
RAILS_ENV=production bundle exec rails assets:precompile
sudo systemctl restart sectools
```

## Security Checklist

After deployment, ensure:

- ✅ Firewall is enabled (UFW)
- ✅ SSL certificate is installed and auto-renewing
- ✅ Strong database password
- ✅ Keep system updated: `sudo apt update && sudo apt upgrade`
- ✅ Setup automated database backups
- ✅ Monitor disk space: `df -h`
- ✅ Monitor memory: `free -h`

## Common Issues

### 1. "Command not found" after installing Ruby

Solution:
```bash
source ~/.bashrc
# or logout and login again
```

### 2. DNS not propagating

Solution: Wait 5-60 minutes for DNS to propagate globally

Check: `dig sectools.yourdomain.com`

### 3. 502 Bad Gateway

Solution:
```bash
sudo systemctl restart sectools
sudo systemctl status sectools
# Check logs for errors
sudo journalctl -u sectools -n 50
```

### 4. SSL certificate fails

Solution:
- Ensure DNS is pointing to server
- Ensure ports 80 and 443 are open
- Manually run: `sudo certbot --nginx -d sectools.yourdomain.com`

### 5. Out of memory

Solution: Add swap space
```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Support

For detailed documentation, see [DEPLOYMENT.md](DEPLOYMENT.md)

For application errors, check:
- Application logs: `tail -f /home/deploy/SecTools/log/production.log`
- Service logs: `sudo journalctl -u sectools -f`
- Nginx logs: `sudo tail -f /var/log/nginx/sectools_error.log`

## Architecture

```
Internet
    ↓
Nginx (Port 80/443) → SSL Termination
    ↓
Puma (Port 3000) → Rails 8.0 Application
    ↓
PostgreSQL (Port 5432) → Database
```

## Performance Tuning

### For 2GB RAM Server
Edit `/etc/systemd/system/sectools.service`:
```ini
Environment="WEB_CONCURRENCY=2"
Environment="RAILS_MAX_THREADS=5"
```

### For 4GB+ RAM Server
```ini
Environment="WEB_CONCURRENCY=4"
Environment="RAILS_MAX_THREADS=5"
```

Restart after changes:
```bash
sudo systemctl daemon-reload
sudo systemctl restart sectools
```

## Monitoring

### Check resource usage
```bash
htop
free -h
df -h
```

### Monitor active connections
```bash
sudo netstat -plant | grep :3000
sudo netstat -plant | grep :80
```

## Backup Strategy

### Automated daily backups
```bash
crontab -e
```

Add:
```
0 2 * * * /home/deploy/backup-sectools.sh
```

### Manual backup
```bash
~/backup-sectools.sh
```

### Restore from backup
```bash
gunzip < backup_20240101.sql.gz | psql sectools_production
```

## Next Steps

1. ✅ Test all security tools
2. ✅ Configure custom settings in `.env.production`
3. ✅ Setup monitoring (optional)
4. ✅ Configure email notifications (optional)
5. ✅ Setup automated backups
6. ✅ Document your API endpoints
7. ✅ Train your team on the tools

---

**Congratulations!** 🎉 Your SecTools application is now live and secured with SSL!
