# SecTools Deployment Checklist

Use this checklist to verify your deployment is complete and secure.

## Pre-Deployment Checklist

### DNS Configuration
- [ ] A record created for subdomain pointing to VPS IP
- [ ] DNS propagation verified with `dig` or `nslookup`
- [ ] TTL set appropriately (3600 recommended)

### VPS Requirements
- [ ] Ubuntu 20.04+ installed
- [ ] Minimum 2GB RAM (4GB+ recommended)
- [ ] 20GB+ disk space available
- [ ] Root or sudo access confirmed
- [ ] SSH key authentication configured (recommended)

### Repository Access
- [ ] GitHub repository created
- [ ] Local code pushed to repository
- [ ] Deploy keys configured (if using private repo)

### Credentials Prepared
- [ ] Strong database password chosen
- [ ] Email for SSL certificate selected
- [ ] Subdomain decided

---

## Deployment Process Checklist

### Initial Setup
- [ ] SSH connection to VPS successful
- [ ] System packages updated (`apt update && apt upgrade`)
- [ ] Deployment script downloaded or manual steps started
- [ ] Required ports open (22, 80, 443)

### Software Installation
- [ ] rbenv installed
- [ ] Ruby 3.3.0+ installed
- [ ] Node.js 20+ installed
- [ ] PostgreSQL installed and running
- [ ] Nginx installed and running
- [ ] Redis installed and running (optional)

### Application Setup
- [ ] Repository cloned to `/home/deploy/SecTools`
- [ ] Dependencies installed (`bundle install`)
- [ ] `.env.production` file created with proper values
- [ ] Database created and migrated
- [ ] Assets precompiled

### Web Server Configuration
- [ ] Nginx site configuration created
- [ ] Nginx configuration tested (`nginx -t`)
- [ ] Nginx reloaded successfully
- [ ] Systemd service file created
- [ ] Application service started and enabled

### SSL Certificate
- [ ] Certbot installed
- [ ] SSL certificate obtained
- [ ] HTTPS redirect configured
- [ ] Certificate auto-renewal tested
- [ ] Mixed content warnings resolved

---

## Post-Deployment Verification

### Application Health
- [ ] Application accessible at https://subdomain.com
- [ ] Homepage loads correctly
- [ ] All tools are listed
- [ ] Can execute at least one test tool successfully
- [ ] Theme switching works (hacker/professional modes)
- [ ] No JavaScript console errors

### Service Status
```bash
# All should return "active (running)"
- [ ] systemctl status sectools
- [ ] systemctl status nginx
- [ ] systemctl status postgresql
- [ ] systemctl status redis-server (if using)
```

### Log Verification
```bash
# Check for errors in logs
- [ ] sudo journalctl -u sectools -n 50 (no critical errors)
- [ ] tail -f /home/deploy/SecTools/log/production.log (clean)
- [ ] tail /var/log/nginx/sectools_error.log (no errors)
```

### Performance Tests
- [ ] Page load time < 3 seconds
- [ ] Tool execution completes successfully
- [ ] PDF/CSV export works
- [ ] Long-running security scans don't timeout
- [ ] Memory usage reasonable (`free -h`)
- [ ] CPU usage normal (`htop`)

### Security Verification
- [ ] HTTP redirects to HTTPS
- [ ] SSL certificate valid (green padlock in browser)
- [ ] SSL Labs grade A or A+ (https://ssllabs.com/ssltest/)
- [ ] Security headers present (check with tool itself!)
- [ ] Database not accessible externally
- [ ] Firewall enabled (`ufw status`)
- [ ] Only necessary ports open (22, 80, 443)

### API Security Tests (If using API Scanner)
- [ ] Can fetch Swagger/OpenAPI specs
- [ ] Authentication testing works
- [ ] Vulnerability scanning executes
- [ ] Results are properly formatted
- [ ] Export functions work (CSV, PDF, JSON)

---

## Functional Testing

### Test Each Tool Category

#### Network Security Tools
- [ ] HTTP Security Headers Analyzer works
- [ ] CORS Scanner executes
- [ ] Subdomain Enumeration completes
- [ ] API Endpoint Security Scanner runs

#### Code Security Tools
- [ ] Secrets Scanner finds patterns
- [ ] XML/JSON Schema Validator works
- [ ] Docker Security Scanner analyzes files

#### Application Security Tools
- [ ] API Schema Security Reviewer tests endpoints
- [ ] IDOR testing completes
- [ ] SQL injection testing works
- [ ] XSS testing executes
- [ ] All security tests can be exported

#### Authentication Security Tools
- [ ] Password Strength Analyzer works
- [ ] JWT Token Decoder functions
- [ ] Brute force testing completes

#### Utility Tools
- [ ] Base64/Encoding Decoder works
- [ ] Hash Tool generates hashes
- [ ] All encoding formats supported

---

## Backup & Maintenance Setup

### Backup Configuration
- [ ] Backup script created (`~/backup-sectools.sh`)
- [ ] Backup script tested manually
- [ ] Backup directory created with proper permissions
- [ ] Automated daily backup scheduled (crontab)
- [ ] Backup retention policy set (7 days default)
- [ ] Test restore from backup

### Update Configuration
- [ ] Update script created (`~/update-sectools.sh`)
- [ ] Update script tested
- [ ] Git pull works without issues
- [ ] Migration strategy documented
- [ ] Rollback plan documented

### Monitoring Setup
- [ ] Log rotation configured
- [ ] Disk space monitoring in place
- [ ] Memory monitoring configured
- [ ] SSL certificate expiry monitoring
- [ ] Uptime monitoring configured (optional)
- [ ] Error tracking setup (Sentry, etc.) (optional)

---

## Documentation

### Internal Documentation
- [ ] `.env.production` values documented securely
- [ ] Database password stored in password manager
- [ ] Server IP and credentials documented
- [ ] SSH keys backed up
- [ ] Deployment date recorded
- [ ] Team members granted access

### User Documentation
- [ ] User guide created (if needed)
- [ ] Tool usage examples documented
- [ ] API documentation complete (if applicable)
- [ ] Security best practices shared with team

---

## Security Hardening

### Server Hardening
- [ ] SSH password authentication disabled
- [ ] SSH key-only authentication enabled
- [ ] Fail2ban installed and configured
- [ ] Automatic security updates enabled
- [ ] Unnecessary services disabled
- [ ] Root login disabled
- [ ] Strong passwords enforced

### Application Hardening
- [ ] RAILS_ENV set to production
- [ ] Debug mode disabled
- [ ] Error pages don't reveal sensitive info
- [ ] Rate limiting configured
- [ ] CORS properly configured
- [ ] CSP headers set
- [ ] XSS protection enabled

### Database Hardening
- [ ] Database not exposed to internet
- [ ] Strong database password
- [ ] Limited database user permissions
- [ ] Regular backups scheduled
- [ ] Connection encryption enabled

---

## Performance Optimization

### Application Performance
- [ ] Assets precompiled
- [ ] Gzip compression enabled
- [ ] Static file caching configured
- [ ] Database indexes created
- [ ] Query optimization done
- [ ] Puma worker count optimized for RAM

### Server Performance
- [ ] Swap space configured (if needed)
- [ ] Open file limits increased (if needed)
- [ ] Nginx worker processes tuned
- [ ] Redis configured (if using background jobs)
- [ ] CDN configured (if needed)

---

## Compliance & Legal

### Terms of Service
- [ ] Acceptable use policy defined
- [ ] Terms of service created
- [ ] Privacy policy created
- [ ] Cookie policy (if applicable)
- [ ] GDPR compliance (if applicable)

### Security Policy
- [ ] Responsible disclosure policy published
- [ ] Security contact email configured
- [ ] Incident response plan documented
- [ ] Data retention policy defined

---

## Final Verification

### Smoke Tests
- [ ] Visit homepage
- [ ] Run 3 different security tools
- [ ] Download a PDF report
- [ ] Download a CSV report
- [ ] Switch themes
- [ ] Test on mobile device
- [ ] Test in different browsers (Chrome, Firefox, Safari)

### User Acceptance
- [ ] Demo to stakeholders
- [ ] User feedback collected
- [ ] Critical issues resolved
- [ ] Nice-to-have issues documented for future

### Sign-Off
- [ ] Deployment documented
- [ ] Operations team trained
- [ ] Support documentation ready
- [ ] Go-live date scheduled
- [ ] Rollback plan tested

---

## Post-Launch Checklist (Week 1)

### Monitoring
- [ ] Check logs daily
- [ ] Monitor resource usage
- [ ] Track error rates
- [ ] Review user feedback
- [ ] Monitor SSL certificate status

### Performance
- [ ] Response times acceptable
- [ ] No memory leaks detected
- [ ] Database performance good
- [ ] Backup system working

### Security
- [ ] No security alerts
- [ ] SSL certificate valid
- [ ] Firewall logs reviewed
- [ ] No unauthorized access attempts

---

## Ongoing Maintenance Schedule

### Daily
- [ ] Check application availability
- [ ] Review error logs
- [ ] Monitor disk space

### Weekly
- [ ] Review backup logs
- [ ] Check resource utilization
- [ ] Review security logs
- [ ] Test key functionality

### Monthly
- [ ] Update system packages
- [ ] Update Ruby gems
- [ ] Review SSL certificate expiry
- [ ] Test backup restore
- [ ] Review and rotate logs
- [ ] Performance review

### Quarterly
- [ ] Security audit
- [ ] Performance optimization
- [ ] Dependency updates
- [ ] Disaster recovery test
- [ ] Documentation review

---

## Emergency Contacts

**Document these securely:**

- [ ] VPS provider support: _______________
- [ ] DNS provider support: _______________
- [ ] SSL certificate support: _______________
- [ ] On-call engineer: _______________
- [ ] Team lead: _______________
- [ ] System administrator: _______________

---

## Success Criteria

Deployment is considered successful when:

✅ Application is accessible via HTTPS
✅ All security tools are functional
✅ SSL certificate is valid and auto-renewing
✅ Backups are running automatically
✅ Monitoring is in place
✅ Documentation is complete
✅ Team is trained
✅ No critical issues outstanding

---

**Date Completed:** _________________

**Deployed By:** _________________

**Verified By:** _________________

**Production URL:** _________________

**Notes:**
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
