# SSL/TLS Security Tester

A comprehensive tool for testing website SSL/TLS security configurations, certificate validity, and detecting common vulnerabilities.

## Features

### Certificate Analysis
- ✅ **Certificate Validity** - Check if certificate is valid and not expired
- ✅ **Expiration Monitoring** - Track days until certificate expires
- ✅ **Certificate Chain** - Verify complete certificate chain
- ✅ **Key Size Analysis** - Check RSA/EC key strength (minimum 2048 bits)
- ✅ **Signature Algorithm** - Verify secure signature algorithms
- ✅ **Subject Alternative Names (SAN)** - List all covered domains
- ✅ **Self-Signed Detection** - Identify self-signed certificates

### Protocol Testing
- ✅ **SSLv2/SSLv3** - Detect critically insecure protocols
- ✅ **TLS 1.0** - Flag deprecated TLS 1.0
- ✅ **TLS 1.1** - Flag deprecated TLS 1.1
- ✅ **TLS 1.2** - Verify modern TLS support
- ✅ **TLS 1.3** - Check for latest TLS version

### Cipher Suite Analysis
- ✅ **Strong Ciphers** - Identify 256-bit+ encryption
- ✅ **Weak Ciphers** - Detect RC4, DES, NULL, EXPORT
- ✅ **Cipher Strength** - Classify cipher bit strength
- ✅ **Forward Secrecy** - Recommend ECDHE ciphers

### Vulnerability Detection
- ⚠️ **POODLE** - SSLv3 vulnerability
- ⚠️ **DROWN** - SSLv2 vulnerability
- ⚠️ **BEAST** - TLS 1.0 vulnerability
- ⚠️ **RC4 Attacks** - Weak cipher detection
- ⚠️ **Certificate Issues** - Expired, self-signed, weak keys
- ⚠️ **Protocol Deprecation** - TLS 1.0/1.1 warnings

### Security Scoring
- 📊 **Grade System** - A through F grading
- 📊 **Numerical Score** - 0-100 point system
- 📊 **Severity Ratings** - CRITICAL, HIGH, MEDIUM, LOW
- 📊 **Actionable Recommendations** - Step-by-step improvements

## Usage

### Via Web Interface

1. Navigate to the SSL/TLS Security Tester tool
2. Enter a target URL (e.g., `https://example.com`)
3. Click "[EXECUTE ANALYSIS]"
4. Review the results:
   - Overall security grade (A-F)
   - Certificate details
   - Protocol support
   - Cipher suites
   - Vulnerabilities
   - Recommendations

### Programmatically

```ruby
tool = SslSecurityTesterTool.new
result = tool.execute(target_url: 'https://example.com')

puts "Security Grade: #{result[:summary][:grade]}"
puts "Score: #{result[:summary][:score]}/100"
puts "Vulnerabilities: #{result[:vulnerabilities].length}"

result[:vulnerabilities].each do |vuln|
  puts "\n#{vuln[:severity]}: #{vuln[:name]}"
  puts "  #{vuln[:description]}"
  puts "  Impact: #{vuln[:impact]}"
end
```

## Test Examples

### Test a Major Website

```ruby
tool = SslSecurityTesterTool.new

# Test Google
result = tool.execute(target_url: 'https://www.google.com')
# Expected: Grade A, Score ~100

# Test GitHub
result = tool.execute(target_url: 'https://github.com')
# Expected: Grade A, Score ~95-100

# Test your own site
result = tool.execute(target_url: 'https://yoursite.com')
```

### BadSSL.com Comprehensive Test Suite

[BadSSL.com](https://badssl.com) provides comprehensive SSL/TLS test scenarios. Run all tests with:

```bash
bin/rails test test/tools/ssl_security_tester_badssl_test.rb
```

#### Certificate Validation Tests

**Expired Certificate**
```ruby
result = tool.execute(target_url: 'https://expired.badssl.com')
# Expected: Grade F, Score 0, CRITICAL "Expired Certificate" vulnerability
```

**Self-Signed Certificate**
```ruby
result = tool.execute(target_url: 'https://self-signed.badssl.com')
# Expected: Grade D-F, HIGH "Self-Signed Certificate" vulnerability
```

**Wrong Hostname**
```ruby
result = tool.execute(target_url: 'https://wrong.host.badssl.com')
# Expected: Should still analyze certificate despite hostname mismatch
```

**Untrusted Root**
```ruby
result = tool.execute(target_url: 'https://untrusted-root.badssl.com')
# Expected: Should detect untrusted certificate chain
```

**Incomplete Chain**
```ruby
result = tool.execute(target_url: 'https://incomplete-chain.badssl.com')
# Expected: Should note incomplete certificate chain
```

#### Protocol Version Tests

**TLS 1.0 (Deprecated)**
```ruby
result = tool.execute(target_url: 'https://tls-v1-0.badssl.com:1010')
# Expected: MEDIUM "TLS 1.0 Enabled" (often disabled in modern OpenSSL)
```

**TLS 1.1 (Deprecated)**
```ruby
result = tool.execute(target_url: 'https://tls-v1-1.badssl.com:1011')
# Expected: LOW "TLS 1.1 Enabled" (often disabled in modern OpenSSL)
```

**TLS 1.2 (Secure)**
```ruby
result = tool.execute(target_url: 'https://tls-v1-2.badssl.com:1012')
# Expected: Should connect successfully, no protocol warnings
```

#### Cipher Suite Tests

**RC4 Cipher (Broken)**
```ruby
result = tool.execute(target_url: 'https://rc4.badssl.com')
# Expected: HIGH "RC4 Cipher Support" (if supported by OpenSSL)
```

**RC4-MD5 Cipher (Very Weak)**
```ruby
result = tool.execute(target_url: 'https://rc4-md5.badssl.com')
# Expected: HIGH severity, weak cipher detected
```

**3DES Cipher (Weak)**
```ruby
result = tool.execute(target_url: 'https://3des.badssl.com')
# Expected: Weak cipher classification if supported
```

**NULL Cipher (No Encryption)**
```ruby
result = tool.execute(target_url: 'https://null.badssl.com')
# Expected: CRITICAL severity (typically blocked by modern OpenSSL)
```

#### Diffie-Hellman Key Exchange Tests

**DH 480-bit (Very Weak)**
```ruby
result = tool.execute(target_url: 'https://dh480.badssl.com')
# Expected: Connection failure or error (rejected by modern OpenSSL)
```

**DH 512-bit (Very Weak)**
```ruby
result = tool.execute(target_url: 'https://dh512.badssl.com')
# Expected: Connection failure or error (rejected by modern OpenSSL)
```

**DH 1024-bit (Weak)**
```ruby
result = tool.execute(target_url: 'https://dh1024.badssl.com')
# Expected: May connect but should warn about weak parameters
```

**DH 2048-bit (Acceptable)**
```ruby
result = tool.execute(target_url: 'https://dh2048.badssl.com')
# Expected: Should connect successfully
```

#### Signature Algorithm Tests

**SHA-256 (Secure)**
```ruby
result = tool.execute(target_url: 'https://sha256.badssl.com')
# Expected: Valid certificate with sha256 signature algorithm
```

**SHA-384 (Secure)**
```ruby
result = tool.execute(target_url: 'https://sha384.badssl.com')
# Expected: Valid certificate with sha384 signature algorithm
```

**SHA-512 (Secure)**
```ruby
result = tool.execute(target_url: 'https://sha512.badssl.com')
# Expected: Valid certificate with sha512 signature algorithm
```

#### RSA Key Size Tests

**RSA 2048-bit (Minimum Recommended)**
```ruby
result = tool.execute(target_url: 'https://rsa2048.badssl.com')
# Expected: No weak key warning, RSA 2048 bits
```

**RSA 4096-bit (Strong)**
```ruby
result = tool.execute(target_url: 'https://rsa4096.badssl.com')
# Expected: No warnings, RSA 4096 bits
```

**RSA 8192-bit (Very Strong)**
```ruby
result = tool.execute(target_url: 'https://rsa8192.badssl.com')
# Expected: No warnings, RSA 8192 bits
```

#### Elliptic Curve Key Tests

**ECC 256-bit (Recommended)**
```ruby
result = tool.execute(target_url: 'https://ecc256.badssl.com')
# Expected: No weak key warning, EC 256 bits
```

**ECC 384-bit (Strong)**
```ruby
result = tool.execute(target_url: 'https://ecc384.badssl.com')
# Expected: No warnings, EC 384 bits
```

#### Certificate Types

**Extended Validation (EV)**
```ruby
result = tool.execute(target_url: 'https://extended-validation.badssl.com')
# Expected: Valid EV certificate
```

**Subdomain Certificate**
```ruby
result = tool.execute(target_url: 'https://subdomain.badssl.com')
# Expected: Valid subdomain certificate
```

#### Special Cases

**No SNI Support**
```ruby
result = tool.execute(target_url: 'https://no-sni.badssl.com')
# Expected: Should handle servers without SNI gracefully
```

**Good SSL Configuration (Baseline)**
```ruby
result = tool.execute(target_url: 'https://badssl.com')
# Expected: Grade A, Score 90-100, no vulnerabilities
```

### Quick Test Script

Test multiple configurations at once:

```ruby
tool = SslSecurityTesterTool.new

tests = {
  'Good SSL' => 'https://badssl.com',
  'Expired Cert' => 'https://expired.badssl.com',
  'Self-Signed' => 'https://self-signed.badssl.com',
  'SHA-256' => 'https://sha256.badssl.com',
  'RSA 2048' => 'https://rsa2048.badssl.com',
  'ECC 256' => 'https://ecc256.badssl.com'
}

tests.each do |name, url|
  result = tool.execute(target_url: url)
  puts "#{name.ljust(15)}: Grade #{result[:summary][:grade]}, Score #{result[:summary][:score]}"
end
```

## Scoring System

### Grade Breakdown

| Grade | Score Range | Description |
|-------|------------|-------------|
| A | 90-100 | Excellent security configuration |
| B | 80-89 | Good security, minor improvements possible |
| C | 70-79 | Adequate security, improvements recommended |
| D | 60-69 | Poor security, immediate action needed |
| F | 0-59 | Failed security check, critical issues |

### Score Deductions

- **-100 points**: Expired certificate
- **-40 points**: SSLv2 or SSLv3 enabled
- **-30 points**: Self-signed certificate or weak ciphers
- **-20 points**: TLS 1.0 enabled or weak key size
- **-10 points**: TLS 1.1 enabled or certificate expiring soon

### Score Bonuses

- **+10 points**: TLS 1.3 support

## Detected Vulnerabilities

### CRITICAL Severity

1. **Expired Certificate**
   - Certificate has passed expiration date
   - Browsers will show security warnings
   - **Fix**: Renew certificate immediately

2. **SSLv2 Enabled**
   - SSLv2 is severely broken
   - Vulnerable to DROWN attack
   - **Fix**: Disable SSLv2 in server configuration

3. **SSLv3 Enabled (POODLE)**
   - SSLv3 vulnerable to POODLE attack
   - Can decrypt secure connections
   - **Fix**: Disable SSLv3 in server configuration

### HIGH Severity

1. **Self-Signed Certificate**
   - Not trusted by browsers
   - No certificate authority validation
   - **Fix**: Get certificate from Let's Encrypt, DigiCert, etc.

2. **Weak Key Size**
   - RSA key < 2048 bits
   - Vulnerable to cryptographic attacks
   - **Fix**: Generate new certificate with 2048+ bit key

3. **Weak Cipher Suites**
   - RC4, DES, NULL, EXPORT ciphers
   - Cryptographically broken
   - **Fix**: Configure strong cipher suites only

4. **Certificate Expiring Soon**
   - Less than 30 days until expiration
   - Risk of service disruption
   - **Fix**: Renew certificate now

### MEDIUM Severity

1. **TLS 1.0 Enabled**
   - Deprecated protocol
   - Vulnerable to BEAST attack
   - **Fix**: Disable TLS 1.0, use TLS 1.2+

### LOW Severity

1. **TLS 1.1 Enabled**
   - Deprecated protocol
   - Modern browsers phasing out support
   - **Fix**: Disable TLS 1.1, use TLS 1.2+

## Recommendations

### Best Practices

1. **Use TLS 1.2 and TLS 1.3 only**
   - Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
   - Enable TLS 1.3 for best performance and security

2. **Use Strong Cipher Suites**
   ```
   Recommended: ECDHE-RSA-AES256-GCM-SHA384
   Also good: ECDHE-RSA-AES128-GCM-SHA256
   Avoid: RC4, DES, NULL, EXPORT
   ```

3. **Maintain Certificate Health**
   - Use 2048-bit or 4096-bit RSA keys
   - Renew certificates before expiration
   - Use certificates from trusted CAs
   - Include all relevant domains in SAN

4. **Enable Security Headers**
   - HSTS (HTTP Strict Transport Security)
   - Certificate Transparency
   - OCSP Stapling

### Server Configuration Examples

#### Nginx
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

#### Apache
```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder on
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

## Output Format

### JSON Export
Results can be exported as JSON for integration with other tools:

```json
{
  "url": "https://example.com",
  "host": "example.com",
  "port": 443,
  "summary": {
    "score": 95,
    "grade": "A",
    "max_score": 100
  },
  "certificate": {
    "subject": "CN=example.com",
    "valid": true,
    "expires_in_days": 89
  },
  "protocols": {
    "TLS1.2": {"supported": true, "secure": true},
    "TLS1.3": {"supported": true, "secure": true}
  },
  "vulnerabilities": [],
  "recommendations": [
    "Enable TLS 1.3 for better security"
  ]
}
```

## Troubleshooting

### "Connection failed" Error

1. **Check URL format**: Must be `https://domain.com`
2. **Verify server is accessible**: Test with `curl -I https://domain.com`
3. **Check firewall**: Ensure port 443 is accessible
4. **Verify DNS**: Ensure domain resolves correctly

### No Protocol/Cipher Information

- Server may be configured to close connections quickly
- Try testing from a server in the same region
- Check server logs for connection errors

### Self-Signed Certificate Errors

- This is expected for development environments
- Use certificates from Let's Encrypt for production
- Or add proper CA signing to your certificate

## Testing Resources

### Test Sites

- [BadSSL.com](https://badssl.com/) - Various SSL/TLS test scenarios
- [HowsMySSL.com](https://www.howsmyssl.com/) - Check your client's SSL
- [SSLLabs.com](https://www.ssllabs.com/ssltest/) - Comprehensive external test

### Additional Tools

- **OpenSSL**: `openssl s_client -connect example.com:443`
- **testssl.sh**: Command-line SSL/TLS testing
- **nmap**: `nmap --script ssl-enum-ciphers -p 443 example.com`

## Security Notes

⚠️ **Important**: This tool performs active network connections to test SSL/TLS configurations. Only test:
- Your own websites
- Websites you have permission to test
- Public services (major websites)

Do not use this tool for:
- Unauthorized security testing
- Penetration testing without permission
- Any malicious purposes

## Contributing

To add new vulnerability checks:

1. Add detection logic in `detect_vulnerabilities` method
2. Update `generate_recommendations` with fix guidance
3. Adjust `calculate_security_score` for scoring impact
4. Update this README with the new check

## References

- [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [NIST Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
