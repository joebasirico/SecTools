# Security Scanning Rules

This directory contains YAML-based security scanning rules for the Code Security Scanner tool. Each file defines patterns for detecting specific types of security vulnerabilities.

## Adding New Rules

Creating new security scanning rules is simple! Just create a new YAML file in this directory.

### Rule File Structure

Each rule file must follow this structure:

```yaml
# Comments describing the vulnerability type
name: Vulnerability Name
severity: CRITICAL|HIGH|MEDIUM|LOW
description: A clear description of what this rule detects

patterns:
  - description: Specific pattern description
    languages: [ruby, javascript, python, php, java]
    regex: 'your-regex-pattern-here'
    example: 'code example showing the vulnerability'
    recommendation: How to fix this issue

  - description: Another pattern for the same vulnerability
    languages: [python]
    regex: 'another-pattern'
    example: 'another example'
    recommendation: Fix recommendation

references:
  - https://owasp.org/...
  - https://cwe.mitre.org/...
```

### Field Descriptions

#### Required Fields

- **name**: Human-readable name of the vulnerability (e.g., "SQL Injection", "XSS")
- **severity**: One of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`
- **description**: Brief explanation of what this vulnerability is
- **patterns**: Array of detection patterns (at least one required)

#### Pattern Fields

Each pattern must include:

- **description**: What this specific pattern detects
- **languages**: Array of languages this pattern applies to
  - Valid values: `ruby`, `javascript`, `typescript`, `python`, `php`, `java`
- **regex**: Regular expression pattern to match the vulnerability
  - Use single quotes to avoid YAML escaping issues
  - Remember to escape special regex characters

#### Optional Fields

- **example**: Code example showing the vulnerability
- **recommendation**: How to remediate the issue
- **references**: Array of helpful URLs (OWASP, CWE, etc.)

## Example: Creating a New Rule

Let's create a rule to detect insecure cookie settings:

```yaml
# Insecure Cookie Configuration
name: Insecure Cookie Settings
severity: MEDIUM
description: Detects cookies set without secure flags (HttpOnly, Secure, SameSite)

patterns:
  - description: Cookie without HttpOnly flag (Ruby)
    languages: [ruby]
    regex: 'cookies\[[^\]]+\]\s*=\s*[^{]*(?!.*httponly)'
    example: 'cookies[:session] = user_token'
    recommendation: Set cookies with httponly: true, secure: true, same_site: :strict

  - description: Cookie without secure flag (JavaScript)
    languages: [javascript, typescript]
    regex: 'document\.cookie\s*=\s*[^;]*(?!.*secure)'
    example: 'document.cookie = "session=" + token'
    recommendation: Use secure, httpOnly, and sameSite flags

  - description: PHP setcookie without secure flags
    languages: [php]
    regex: 'setcookie\([^)]*\)(?!.*true.*true)'
    example: 'setcookie("session", $token)'
    recommendation: Use setcookie with secure and httponly parameters

references:
  - https://owasp.org/www-community/controls/SecureCookieAttribute
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
```

Save this as `config/security_rules/insecure_cookies.yml` and the scanner will automatically load it!

## Regular Expression Tips

### Language-Specific Patterns

- **Ruby**: Look for Rails methods like `params`, `cookies`, `request`
- **JavaScript/TypeScript**: Common DOM methods, Node.js APIs
- **Python**: Django/Flask request objects, common stdlib functions
- **PHP**: Superglobals like `$_GET`, `$_POST`, `$_REQUEST`

### Common Regex Patterns

```regex
# Match user input sources
(params|request|cookies|\$_(GET|POST|REQUEST|COOKIE))

# Match string concatenation/interpolation
['"].*\+.*        # Concatenation with +
['"].*\#\{        # Ruby interpolation
['"].*\$\{        # JS template literals
['"].*%s          # Python string formatting

# Negative lookahead (ensure something is NOT present)
(?!.*sanitize)    # Ensures "sanitize" is not in the line
```

### Testing Your Regex

You can test patterns in Ruby console:

```ruby
pattern = /your-regex-here/
test_code = "suspicious_code_here"
test_code.match?(pattern)  # => true if matches
```

## Best Practices

1. **Be Specific**: Patterns should be specific enough to avoid false positives
2. **Include Context**: Use negative lookahead to check for proper sanitization
3. **Test Thoroughly**: Test your patterns against both vulnerable and safe code
4. **Document Well**: Clear descriptions and examples help others understand the rule
5. **Set Appropriate Severity**:
   - `CRITICAL`: Remote code execution, SQL injection, hardcoded secrets
   - `HIGH`: XSS, authentication bypass, path traversal
   - `MEDIUM`: Weak crypto, information disclosure
   - `LOW`: Code quality, minor security concerns

## Existing Rules

Current security rules in this directory:

- `sql_injection.yml` - SQL Injection patterns
- `xss.yml` - Cross-Site Scripting (XSS) patterns
- `command_injection.yml` - OS Command Injection patterns
- `hardcoded_secrets.yml` - Hardcoded credentials and secrets
- `path_traversal.yml` - Path traversal vulnerabilities
- `jwt_issues.yml` - JWT security misconfigurations
- `weak_crypto.yml` - Weak cryptographic algorithms

## Validating Rules

The `SecurityRuleLoader` class automatically validates rule files when loaded. If a rule is invalid, check the Rails logs for error messages.

Required validations:
- Must have `name`, `severity`, and `patterns` fields
- Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW
- Each pattern must have `regex`, `languages`, and `description`

## Contributing Rules

We welcome contributions! When adding new rules:

1. Create a descriptive filename (e.g., `csrf_vulnerabilities.yml`)
2. Include real-world examples in the `example` field
3. Provide clear remediation advice in `recommendation`
4. Link to authoritative sources in `references`
5. Test against actual vulnerable code samples

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Ruby Security Guide](https://guides.rubyonrails.org/security.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
