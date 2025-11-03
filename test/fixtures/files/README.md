# Test Fixture Files for Code Security Scanner

This directory contains intentionally vulnerable test files used to verify the Code Security Scanner tool is working correctly.

## Files

- **vulnerable_test.rb** - Ruby/Rails vulnerabilities
- **vulnerable_test.js** - JavaScript/Node.js vulnerabilities
- **vulnerable_test.py** - Python vulnerabilities
- **vulnerable_test.php** - PHP vulnerabilities

## Usage

These files can be uploaded to the Code Security Scanner tool to test its detection capabilities.

### Via Web Interface

1. Navigate to the Code Security Scanner tool
2. Upload any of these test files
3. View the detected vulnerabilities

### Programmatically

```ruby
tool = CodeSecurityScannerTool.new
file_content = File.read(Rails.root.join('test/fixtures/files/vulnerable_test.rb'))
result = tool.execute(source_file: file_content)

puts "Found #{result[:summary][:total]} vulnerabilities"
puts "Critical: #{result[:summary][:critical]}"
puts "High: #{result[:summary][:high]}"
```

## Expected Detections

### vulnerable_test.rb
- SQL Injection (multiple patterns)
- XSS (html_safe, raw)
- Command Injection (system, backticks, exec)
- Path Traversal (File.read, File.open)
- IDOR (find without authorization)
- Hardcoded Secrets (API keys, passwords)
- JWT Issues (decode without verification)
- Weak Cryptography (MD5, SHA1, rand)
- Insecure Deserialization (Marshal.load, YAML.load)
- Mass Assignment (without permit)
- Open Redirect (redirect_to with params)

### vulnerable_test.js
- SQL Injection (query concatenation)
- XSS (innerHTML, document.write)
- Command Injection (exec with concatenation)
- JWT Issues (empty secret, "none" algorithm)
- Weak Cryptography (Math.random, MD5)
- Hardcoded Secrets (API keys, AWS keys)

### vulnerable_test.py
- SQL Injection (string formatting in execute)
- Command Injection (os.system, subprocess with shell=True)
- JWT Issues (verify_signature: False)
- Weak Cryptography (MD5, SHA1, random.random)
- Hardcoded Secrets (keys, passwords, private keys)
- Insecure Deserialization (pickle.loads)

### vulnerable_test.php
- SQL Injection (mysql_query, mysqli_query)
- XSS (echo/print $_GET/$_POST)
- Command Injection (exec, shell_exec, system)
- Path Traversal (fopen, include, require with user input)
- Weak Cryptography (MD5, SHA1, mcrypt)
- Insecure Deserialization (unserialize)

##WARNING

**These files contain intentionally insecure code patterns.**

- Do NOT use these patterns in production code
- These files are for testing purposes only
- Always follow secure coding practices

## Contributing

When adding new vulnerability patterns:

1. Add test cases to the appropriate language file
2. Ensure the pattern is detectable by existing or new rules
3. Document expected detections above
4. Update test assertions if needed
