# Testing the Code Security Scanner

This document explains how to test the Code Security Scanner tool to verify it's working correctly.

## Quick Test

### Option 1: Via Web Interface

1. Start the Rails server:
   ```bash
   bin/dev
   ```

2. Navigate to `http://localhost:3000`

3. Click on "Code Security Scanner"

4. Upload one of the test files from `test/fixtures/files/`:
   - `vulnerable_test.rb` - Ruby vulnerabilities
   - `vulnerable_test.js` - JavaScript vulnerabilities
   - `vulnerable_test.py` - Python vulnerabilities
   - `vulnerable_test.php` - PHP vulnerabilities

5. Click "[EXECUTE ANALYSIS]"

6. Verify that vulnerabilities are detected and displayed

### Option 2: Via Rails Console

```bash
bin/rails console
```

```ruby
# Load a test file
code = File.read(Rails.root.join('test/fixtures/files/vulnerable_test.rb'))

# Run the scanner
tool = CodeSecurityScannerTool.new
result = tool.execute(source_file: code)

# View results
puts "Files scanned: #{result[:files_scanned]}"
puts "Total findings: #{result[:summary][:total]}"
puts "Critical: #{result[:summary][:critical]}"
puts "High: #{result[:summary][:high]}"
puts "Medium: #{result[:summary][:medium]}"
puts "Low: #{result[:summary][:low]}"

# View individual findings
result[:findings].first(5).each do |finding|
  puts "\n#{finding[:vulnerability_type]} (#{finding[:severity]})"
  puts "  File: #{finding[:file]}:#{finding[:line_number]}"
  puts "  Description: #{finding[:description]}"
  puts "  Code: #{finding[:line_content]}"
end
```

## Running Automated Tests

### Run All Tool Tests

```bash
bin/rails test test/tools/code_security_scanner_tool_test.rb
```

### Run Specific Test

```bash
bin/rails test test/tools/code_security_scanner_tool_test.rb:27
```

### Run Tests with Verbose Output

```bash
bin/rails test test/tools/code_security_scanner_tool_test.rb --verbose
```

## Expected Test Results

The test suite should show:
- ✅ All rules loaded correctly
- ✅ Language detection working (Ruby, JavaScript, Python, PHP)
- ✅ SQL Injection detected
- ✅ XSS detected
- ✅ Command Injection detected
- ✅ Hardcoded Secrets detected
- ✅ JWT Issues detected
- ✅ Weak Cryptography detected
- ✅ Summary counts accurate
- ✅ Code snippets included
- ✅ Recommendations provided

## Testing Individual Rules

### Test SQL Injection Detection

```ruby
code = <<~RUBY
  User.where("id = " + params[:id])
RUBY

tool = CodeSecurityScannerTool.new
result = tool.execute(source_file: code)
puts result[:findings].any? { |f| f[:vulnerability_type] == "SQL Injection" }
# => true
```

### Test XSS Detection

```javascript
const code = `
  function display(input) {
    document.getElementById('content').innerHTML = input;
  }
`;

tool = CodeSecurityScannerTool.new
result = tool.execute(source_file: code)
puts result[:findings].any? { |f| f[:vulnerability_type] == "Cross-Site Scripting (XSS)" }
# => true
```

### Test Hardcoded Secrets Detection

```ruby
code = <<~RUBY
  API_KEY = "sk_live_1234567890abcdef"
RUBY

tool = CodeSecurityScannerTool.new
result = tool.execute(source_file: code)
puts result[:findings].any? { |f| f[:vulnerability_type] == "Hardcoded Secrets" }
# => true
```

## Testing Rule Loading

### Check Loaded Rules

```bash
bin/rails runner "puts SecurityRuleLoader.rule_stats.inspect"
```

Expected output:
```ruby
{
  total_rules: 7,
  total_patterns: 64,
  by_severity: {"CRITICAL"=>3, "HIGH"=>3, "MEDIUM"=>1},
  rules_list: ["command_injection", "hardcoded_secrets", "jwt_issues", "path_traversal", "sql_injection", "weak_crypto", "xss"]
}
```

### List All Rules

```bash
bin/rails runner "puts SecurityRuleLoader.list_rules"
```

### Load Specific Rule

```ruby
rule = SecurityRuleLoader.load_rule('sql_injection')
puts rule[:name]          # => "SQL Injection"
puts rule[:severity]      # => "CRITICAL"
puts rule[:patterns].count # => 9
```

## Testing ZIP File Upload

1. Create a ZIP file with multiple source files:
   ```bash
   cd test/fixtures/files
   zip vulnerable_code.zip vulnerable_test.rb vulnerable_test.js
   ```

2. Upload the ZIP via the web interface or:
   ```ruby
   zip_content = File.read('vulnerable_code.zip')
   tool = CodeSecurityScannerTool.new
   result = tool.execute(source_file: zip_content)
   puts "Scanned #{result[:files_scanned]} files"
   ```

## Troubleshooting

### No Vulnerabilities Detected

1. **Check language detection:**
   ```ruby
   tool = CodeSecurityScannerTool.new
   lang = tool.send(:detect_language_from_content, your_code)
   puts "Detected language: #{lang}"
   ```

2. **Verify rules are loaded:**
   ```ruby
   patterns = CodeSecurityScannerTool.vulnerability_patterns
   puts "Loaded #{patterns.keys.length} rule types"
   ```

3. **Check if pattern matches:**
   ```ruby
   line = "User.where(\"id = \" + params[:id])"
   pattern = /\.where\(['"]\s*\w+\s*=\s*['"]\s*\+\s*/
   puts line.match?(pattern) # => true
   ```

### Tests Failing

1. **Clear cache and restart:**
   ```bash
   bin/rails tmp:clear
   bin/rails restart
   ```

2. **Check for rule file errors:**
   ```bash
   bin/rails runner "
     SecurityRuleLoader.list_rules.each do |rule_name|
       rule_data = YAML.load_file(Rails.root.join('config/security_rules', \"\#{rule_name}.yml\"))
       errors = SecurityRuleLoader.validate_rule(rule_data)
       puts \"\#{rule_name}: \#{errors.any? ? errors.join(', ') : 'OK'}\"
     end
   "
   ```

3. **Verify test fixtures exist:**
   ```bash
   ls -la test/fixtures/files/
   ```

## Performance Testing

### Benchmark Scanning Speed

```ruby
require 'benchmark'

code = File.read(Rails.root.join('test/fixtures/files/vulnerable_test.rb'))
tool = CodeSecurityScannerTool.new

time = Benchmark.realtime do
  result = tool.execute(source_file: code)
end

puts "Scan completed in #{(time * 1000).round(2)}ms"
```

### Test Large Files

```ruby
# Generate a large test file
large_code = File.read(Rails.root.join('app/controllers/application_controller.rb')) * 100

tool = CodeSecurityScannerTool.new
result = tool.execute(source_file: large_code)

puts "Scanned #{large_code.lines.count} lines"
puts "Found #{result[:findings].length} issues"
```

## Adding New Test Cases

When adding new vulnerability patterns:

1. Add the pattern to the appropriate rule file in `config/security_rules/`
2. Add test case to the appropriate fixture file
3. Add a test assertion to `code_security_scanner_tool_test.rb`
4. Run tests to verify detection

Example:
```ruby
test "detects new vulnerability type" do
  code = <<~RUBY
    # Your vulnerable code here
  RUBY

  result = @tool.execute(source_file: code)
  findings = result[:findings].select { |f| f[:vulnerability_type] == "Your Vuln Type" }

  assert_operator findings.length, :>, 0
  assert_equal "SEVERITY", findings.first[:severity]
end
```

## Continuous Integration

Add to your CI pipeline:

```yaml
# .github/workflows/test.yml
- name: Run Security Scanner Tests
  run: bin/rails test test/tools/code_security_scanner_tool_test.rb
```

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Security Rules README](config/security_rules/README.md)
- [Test Fixtures README](test/fixtures/files/README.md)
