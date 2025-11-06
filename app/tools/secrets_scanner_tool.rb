# Secrets Scanner Tool
# Description: Scan code and configuration files for accidentally committed secrets

class SecretsScannerTool
  include SecurityTool

  configure_tool(
    name: "Secrets Scanner",
    description: "Scan code, configuration files, and repositories for accidentally committed secrets, API keys, passwords, tokens, and other sensitive data that should not be in version control.",
    category: "Code Security"
  )

  input_field :input_type,
              type: :select,
              label: "Input Type",
              options: ["Text/Code Paste", "File Upload"],
              required: true

  input_field :content,
              type: :text,
              label: "Paste Code or Configuration (if Text/Code Paste selected)",
              placeholder: "Paste your code, config file, or .env content here",
              required: false

  input_field :file,
              type: :file,
              label: "Upload File (if File Upload selected)",
              placeholder: "Upload a file to scan",
              required: false,
              options: { accept: "*" }

  output_format :html, :json

  # Secret detection patterns
  SECRET_PATTERNS = {
    aws_access_key: {
      pattern: /AKIA[0-9A-Z]{16}/,
      name: "AWS Access Key ID",
      severity: :critical
    },
    aws_secret_key: {
      pattern: /aws[_\-\s]*secret[_\-\s]*(?:access)?[_\-\s]*key[_\-\s]*[=:]\s*['\"]?([a-zA-Z0-9+\/]{40})['\"]?/i,
      name: "AWS Secret Access Key",
      severity: :critical
    },
    github_token: {
      pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/,
      name: "GitHub Token",
      severity: :critical
    },
    github_classic_token: {
      pattern: /[gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"]/ ,
      name: "GitHub Classic Token",
      severity: :critical
    },
    google_api_key: {
      pattern: /AIza[0-9A-Za-z\-_]{35}/,
      name: "Google API Key",
      severity: :critical
    },
    google_cloud_key: {
      pattern: /\"type\": \"service_account\"/,
      name: "Google Cloud Service Account Key",
      severity: :critical
    },
    slack_token: {
      pattern: /xox[baprs]-([0-9a-zA-Z]{10,48})/,
      name: "Slack Token",
      severity: :high
    },
    slack_webhook: {
      pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/,
      name: "Slack Webhook URL",
      severity: :high
    },
    stripe_api_key: {
      pattern: /(?:r|s)k_live_[0-9a-zA-Z]{24,}/,
      name: "Stripe Live API Key",
      severity: :critical
    },
    mailgun_api_key: {
      pattern: /key-[0-9a-zA-Z]{32}/,
      name: "Mailgun API Key",
      severity: :high
    },
    twilio_api_key: {
      pattern: /SK[0-9a-fA-F]{32}/,
      name: "Twilio API Key",
      severity: :high
    },
    private_key: {
      pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
      name: "Private Key",
      severity: :critical
    },
    jwt_secret: {
      pattern: /jwt[_\-\s]*secret[_\-\s]*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?/i,
      name: "JWT Secret",
      severity: :critical
    },
    database_url: {
      pattern: /(?:postgres|mysql|mongodb):\/\/[^\s:]+:[^\s@]+@[^\s\/]+/,
      name: "Database Connection String with Password",
      severity: :critical
    },
    generic_api_key: {
      pattern: /api[_\-\s]*key[_\-\s]*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?/i,
      name: "Generic API Key",
      severity: :high
    },
    generic_secret: {
      pattern: /(?:secret|password|passwd|pwd)[_\-\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?/i,
      name: "Generic Secret/Password",
      severity: :medium
    },
    bearer_token: {
      pattern: /bearer\s+[a-zA-Z0-9_\-\.=]{20,}/i,
      name: "Bearer Token",
      severity: :high
    },
    authorization_header: {
      pattern: /authorization[_\-\s]*[=:]\s*['\"]?(?:basic|bearer)\s+[a-zA-Z0-9_\-\.=]+['\"]?/i,
      name: "Authorization Header",
      severity: :high
    },
    ssh_key: {
      pattern: /ssh-(?:rsa|dss|ed25519) [A-Za-z0-9+\/]{100,}/,
      name: "SSH Public Key",
      severity: :medium
    },
    azure_key: {
      pattern: /[a-zA-Z0-9\/+]{86}==/,
      name: "Potential Azure Key",
      severity: :medium
    },
    sendgrid_api_key: {
      pattern: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/,
      name: "SendGrid API Key",
      severity: :high
    },
    facebook_access_token: {
      pattern: /EAA[a-zA-Z0-9]{90,}/,
      name: "Facebook Access Token",
      severity: :high
    },
    oauth_token: {
      pattern: /oauth[_\-\s]*(?:token|secret)[_\-\s]*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?/i,
      name: "OAuth Token/Secret",
      severity: :high
    }
  }.freeze unless defined?(SECRET_PATTERNS)

  # High entropy strings that might be secrets
  HIGH_ENTROPY_THRESHOLD = 4.5 unless defined?(HIGH_ENTROPY_THRESHOLD)

  def execute(params)
    input_type = params[:input_type]
    content = params[:content]
    file = params[:file]

    # Determine content to scan
    scan_content = if input_type&.include?("File Upload") && file.present?
                     file.read
                   elsif input_type&.include?("Text") && content.present?
                     content
                   else
                     return { error: "Please provide either text content or upload a file" }
                   end

    results = {
      scanned_bytes: scan_content.bytesize,
      scanned_lines: scan_content.lines.count,
      secrets_found: [],
      high_entropy_strings: [],
      total_findings: 0,
      risk_level: :low,
      recommendations: []
    }

    # Scan for known secret patterns
    scan_for_patterns(scan_content, results)

    # Scan for high entropy strings
    scan_for_high_entropy(scan_content, results)

    # Calculate risk level
    calculate_risk_level(results)

    results
  rescue StandardError => e
    { error: "Error scanning for secrets: #{e.message}" }
  end

  private

  def scan_for_patterns(content, results)
    lines = content.lines

    SECRET_PATTERNS.each do |type, config|
      pattern = config[:pattern]
      matches = content.scan(pattern)

      next if matches.empty?

      # Find line numbers for each match
      lines.each_with_index do |line, index|
        if line.match?(pattern)
          match_data = line.match(pattern)

          results[:secrets_found] << {
            type: type,
            name: config[:name],
            severity: config[:severity],
            line_number: index + 1,
            line_content: line.strip,
            matched_value: mask_secret(match_data[0]),
            full_match: match_data[0]
          }
        end
      end
    end

    results[:total_findings] = results[:secrets_found].length
  end

  def scan_for_high_entropy(content, results)
    # Look for assignment-like patterns with high entropy values
    content.lines.each_with_index do |line, index|
      # Match patterns like KEY=value or key: value
      if line =~ /(?:^|[\s,])([\w_-]+)\s*[=:]\s*['\"]?([a-zA-Z0-9+\/=_-]{20,})['\"]?/
        key_name = $1
        value = $2

        # Skip if already detected by pattern matching
        next if results[:secrets_found].any? { |s| s[:line_number] == index + 1 }

        # Calculate Shannon entropy
        entropy = calculate_entropy(value)

        if entropy > HIGH_ENTROPY_THRESHOLD && value.length >= 20
          results[:high_entropy_strings] << {
            key_name: key_name,
            entropy: entropy.round(2),
            length: value.length,
            line_number: index + 1,
            line_content: line.strip,
            masked_value: mask_secret(value),
            severity: :medium
          }

          results[:total_findings] += 1
        end
      end
    end
  end

  def calculate_entropy(string)
    return 0 if string.empty?

    frequencies = Hash.new(0)
    string.each_char { |char| frequencies[char] += 1 }

    entropy = 0
    string.length.times do |i|
      freq = frequencies[string[i]].to_f / string.length
      entropy -= freq * Math.log2(freq) if freq > 0
    end

    entropy
  end

  def mask_secret(value)
    return value if value.length < 8

    visible_chars = [value.length / 4, 4].min
    "#{value[0...visible_chars]}#{'*' * (value.length - visible_chars * 2)}#{value[-visible_chars..-1]}"
  end

  def calculate_risk_level(results)
    critical_count = results[:secrets_found].count { |s| s[:severity] == :critical }
    high_count = results[:secrets_found].count { |s| s[:severity] == :high }
    medium_count = results[:secrets_found].count { |s| s[:severity] == :medium }

    results[:risk_level] = if critical_count > 0
                            :critical
                          elsif high_count > 0
                            :high
                          elsif medium_count > 0 || results[:high_entropy_strings].any?
                            :medium
                          else
                            :low
                          end

    results[:recommendations] = generate_recommendations(results)
  end

  def generate_recommendations(results)
    recommendations = []

    if results[:total_findings] > 0
      recommendations << "CRITICAL: Remove all secrets from code and configuration files immediately"
      recommendations << "Rotate all exposed credentials (API keys, tokens, passwords)"
      recommendations << "Use environment variables or secret management tools (HashiCorp Vault, AWS Secrets Manager)"
      recommendations << "Add sensitive file patterns to .gitignore (.env, credentials.yml, etc.)"
      recommendations << "Consider using git-secrets or similar tools in pre-commit hooks"
      recommendations << "Audit git history for previously committed secrets using tools like truffleHog"
      recommendations << "Implement secret scanning in CI/CD pipeline"
    else
      recommendations << "No obvious secrets detected in the scanned content"
      recommendations << "Continue using secure secret management practices"
      recommendations << "Never commit .env files, credential files, or config with secrets"
      recommendations << "Use environment variables for sensitive configuration"
      recommendations << "Consider implementing automated secret scanning"
    end

    if results[:high_entropy_strings].any?
      recommendations << "Review high-entropy strings - they may be encoded secrets or tokens"
    end

    recommendations
  end
end

SecretsScannerTool.register!
