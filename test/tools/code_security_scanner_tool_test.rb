# frozen_string_literal: true

require "test_helper"

class CodeSecurityScannerToolTest < ActiveSupport::TestCase
  def setup
    @tool = CodeSecurityScannerTool.new
  end

  test "tool is properly configured" do
    assert_equal "Code Security Scanner", CodeSecurityScannerTool.tool_name
    assert_equal "Code Security", CodeSecurityScannerTool.tool_category
    assert_includes CodeSecurityScannerTool.tool_outputs, :html
    assert_includes CodeSecurityScannerTool.tool_outputs, :json
  end

  test "vulnerability patterns are loaded from YAML files" do
    patterns = CodeSecurityScannerTool.vulnerability_patterns

    assert patterns.is_a?(Hash)
    assert patterns.key?(:sql_injection)
    assert patterns.key?(:xss)
    assert patterns.key?(:command_injection)
    assert patterns.key?(:hardcoded_secrets)
  end

  test "detects SQL injection in Ruby code" do
    ruby_code = <<~RUBY
      class UserController
        def search
          User.where("email = '" + params[:email] + "'")
        end
      end
    RUBY

    result = @tool.execute(source_file: ruby_code, scan_depth: false)

    assert_operator result[:findings].length, :>, 0
    sql_findings = result[:findings].select { |f| f[:vulnerability_type] == "SQL Injection" }
    assert_operator sql_findings.length, :>, 0
    assert_equal "CRITICAL", sql_findings.first[:severity]
  end

  test "detects XSS in JavaScript code" do
    js_code = <<~JS
      function displayContent(userInput) {
        document.getElementById('content').innerHTML = userInput;
      }
    JS

    result = @tool.execute(source_file: js_code, scan_depth: false)

    assert_operator result[:findings].length, :>, 0
    xss_findings = result[:findings].select { |f| f[:vulnerability_type] == "Cross-Site Scripting (XSS)" }
    assert_operator xss_findings.length, :>, 0
    assert_equal "HIGH", xss_findings.first[:severity]
  end

  test "detects hardcoded secrets" do
    ruby_code = <<~RUBY
      class ApiClient
        API_KEY = "sk_live_1234567890abcdef"
        PASSWORD = "MyP@ssw0rd"
      end
    RUBY

    result = @tool.execute(source_file: ruby_code, scan_depth: false)

    secret_findings = result[:findings].select { |f| f[:vulnerability_type] == "Hardcoded Secrets" }
    assert_operator secret_findings.length, :>, 0
    assert_equal "CRITICAL", secret_findings.first[:severity]
  end

  test "detects command injection in Python code" do
    python_code = <<~PYTHON
      import os
      def execute(directory):
          os.system("ls " + directory)
    PYTHON

    result = @tool.execute(source_file: python_code, scan_depth: false)

    cmd_findings = result[:findings].select { |f| f[:vulnerability_type] == "Command Injection" }
    assert_operator cmd_findings.length, :>, 0
    assert_equal "CRITICAL", cmd_findings.first[:severity]
  end

  test "detects JWT issues" do
    ruby_code = <<~RUBY
      def verify
        JWT.decode(token, nil, false)
      end
    RUBY

    result = @tool.execute(source_file: ruby_code, scan_depth: false)

    jwt_findings = result[:findings].select { |f| f[:vulnerability_type] == "JWT Security Issues" }
    assert_operator jwt_findings.length, :>, 0
    assert_equal "HIGH", jwt_findings.first[:severity]
  end

  test "detects weak cryptography" do
    ruby_code = <<~RUBY
      def hash_password(pwd)
        Digest::MD5.hexdigest(pwd)
      end
    RUBY

    result = @tool.execute(source_file: ruby_code, scan_depth: false)

    crypto_findings = result[:findings].select { |f| f[:vulnerability_type] == "Weak Cryptography" }
    assert_operator crypto_findings.length, :>, 0
    assert_equal "MEDIUM", crypto_findings.first[:severity]
  end

  test "returns summary with severity counts" do
    ruby_code = <<~RUBY
      class Test
        def search
          User.where("id = " + params[:id])  # SQL Injection - CRITICAL
        end

        def hash
          Digest::MD5.hexdigest(password)  # Weak Crypto - MEDIUM
        end
      end
    RUBY

    result = @tool.execute(source_file: ruby_code, scan_depth: false)

    assert result[:summary].is_a?(Hash)
    assert result[:summary].key?(:total)
    assert result[:summary].key?(:critical)
    assert result[:summary].key?(:high)
    assert result[:summary].key?(:medium)
    assert result[:summary].key?(:low)

    assert_operator result[:summary][:total], :>, 0
  end

  test "scans test fixture files" do
    # Test Ruby file
    ruby_file = File.read(Rails.root.join('test/fixtures/files/vulnerable_test.rb'))
    result = @tool.execute(source_file: ruby_file, scan_depth: false)

    assert_operator result[:findings].length, :>, 10, "Should detect multiple vulnerabilities in Ruby test file"
    assert_operator result[:summary][:critical], :>, 0
    assert_operator result[:summary][:high], :>, 0
    assert_operator result[:summary][:medium], :>, 0
  end

  test "handles empty file" do
    result = @tool.execute(source_file: "", scan_depth: false)

    assert result[:error].present?
  end

  test "handles non-code content gracefully" do
    text_content = "This is just plain text with no code"

    result = @tool.execute(source_file: text_content, scan_depth: false)

    assert_equal 0, result[:findings].length
    assert_equal 0, result[:summary][:total]
  end

  test "language detection works correctly" do
    assert_equal :ruby, @tool.send(:detect_language, "test.rb")
    assert_equal :javascript, @tool.send(:detect_language, "test.js")
    assert_equal :python, @tool.send(:detect_language, "test.py")
    assert_equal :php, @tool.send(:detect_language, "test.php")
    assert_equal :java, @tool.send(:detect_language, "test.java")
  end

  test "severity ranking works correctly" do
    assert_equal 4, @tool.send(:severity_rank, "CRITICAL")
    assert_equal 3, @tool.send(:severity_rank, "HIGH")
    assert_equal 2, @tool.send(:severity_rank, "MEDIUM")
    assert_equal 1, @tool.send(:severity_rank, "LOW")
    assert_equal 0, @tool.send(:severity_rank, "UNKNOWN")
  end

  test "findings include code snippets" do
    ruby_code = <<~RUBY
      class Test
        def vulnerable
          User.where("id = " + params[:id])
        end
      end
    RUBY

    result = @tool.execute(source_file: ruby_code, scan_depth: false)

    finding = result[:findings].first
    assert finding[:code_snippet].present?
    assert_includes finding[:code_snippet], ">>>"  # Highlights the vulnerable line
  end

  test "findings include recommendations" do
    ruby_code = <<~RUBY
      User.where("id = " + params[:id])
    RUBY

    result = @tool.execute(source_file: ruby_code, scan_depth: false)

    finding = result[:findings].first
    assert finding[:recommendation].present?
  end
end
