# API Endpoint Security Scanner Tool
# Description: Test REST/GraphQL endpoints for common vulnerabilities

class ApiSecurityScannerTool
  include SecurityTool

  configure_tool(
    name: "API Endpoint Security Scanner",
    description: "Test REST and GraphQL API endpoints for common security vulnerabilities including authentication bypass, parameter tampering, injection flaws, rate limiting, and improper error handling.",
    category: "API Security"
  )

  input_field :endpoint_url,
              type: :url,
              label: "API Endpoint URL",
              placeholder: "https://api.example.com/v1/users",
              required: true

  input_field :api_type,
              type: :select,
              label: "API Type",
              options: ["REST", "GraphQL"],
              required: true

  input_field :http_method,
              type: :select,
              label: "HTTP Method (for REST)",
              options: ["GET", "POST", "PUT", "PATCH", "DELETE"],
              required: false

  input_field :auth_token,
              type: :password,
              label: "Authorization Token (optional)",
              placeholder: "Bearer token or API key",
              required: false

  input_field :request_body,
              type: :text,
              label: "Request Body (JSON, optional)",
              placeholder: '{"key": "value"}',
              required: false

  output_format :html, :json

  def execute(params)
    endpoint_url = params[:endpoint_url]&.strip
    api_type = params[:api_type]
    http_method = params[:http_method] || "GET"
    auth_token = params[:auth_token]
    request_body = params[:request_body]&.strip

    return { error: "Endpoint URL is required" } if endpoint_url.blank?

    # Add https:// if no protocol specified
    endpoint_url = "https://#{endpoint_url}" unless endpoint_url.match?(/^https?:\/\//i)

    begin
      uri = URI.parse(endpoint_url)
      return { error: "Invalid URL format" } unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

      results = {
        endpoint: endpoint_url,
        api_type: api_type,
        tests_performed: [],
        vulnerabilities: [],
        warnings: [],
        info: [],
        security_score: 100,
        risk_level: :low,
        recommendations: []
      }

      # Perform security tests
      test_authentication(uri, auth_token, http_method, results)
      test_rate_limiting(uri, auth_token, http_method, results)
      test_error_handling(uri, auth_token, http_method, results)
      test_http_methods(uri, auth_token, results)
      test_injection_vulnerabilities(uri, auth_token, http_method, request_body, results)
      test_information_disclosure(uri, auth_token, http_method, results)

      if api_type == "GraphQL"
        test_graphql_specific(uri, auth_token, results)
      end

      # Calculate final score and risk
      calculate_security_score(results)

      results
    rescue URI::InvalidURIError
      { error: "Invalid URL format" }
    rescue StandardError => e
      { error: "Error scanning API: #{e.message}" }
    end
  end

  private

  def make_request(uri, method, headers = {}, body = nil)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = 10
    http.read_timeout = 10
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request_class = case method.upcase
                    when "GET" then Net::HTTP::Get
                    when "POST" then Net::HTTP::Post
                    when "PUT" then Net::HTTP::Put
                    when "PATCH" then Net::HTTP::Patch
                    when "DELETE" then Net::HTTP::Delete
                    when "OPTIONS" then Net::HTTP::Options
                    when "HEAD" then Net::HTTP::Head
                    else Net::HTTP::Get
                    end

    request = request_class.new(uri.request_uri)
    headers.each { |key, value| request[key] = value }
    request.body = body if body && !["GET", "HEAD"].include?(method.upcase)

    http.request(request)
  rescue StandardError => e
    OpenStruct.new(code: "000", body: "", message: e.message)
  end

  def test_authentication(uri, auth_token, method, results)
    results[:tests_performed] << "Authentication Testing"

    # Test without authentication
    response_no_auth = make_request(uri, method)

    # Test with authentication if token provided
    if auth_token.present?
      headers = { 'Authorization' => auth_token }
      response_with_auth = make_request(uri, method, headers)

      if response_with_auth.code == response_no_auth.code && response_no_auth.code.to_i < 400
        results[:vulnerabilities] << {
          severity: :critical,
          type: "Authentication Not Required",
          message: "Endpoint responds with same status code with and without authentication",
          impact: "Potential authentication bypass",
          status_codes: "Without auth: #{response_no_auth.code}, With auth: #{response_with_auth.code}"
        }
        results[:security_score] -= 30
      end
    else
      if response_no_auth.code.to_i < 400
        results[:info] << {
          type: "No Authentication Tested",
          message: "Endpoint is accessible without authentication",
          note: "Provide an auth token to test authentication properly"
        }
      end
    end

    # Test for common authentication bypasses
    bypass_attempts = [
      { header: 'X-Original-URL', value: '/admin' },
      { header: 'X-Rewrite-URL', value: '/admin' },
      { header: 'X-Forwarded-For', value: '127.0.0.1' },
      { header: 'X-Remote-Addr', value: '127.0.0.1' }
    ]

    bypass_attempts.each do |attempt|
      response = make_request(uri, method, { attempt[:header] => attempt[:value] })
      if response.code.to_i < 400 && response.code != response_no_auth.code
        results[:vulnerabilities] << {
          severity: :high,
          type: "Header-Based Authentication Bypass",
          message: "Endpoint behavior changes with #{attempt[:header]} header",
          impact: "Possible authentication/authorization bypass"
        }
        results[:security_score] -= 20
        break
      end
    end
  end

  def test_rate_limiting(uri, auth_token, method, results)
    results[:tests_performed] << "Rate Limiting Testing"

    headers = {}
    headers['Authorization'] = auth_token if auth_token.present?

    # Make multiple rapid requests
    responses = []
    5.times do
      response = make_request(uri, method, headers)
      responses << response.code.to_i
    end

    # Check if we got rate limited
    rate_limited = responses.any? { |code| code == 429 }

    unless rate_limited
      results[:warnings] << {
        type: "No Rate Limiting Detected",
        message: "Made 5 rapid requests without hitting rate limits",
        impact: "API may be vulnerable to abuse and DoS attacks",
        recommendation: "Implement rate limiting (e.g., 100 requests per minute)"
      }
      results[:security_score] -= 10
    end

    # Check for rate limit headers
    last_response = make_request(uri, method, headers)
    rate_limit_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-Rate-Limit', 'RateLimit-Limit']

    has_rate_limit_headers = rate_limit_headers.any? { |h| last_response[h].present? }

    if has_rate_limit_headers
      results[:info] << {
        type: "Rate Limit Headers Present",
        message: "API provides rate limiting information in headers"
      }
    end
  end

  def test_error_handling(uri, auth_token, method, results)
    results[:tests_performed] << "Error Handling Testing"

    headers = {}
    headers['Authorization'] = auth_token if auth_token.present?

    # Test with malformed requests
    test_cases = [
      { desc: "Invalid JSON", body: '{invalid json}', content_type: 'application/json' },
      { desc: "SQL Injection Attempt", body: '{"id": "1\' OR \'1\'=\'1"}', content_type: 'application/json' },
      { desc: "XXE Attempt", body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', content_type: 'application/xml' }
    ]

    test_cases.each do |test_case|
      next if method.upcase == "GET"

      test_headers = headers.merge({ 'Content-Type' => test_case[:content_type] })
      response = make_request(uri, method, test_headers, test_case[:body])

      # Check for verbose error messages
      if response.body.length > 500 || response.body.match?(/stack trace|exception|error at line|file.*line \d+/i)
        results[:vulnerabilities] << {
          severity: :medium,
          type: "Verbose Error Messages",
          message: "API returns detailed error messages for #{test_case[:desc]}",
          impact: "Information disclosure that aids attackers",
          response_length: response.body.length
        }
        results[:security_score] -= 15
        break
      end
    end
  end

  def test_http_methods(uri, auth_token, results)
    results[:tests_performed] << "HTTP Methods Testing"

    headers = {}
    headers['Authorization'] = auth_token if auth_token.present?

    # Test OPTIONS to see what methods are allowed
    options_response = make_request(uri, "OPTIONS", headers)
    allowed_methods = options_response['Allow']

    if allowed_methods.present?
      results[:info] << {
        type: "Allowed HTTP Methods",
        message: "Server reports allowed methods: #{allowed_methods}"
      }

      dangerous_methods = ['TRACE', 'CONNECT', 'PUT', 'DELETE']
      found_dangerous = dangerous_methods.select { |m| allowed_methods.upcase.include?(m) }

      if found_dangerous.any?
        results[:warnings] << {
          type: "Potentially Dangerous Methods Allowed",
          message: "Server allows: #{found_dangerous.join(', ')}",
          recommendation: "Ensure these methods require proper authorization"
        }
        results[:security_score] -= 5
      end
    end

    # Test if TRACE is actually enabled (XST vulnerability)
    trace_response = make_request(uri, "TRACE", headers)
    if trace_response.code.to_i == 200
      results[:vulnerabilities] << {
        severity: :medium,
        type: "TRACE Method Enabled (XST)",
        message: "HTTP TRACE method is enabled",
        impact: "Cross-Site Tracing (XST) attack possible",
        recommendation: "Disable TRACE method"
      }
      results[:security_score] -= 10
    end
  end

  def test_injection_vulnerabilities(uri, auth_token, method, request_body, results)
    results[:tests_performed] << "Injection Vulnerability Testing"

    return if method.upcase == "GET" && request_body.blank?

    headers = { 'Content-Type' => 'application/json' }
    headers['Authorization'] = auth_token if auth_token.present?

    # SQL Injection payloads
    sql_payloads = [
      "' OR '1'='1",
      "1' OR '1'='1' --",
      "' UNION SELECT NULL--"
    ]

    # NoSQL Injection payloads
    nosql_payloads = [
      '{"$gt": ""}',
      '{"$ne": null}'
    ]

    # Test SQL injection
    sql_payloads.each do |payload|
      test_body = if request_body.present?
                    request_body.gsub(/"[^"]*"/, "\"#{payload}\"")
                  else
                    "{\"id\": \"#{payload}\"}"
                  end

      response = make_request(uri, method, headers, test_body)

      # Look for SQL error messages
      if response.body.match?(/sql|mysql|postgresql|sqlite|oracle|syntax error|database/i)
        results[:vulnerabilities] << {
          severity: :critical,
          type: "SQL Injection Vulnerability",
          message: "API returns database error messages",
          impact: "Database could be compromised",
          payload: payload
        }
        results[:security_score] -= 40
        break
      end
    end
  end

  def test_information_disclosure(uri, auth_token, method, results)
    results[:tests_performed] << "Information Disclosure Testing"

    headers = {}
    headers['Authorization'] = auth_token if auth_token.present?

    response = make_request(uri, method, headers)

    # Check response headers for information disclosure
    server_header = response['Server']
    x_powered_by = response['X-Powered-By']
    x_aspnet_version = response['X-AspNet-Version']

    disclosed_info = []
    disclosed_info << "Server: #{server_header}" if server_header.present?
    disclosed_info << "X-Powered-By: #{x_powered_by}" if x_powered_by.present?
    disclosed_info << "X-AspNet-Version: #{x_aspnet_version}" if x_aspnet_version.present?

    if disclosed_info.any?
      results[:warnings] << {
        type: "Information Disclosure in Headers",
        message: "Server discloses technology information",
        headers: disclosed_info,
        recommendation: "Remove or obfuscate server version headers"
      }
      results[:security_score] -= 5
    end

    # Check for API keys or tokens in response
    if response.body.match?(/api[_-]?key|token|secret|password|bearer/i)
      results[:warnings] << {
        type: "Potential Sensitive Data in Response",
        message: "Response may contain API keys or tokens",
        recommendation: "Review response for sensitive data exposure"
      }
      results[:security_score] -= 10
    end
  end

  def test_graphql_specific(uri, auth_token, results)
    results[:tests_performed] << "GraphQL-Specific Testing"

    headers = { 'Content-Type' => 'application/json' }
    headers['Authorization'] = auth_token if auth_token.present?

    # Test introspection query
    introspection_query = {
      query: "{ __schema { types { name } } }"
    }.to_json

    response = make_request(uri, "POST", headers, introspection_query)

    if response.code.to_i == 200 && response.body.include?('__schema')
      results[:warnings] << {
        type: "GraphQL Introspection Enabled",
        message: "GraphQL introspection is enabled in production",
        impact: "Attackers can discover entire API schema",
        recommendation: "Disable introspection in production environments"
      }
      results[:security_score] -= 15
    end

    # Test for query depth/complexity attacks
    deep_query = {
      query: "{ users { posts { comments { author { posts { comments { id } } } } } } }"
    }.to_json

    response = make_request(uri, "POST", headers, deep_query)

    if response.code.to_i == 200
      results[:warnings] << {
        type: "No Query Depth Limiting",
        message: "GraphQL accepts deeply nested queries",
        impact: "Vulnerable to DoS through expensive queries",
        recommendation: "Implement query depth and complexity limiting"
      }
      results[:security_score] -= 10
    end
  end

  def calculate_security_score(results)
    # Ensure score doesn't go below 0
    results[:security_score] = [results[:security_score], 0].max

    # Calculate risk level
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

    # Generate recommendations
    results[:recommendations] = generate_recommendations(results)
  end

  def generate_recommendations(results)
    recommendations = []

    if results[:vulnerabilities].any? { |v| v[:type].include?("SQL Injection") }
      recommendations << "CRITICAL: Fix SQL injection vulnerabilities immediately"
      recommendations << "Use parameterized queries and ORM frameworks"
    end

    if results[:vulnerabilities].any? { |v| v[:type].include?("Authentication") }
      recommendations << "CRITICAL: Implement proper authentication and authorization"
      recommendations << "Validate all authentication tokens server-side"
    end

    if results[:warnings].any? { |w| w[:type].include?("Rate Limiting") }
      recommendations << "Implement rate limiting to prevent abuse (e.g., 100 req/min per IP)"
      recommendations << "Consider using API gateway for centralized rate limiting"
    end

    if results[:vulnerabilities].any? { |v| v[:type].include?("Error") }
      recommendations << "Sanitize error messages - never expose stack traces or internal details"
      recommendations << "Log detailed errors server-side, return generic messages to clients"
    end

    if results[:warnings].any? { |w| w[:type].include?("GraphQL") }
      recommendations << "Disable GraphQL introspection in production"
      recommendations << "Implement query depth, complexity, and cost analysis"
    end

    recommendations << "Implement HTTPS for all API endpoints" unless results[:endpoint].start_with?("https://")
    recommendations << "Use API versioning (e.g., /v1/, /v2/)"
    recommendations << "Implement comprehensive logging and monitoring"
    recommendations << "Regular security testing and penetration testing"
    recommendations << "Follow OWASP API Security Top 10 guidelines"

    recommendations
  end
end

ApiSecurityScannerTool.register!
