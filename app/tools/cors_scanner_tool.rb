# CORS/Cross-Origin Scanner Tool
# Description: Test web applications for CORS misconfigurations

class CorsScannerTool
  include SecurityTool

  configure_tool(
    name: "CORS/Cross-Origin Scanner",
    description: "Test web applications for CORS (Cross-Origin Resource Sharing) misconfigurations that could lead to cross-origin attacks and data theft.",
    category: "Network Security"
  )

  input_field :url,
              type: :url,
              label: "Target URL",
              placeholder: "https://api.example.com/endpoint",
              required: true

  input_field :test_origins,
              type: :text,
              label: "Test Origins (comma-separated, optional)",
              placeholder: "https://evil.com, https://attacker.com, null",
              required: false

  output_format :html, :json

  def execute(params)
    url = params[:url]&.strip
    custom_origins = params[:test_origins]&.strip

    return { error: "URL is required" } if url.blank?

    # Add https:// if no protocol specified
    url = "https://#{url}" unless url.match?(/^https?:\/\//i)

    begin
      uri = URI.parse(url)
      return { error: "Invalid URL format" } unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

      # Parse custom test origins if provided
      test_origins = if custom_origins.present?
                      custom_origins.split(',').map(&:strip).reject(&:blank?)
                    else
                      default_test_origins(uri)
                    end

      # Perform CORS tests
      results = {
        url: url,
        tests_performed: [],
        vulnerabilities: [],
        findings: [],
        risk_level: :low,
        score: 100,
        recommendations: []
      }

      # Test each origin
      test_origins.each do |origin|
        test_result = test_cors_with_origin(uri, origin)
        results[:tests_performed] << test_result

        analyze_cors_response(test_result, results)
      end

      # Test for null origin
      null_test = test_cors_with_origin(uri, "null")
      results[:tests_performed] << null_test
      analyze_cors_response(null_test, results)

      # Calculate final risk and score
      calculate_risk_score(results)

      results
    rescue URI::InvalidURIError
      { error: "Invalid URL format" }
    rescue SocketError
      { error: "Could not resolve hostname" }
    rescue StandardError => e
      { error: "Error testing CORS: #{e.message}" }
    end
  end

  private

  def default_test_origins(uri)
    base_domain = uri.host

    [
      "https://evil.com",
      "https://attacker.com",
      "http://#{base_domain}",  # Protocol mismatch
      "https://subdomain.#{base_domain}",  # Subdomain test
      "https://#{base_domain}.evil.com"  # Domain suffix test
    ]
  end

  def test_cors_with_origin(uri, origin)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = 10
    http.read_timeout = 10
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    # Test OPTIONS preflight request
    preflight_request = Net::HTTP::Options.new(uri.request_uri)
    preflight_request['Origin'] = origin
    preflight_request['Access-Control-Request-Method'] = 'POST'
    preflight_request['Access-Control-Request-Headers'] = 'content-type,authorization'

    preflight_response = http.request(preflight_request)

    # Test actual GET request
    get_request = Net::HTTP::Get.new(uri.request_uri)
    get_request['Origin'] = origin

    get_response = http.request(get_request)

    {
      origin: origin,
      preflight: {
        status: preflight_response.code.to_i,
        acao: preflight_response['access-control-allow-origin'],
        acac: preflight_response['access-control-allow-credentials'],
        acam: preflight_response['access-control-allow-methods'],
        acah: preflight_response['access-control-allow-headers'],
        acma: preflight_response['access-control-max-age']
      },
      actual: {
        status: get_response.code.to_i,
        acao: get_response['access-control-allow-origin'],
        acac: get_response['access-control-allow-credentials']
      }
    }
  rescue StandardError => e
    {
      origin: origin,
      error: e.message
    }
  end

  def analyze_cors_response(test_result, results)
    return if test_result[:error].present?

    origin = test_result[:origin]
    preflight = test_result[:preflight]
    actual = test_result[:actual]

    # Check for wildcard with credentials (critical vulnerability)
    if (preflight[:acao] == '*' || actual[:acao] == '*') &&
       (preflight[:acac] == 'true' || actual[:acac] == 'true')
      results[:vulnerabilities] << {
        severity: :critical,
        type: "Wildcard CORS with Credentials",
        origin: origin,
        message: "Server accepts wildcard origin (*) with credentials enabled - allows any origin to access authenticated data",
        impact: "Complete account takeover, data theft"
      }
      results[:score] -= 40
    end

    # Check for origin reflection
    if (preflight[:acao] == origin || actual[:acao] == origin) && !origin.include?(results[:url])
      results[:vulnerabilities] << {
        severity: :high,
        type: "Origin Reflection",
        origin: origin,
        message: "Server reflects the Origin header back, accepting arbitrary origins",
        impact: "Allows attackers to bypass CORS protections"
      }
      results[:score] -= 25
    end

    # Check for null origin acceptance
    if origin == "null" && (preflight[:acao] == "null" || actual[:acao] == "null")
      results[:vulnerabilities] << {
        severity: :high,
        type: "Null Origin Accepted",
        origin: origin,
        message: "Server accepts 'null' origin (file://, sandboxed iframes)",
        impact: "Allows attacks from sandboxed contexts"
      }
      results[:score] -= 25
    end

    # Check for overly permissive methods
    if preflight[:acam].present?
      dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
      allowed_methods = preflight[:acam].split(',').map(&:strip).map(&:upcase)
      dangerous_found = allowed_methods & dangerous_methods

      if dangerous_found.any?
        results[:findings] << {
          severity: :medium,
          type: "Permissive Methods",
          origin: origin,
          message: "Allows potentially dangerous HTTP methods: #{dangerous_found.join(', ')}",
          impact: "May allow unauthorized data modification"
        }
        results[:score] -= 10
      end
    end

    # Check for wildcard origin (without credentials - lower risk)
    if (preflight[:acao] == '*' || actual[:acao] == '*') &&
       preflight[:acac] != 'true' && actual[:acac] != 'true'
      results[:findings] << {
        severity: :low,
        type: "Wildcard CORS",
        origin: origin,
        message: "Server uses wildcard (*) for Access-Control-Allow-Origin",
        impact: "Allows any origin to make requests, but without credentials"
      }
      results[:score] -= 5
    end

    # Check for long max-age
    if preflight[:acma].present? && preflight[:acma].to_i > 86400
      results[:findings] << {
        severity: :info,
        type: "Long Preflight Cache",
        origin: origin,
        message: "Preflight responses cached for #{preflight[:acma]} seconds (>24 hours)",
        impact: "CORS policy changes won't take effect immediately"
      }
    end
  end

  def calculate_risk_score(results)
    # Ensure score doesn't go below 0
    results[:score] = [results[:score], 0].max

    # Determine risk level based on vulnerabilities
    if results[:vulnerabilities].any? { |v| v[:severity] == :critical }
      results[:risk_level] = :critical
    elsif results[:vulnerabilities].any? { |v| v[:severity] == :high }
      results[:risk_level] = :high
    elsif results[:findings].any? { |f| f[:severity] == :medium }
      results[:risk_level] = :medium
    elsif results[:findings].any?
      results[:risk_level] = :low
    else
      results[:risk_level] = :secure
    end

    # Generate recommendations
    results[:recommendations] = generate_recommendations(results)

    # Add grade
    results[:grade] = case results[:score]
                      when 90..100 then "A"
                      when 80..89 then "B"
                      when 70..79 then "C"
                      when 60..69 then "D"
                      else "F"
                      end
  end

  def generate_recommendations(results)
    recommendations = []

    if results[:vulnerabilities].any? { |v| v[:type] == "Wildcard CORS with Credentials" }
      recommendations << "CRITICAL: Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
      recommendations << "Whitelist specific trusted origins instead of using wildcards"
    end

    if results[:vulnerabilities].any? { |v| v[:type] == "Origin Reflection" }
      recommendations << "Do not reflect the Origin header back without validation"
      recommendations << "Implement a strict whitelist of allowed origins"
    end

    if results[:vulnerabilities].any? { |v| v[:type] == "Null Origin Accepted" }
      recommendations << "Do not accept 'null' as a valid origin"
      recommendations << "Reject requests with null origin or use strict origin validation"
    end

    if results[:findings].any? { |f| f[:type] == "Permissive Methods" }
      recommendations << "Only allow necessary HTTP methods in Access-Control-Allow-Methods"
      recommendations << "Restrict dangerous methods (PUT, DELETE, PATCH) to authenticated requests"
    end

    if results[:findings].any? { |f| f[:type] == "Wildcard CORS" }
      recommendations << "Consider using specific origin whitelisting instead of wildcards"
      recommendations << "If public API, document that authentication is not supported"
    end

    if recommendations.empty?
      recommendations << "CORS configuration appears secure"
      recommendations << "Continue to validate all incoming requests server-side"
      recommendations << "Regularly review and update the origin whitelist"
    end

    recommendations
  end
end

CorsScannerTool.register!
