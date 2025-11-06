# HTTP Security Headers Analyzer Tool
# Description: Analyze HTTP response headers for security misconfigurations

class HttpHeadersAnalyzerTool
  include SecurityTool

  configure_tool(
    name: "HTTP Security Headers Analyzer",
    description: "Analyze HTTP response headers for security misconfigurations and missing security controls. Tests for CSP, HSTS, X-Frame-Options, and other critical security headers.",
    category: "Network Security"
  )

  input_field :url,
              type: :url,
              label: "Target URL",
              placeholder: "https://example.com",
              required: true

  output_format :html, :json

  def execute(params)
    url = params[:url]&.strip

    return { error: "URL is required" } if url.blank?

    # Add https:// if no protocol specified
    url = "https://#{url}" unless url.match?(/^https?:\/\//i)

    begin
      uri = URI.parse(url)
      return { error: "Invalid URL format" } unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

      # Fetch headers
      response = fetch_headers(uri)
      headers = response.to_hash

      # Analyze headers
      results = {
        url: url,
        status_code: response.code.to_i,
        security_headers: analyze_security_headers(headers),
        information_disclosure: check_information_disclosure(headers),
        score: 0,
        grade: "F",
        recommendations: []
      }

      # Calculate score
      calculate_score(results)

      results
    rescue URI::InvalidURIError
      { error: "Invalid URL format" }
    rescue SocketError
      { error: "Could not resolve hostname. Please check the URL." }
    rescue Net::OpenTimeout, Net::ReadTimeout
      { error: "Connection timeout. The server did not respond in time." }
    rescue OpenSSL::SSL::SSLError => e
      { error: "SSL/TLS error: #{e.message}" }
    rescue StandardError => e
      { error: "Error fetching headers: #{e.message}" }
    end
  end

  private

  def fetch_headers(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = 10
    http.read_timeout = 10
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE # For testing purposes

    request = Net::HTTP::Get.new(uri.request_uri)
    request['User-Agent'] = 'SecTools Security Scanner'

    http.request(request)
  end

  def analyze_security_headers(headers)
    {
      content_security_policy: check_csp(headers),
      strict_transport_security: check_hsts(headers),
      x_frame_options: check_x_frame_options(headers),
      x_content_type_options: check_x_content_type_options(headers),
      x_xss_protection: check_x_xss_protection(headers),
      referrer_policy: check_referrer_policy(headers),
      permissions_policy: check_permissions_policy(headers),
      cross_origin_policies: check_cross_origin_policies(headers)
    }
  end

  def check_csp(headers)
    csp = find_header(headers, ['content-security-policy'])

    if csp.present?
      issues = []
      issues << "Uses 'unsafe-inline' which allows inline scripts" if csp =~ /unsafe-inline/i
      issues << "Uses 'unsafe-eval' which allows eval()" if csp =~ /unsafe-eval/i
      issues << "Uses wildcard (*) which is overly permissive" if csp.include?('*')

      {
        present: true,
        value: csp,
        status: issues.empty? ? :good : :warning,
        issues: issues,
        score: issues.empty? ? 20 : 10
      }
    else
      {
        present: false,
        status: :critical,
        message: "Content-Security-Policy header is missing",
        recommendation: "Add CSP header to prevent XSS and data injection attacks",
        score: 0
      }
    end
  end

  def check_hsts(headers)
    hsts = find_header(headers, ['strict-transport-security'])

    if hsts.present?
      max_age = hsts[/max-age=(\d+)/, 1].to_i
      includes_subdomains = hsts.include?('includeSubDomains')
      preload = hsts.include?('preload')

      issues = []
      issues << "max-age is less than 1 year (recommended: 31536000)" if max_age < 31536000
      issues << "Missing 'includeSubDomains' directive" unless includes_subdomains

      {
        present: true,
        value: hsts,
        max_age: max_age,
        includes_subdomains: includes_subdomains,
        preload: preload,
        status: issues.empty? ? :good : :warning,
        issues: issues,
        score: issues.empty? ? 15 : 10
      }
    else
      {
        present: false,
        status: :critical,
        message: "Strict-Transport-Security header is missing",
        recommendation: "Add HSTS header to enforce HTTPS connections",
        score: 0
      }
    end
  end

  def check_x_frame_options(headers)
    xfo = find_header(headers, ['x-frame-options'])

    if xfo.present?
      value = xfo.upcase
      secure = ['DENY', 'SAMEORIGIN'].include?(value)

      {
        present: true,
        value: xfo,
        status: secure ? :good : :warning,
        message: secure ? "Properly configured" : "Value should be DENY or SAMEORIGIN",
        score: secure ? 15 : 8
      }
    else
      {
        present: false,
        status: :warning,
        message: "X-Frame-Options header is missing",
        recommendation: "Add X-Frame-Options to prevent clickjacking attacks",
        score: 0
      }
    end
  end

  def check_x_content_type_options(headers)
    xcto = find_header(headers, ['x-content-type-options'])

    if xcto.present? && xcto.downcase == 'nosniff'
      {
        present: true,
        value: xcto,
        status: :good,
        message: "Properly configured",
        score: 10
      }
    else
      {
        present: xcto.present?,
        value: xcto,
        status: :warning,
        message: xcto.present? ? "Value should be 'nosniff'" : "X-Content-Type-Options header is missing",
        recommendation: "Set to 'nosniff' to prevent MIME type sniffing",
        score: 0
      }
    end
  end

  def check_x_xss_protection(headers)
    xxp = find_header(headers, ['x-xss-protection'])

    {
      present: xxp.present?,
      value: xxp,
      status: :info,
      message: "This header is deprecated. Use Content-Security-Policy instead.",
      score: 0
    }
  end

  def check_referrer_policy(headers)
    rp = find_header(headers, ['referrer-policy'])

    if rp.present?
      secure_values = ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin']
      is_secure = secure_values.any? { |v| rp.downcase.include?(v) }

      {
        present: true,
        value: rp,
        status: is_secure ? :good : :warning,
        message: is_secure ? "Properly configured" : "Consider using a stricter policy",
        score: is_secure ? 10 : 5
      }
    else
      {
        present: false,
        status: :info,
        message: "Referrer-Policy header is missing",
        recommendation: "Consider adding Referrer-Policy to control referrer information",
        score: 0
      }
    end
  end

  def check_permissions_policy(headers)
    pp = find_header(headers, ['permissions-policy', 'feature-policy'])

    if pp.present?
      {
        present: true,
        value: pp,
        status: :good,
        message: "Permissions-Policy is configured",
        score: 10
      }
    else
      {
        present: false,
        status: :info,
        message: "Permissions-Policy header is missing",
        recommendation: "Consider adding Permissions-Policy to control browser features",
        score: 0
      }
    end
  end

  def check_cross_origin_policies(headers)
    corp = find_header(headers, ['cross-origin-resource-policy'])
    coep = find_header(headers, ['cross-origin-embedder-policy'])
    coop = find_header(headers, ['cross-origin-opener-policy'])

    {
      corp: {
        present: corp.present?,
        value: corp,
        status: corp.present? ? :good : :info
      },
      coep: {
        present: coep.present?,
        value: coep,
        status: coep.present? ? :good : :info
      },
      coop: {
        present: coop.present?,
        value: coop,
        status: coop.present? ? :good : :info
      },
      score: [corp, coep, coop].count(&:present?) * 3
    }
  end

  def check_information_disclosure(headers)
    issues = []

    server = find_header(headers, ['server'])
    if server.present?
      issues << {
        header: "Server",
        value: server,
        severity: :low,
        message: "Server header discloses server information"
      }
    end

    x_powered_by = find_header(headers, ['x-powered-by'])
    if x_powered_by.present?
      issues << {
        header: "X-Powered-By",
        value: x_powered_by,
        severity: :low,
        message: "Discloses technology stack information"
      }
    end

    x_aspnet_version = find_header(headers, ['x-aspnet-version'])
    if x_aspnet_version.present?
      issues << {
        header: "X-AspNet-Version",
        value: x_aspnet_version,
        severity: :medium,
        message: "Discloses ASP.NET version"
      }
    end

    issues
  end

  def find_header(headers, names)
    names.each do |name|
      value = headers[name]&.first || headers[name.downcase]&.first
      return value if value.present?
    end
    nil
  end

  def calculate_score(results)
    total_score = 0
    max_score = 100

    # Add up all scores
    sh = results[:security_headers]
    total_score += sh[:content_security_policy][:score]
    total_score += sh[:strict_transport_security][:score]
    total_score += sh[:x_frame_options][:score]
    total_score += sh[:x_content_type_options][:score]
    total_score += sh[:referrer_policy][:score]
    total_score += sh[:permissions_policy][:score]
    total_score += sh[:cross_origin_policies][:score]

    # Deduct points for information disclosure
    total_score -= results[:information_disclosure].length * 2

    # Calculate percentage
    percentage = [(total_score.to_f / max_score * 100).round, 100].min

    results[:score] = percentage
    results[:grade] = case percentage
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

    sh = results[:security_headers]

    recommendations << "Implement Content-Security-Policy header to prevent XSS attacks" unless sh[:content_security_policy][:present]
    recommendations << "Add Strict-Transport-Security header with long max-age" unless sh[:strict_transport_security][:present]
    recommendations << "Set X-Frame-Options to DENY or SAMEORIGIN" unless sh[:x_frame_options][:present]
    recommendations << "Enable X-Content-Type-Options: nosniff" unless sh[:x_content_type_options][:present]
    recommendations << "Configure Referrer-Policy for privacy" unless sh[:referrer_policy][:present]
    recommendations << "Remove or obfuscate Server and X-Powered-By headers" if results[:information_disclosure].any?
    recommendations << "Consider implementing Cross-Origin policies (CORP, COEP, COOP)" if sh[:cross_origin_policies][:score] < 9

    recommendations
  end
end

HttpHeadersAnalyzerTool.register!
