# frozen_string_literal: true

require "json"
require "yaml"
require "set"
require "active_support/core_ext/hash/indifferent_access"

# API Schema Security Reviewer
# Analyzes OpenAPI/Swagger specifications for security gaps
class ApiSchemaSecurityReviewerTool
  include SecurityTool

  configure_tool(
    name: "API Schema Security Reviewer",
    description: "Analyze OpenAPI/Swagger specs for security misconfigurations and missing protections",
    category: "Application Security",
  )

  input_field :api_spec_file,
              type: :file,
              label: "OpenAPI / Swagger File",
              placeholder: "Upload .yaml, .yml, or .json API specification",
              required: true,
              accept: ".yaml,.yml,.json"

  input_field :treat_get_as_sensitive,
              type: :checkbox,
              label: "Treat GET endpoints as sensitive",
              placeholder: "Enable to require auth on all HTTP verbs",
              required: false

  output_format :html, :json

  HTTP_METHODS = %w[get post put patch delete head options trace].freeze unless defined?(HTTP_METHODS)

  def execute(params)
    file_content = params[:api_spec_file]
    treat_get_as_sensitive = params[:treat_get_as_sensitive] == "1" || params[:treat_get_as_sensitive] == true

    if file_content.blank?
      return {
        error: "No API specification provided",
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      }
    end

    spec = parse_spec(file_content)
    return spec if spec[:error] # Propagate parse error

    analysis = analyze_spec(spec[:data], treat_get_as_sensitive)
    analysis
  rescue StandardError => e
    {
      error: "Failed to analyze API specification: #{e.message}",
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    }
  end

  private

  def parse_spec(file_content)
    data = begin
      JSON.parse(file_content)
    rescue JSON::ParserError
      begin
        YAML.safe_load(file_content, aliases: true)
      rescue Psych::SyntaxError => e
        return { error: "Invalid OpenAPI/Swagger document: #{e.message}" }
      end
    end

    unless data.is_a?(Hash)
      return { error: "Unsupported spec format. Expected a JSON or YAML object at the root." }
    end

    { data: deep_stringify(data) }
  end

  def analyze_spec(spec, treat_get_as_sensitive)
    info = {
      title: spec.dig("info", "title"),
      version: spec.dig("info", "version"),
      openapi_version: spec["openapi"] || spec["swagger"],
    }

    security_schemes = extract_security_schemes(spec)
    operations = extract_operations(spec)
    global_security = normalize_security(spec["security"])

    findings = []
    unauthenticated_operations = 0
    operations.each do |operation|
      method = operation[:method]
      verb = method.upcase
      requires_auth = treat_get_as_sensitive || !%w[GET HEAD OPTIONS TRACE].include?(verb)

      operation_security = normalize_security(operation[:operation].fetch("security", nil)) ||
        normalize_security(operation[:path_item].fetch("security", nil)) ||
        global_security

      if requires_auth && (operation_security.nil? || operation_security.empty?)
        unauthenticated_operations += 1
        severity = %w[POST PUT PATCH DELETE].include?(verb) ? "CRITICAL" : "HIGH"
        findings << build_finding(
          severity: severity,
          issue: "Missing authentication requirement",
          message: "#{verb} #{operation[:path]} does not declare any security requirements.",
          remediation: "Attach a security scheme (e.g., OAuth2, API key header, JWT bearer) to this operation.",
          metadata: { path: operation[:path], method: verb },
        )
      end

      unless declares_auth_responses?(operation[:operation])
        findings << build_finding(
          severity: "MEDIUM",
          issue: "Missing auth error responses",
          message: "#{verb} #{operation[:path]} does not document 401/403 responses.",
          remediation: "Document 401 Unauthorized and 403 Forbidden responses to set correct expectations and enforce access control.",
          metadata: { path: operation[:path], method: verb },
        )
      end

      if rate_limiting_missing?(operation[:operation])
        findings << build_finding(
          severity: "LOW",
          issue: "Rate limiting not documented",
          message: "#{verb} #{operation[:path]} does not advertise rate limiting (e.g., 429 response or x-rate-limit headers).",
          remediation: "Expose throttling behaviour with a documented 429 response or vendor extensions so consumers understand protection limits.",
          metadata: { path: operation[:path], method: verb },
        )
      end
    end

    if security_schemes.empty?
      findings << build_finding(
        severity: "CRITICAL",
        issue: "No security schemes defined",
        message: "The specification does not define any security schemes.",
        remediation: "Define authentication mechanisms under components.securitySchemes (OpenAPI 3) or securityDefinitions (Swagger 2).",
      )
    end

    if global_security.nil? || global_security.empty?
      findings << build_finding(
        severity: "MEDIUM",
        issue: "Global security missing",
        message: "No top-level security requirement is defined. Each operation must individually declare security.",
        remediation: "Add a global security section to apply authentication requirements to all endpoints by default.",
      )
    end

    findings.concat analyze_security_schemes(security_schemes)
    findings.concat analyze_server_security(spec)

    summary = calculate_summary(findings)

    security_coverage = {
      operations_total: operations.length,
      unauthenticated_operations: unauthenticated_operations,
      authenticated_operations: operations.length - unauthenticated_operations,
      authenticated_percentage: operations.length.zero? ? 0 : (((operations.length - unauthenticated_operations).to_f / operations.length) * 100).round(2),
    }

    recommendations = generate_recommendations(findings, security_coverage, security_schemes)

    {
      spec_info: info,
      operations_analyzed: operations.length,
      security_schemes: security_schemes,
      security_coverage: security_coverage,
      findings: findings.sort_by { |f| -severity_rank(f[:severity]) },
      recommendations: recommendations,
      summary: summary,
    }
  end

  def deep_stringify(value)
    case value
    when Hash
      value.each_with_object({}) do |(key, val), memo|
        memo[key.to_s] = deep_stringify(val)
      end
    when Array
      value.map { |item| deep_stringify(item) }
    else
      value
    end
  end

  def extract_operations(spec)
    paths = spec["paths"]
    return [] unless paths.is_a?(Hash)

    operations = []
    paths.each do |path, path_item|
      next unless path_item.is_a?(Hash)

      path_item.each do |method, operation|
        next unless HTTP_METHODS.include?(method.to_s.downcase)
        next unless operation.is_a?(Hash)

        operations << {
          path: path,
          method: method.to_s.downcase,
          operation: operation,
          path_item: path_item,
        }
      end
    end

    operations
  end

  def extract_security_schemes(spec)
    schemes = []

    components = spec["components"]
    if components.is_a?(Hash) && components["securitySchemes"].is_a?(Hash)
      components["securitySchemes"].each do |name, scheme|
        schemes << normalize_scheme(name, scheme)
      end
    end

    security_definitions = spec["securityDefinitions"]
    if security_definitions.is_a?(Hash)
      security_definitions.each do |name, scheme|
        schemes << normalize_scheme(name, scheme)
      end
    end

    schemes
  end

  def normalize_scheme(name, raw_scheme)
    scheme = raw_scheme.is_a?(Hash) ? deep_stringify(raw_scheme) : {}
    {
      name: name,
      type: scheme["type"],
      scheme: scheme["scheme"],
      in: scheme["in"],
      bearer_format: scheme["bearerFormat"],
      flows: scheme["flows"],
      description: scheme["description"],
    }
  end

  def normalize_security(value)
    return nil if value.nil?
    return [] if value.respond_to?(:empty?) && value.empty?

    case value
    when Array
      value.map do |entry|
        entry.is_a?(Hash) ? entry.keys : entry
      end.flatten.compact
    when Hash
      value.keys
    else
      Array(value)
    end
  end

  def analyze_security_schemes(schemes)
    findings = []

    schemes.each do |scheme|
      case scheme[:type]
      when "http"
        if scheme[:scheme].to_s.casecmp("basic").zero?
          findings << build_finding(
            severity: "HIGH",
            issue: "HTTP Basic authentication detected",
            message: "Security scheme '#{scheme[:name]}' uses HTTP Basic authentication.",
            remediation: "Switch to token-based authentication (e.g., OAuth2 client credentials or JWT bearer) to avoid static credentials.",
            metadata: { scheme: scheme[:name] },
          )
        elsif scheme[:scheme].to_s.casecmp("bearer").zero? && scheme[:bearer_format].blank?
          findings << build_finding(
            severity: "LOW",
            issue: "Bearer scheme missing format",
            message: "Security scheme '#{scheme[:name]}' does not document bearer token format.",
            remediation: "Document the bearer token format (e.g., JWT) to help clients implement validation correctly.",
            metadata: { scheme: scheme[:name] },
          )
        end
      when "apiKey"
        if scheme[:in].to_s.casecmp("query").zero?
          findings << build_finding(
            severity: "HIGH",
            issue: "API key exposed in query string",
            message: "Security scheme '#{scheme[:name]}' transmits the API key via query parameters.",
            remediation: "Move API keys to an HTTP header (e.g., Authorization) to avoid logging leakage and caching issues.",
            metadata: { scheme: scheme[:name] },
          )
        elsif scheme[:in].to_s.casecmp("cookie").zero?
          findings << build_finding(
            severity: "MEDIUM",
            issue: "Cookie-based API key detected",
            message: "Security scheme '#{scheme[:name]}' stores the API key in cookies.",
            remediation: "Ensure cookies are HttpOnly, Secure, SameSite=strict, and avoid persistent API keys stored client-side.",
            metadata: { scheme: scheme[:name] },
          )
        end
      when "oauth2"
        unless oauth_scopes_sufficient?(scheme[:flows])
          findings << build_finding(
            severity: "MEDIUM",
            issue: "OAuth scopes not documented",
            message: "Security scheme '#{scheme[:name]}' does not document scopes or uses empty scope lists.",
            remediation: "Provide explicit scopes per flow to enable least privilege and granular access control.",
            metadata: { scheme: scheme[:name] },
          )
        end
      end
    end

    findings
  end

  def analyze_server_security(spec)
    findings = []

    servers = Array(spec["servers"]).select { |server| server.is_a?(Hash) }
    http_servers = servers.select do |server|
      url = server["url"].to_s
      url.start_with?("http://")
    end

    http_servers.each do |server|
      findings << build_finding(
        severity: "HIGH",
        issue: "Insecure server endpoint",
        message: "Server '#{server['url']}' uses HTTP instead of HTTPS.",
        remediation: "Serve APIs exclusively over HTTPS and update the specification to point to secure endpoints.",
        metadata: { server: server["url"] },
      )
    end

    schemes = Array(spec["schemes"])
    if schemes.include?("http")
      findings << build_finding(
        severity: "HIGH",
        issue: "HTTP scheme enabled",
        message: "The specification allows plain HTTP traffic via the schemes array.",
        remediation: "Remove 'http' from the schemes list to enforce TLS.",
      )
    end

    findings
  end

  def declares_auth_responses?(operation)
    responses = operation["responses"]
    return false unless responses.is_a?(Hash)

    responses.key?("401") || responses.key?("403")
  end

  def rate_limiting_missing?(operation)
    responses = operation["responses"]
    return false unless responses.is_a?(Hash)

    return false if responses.key?("429")

    # Check for vendor extensions advertising rate limits
    vendor_extensions = operation.select { |key, _| key.to_s.start_with?("x-") }
    !vendor_extensions.keys.any? { |key| key.downcase.include?("rate") }
  end

  def oauth_scopes_sufficient?(flows)
    return false unless flows.is_a?(Hash)

    flows.values.any? do |flow|
      flow.is_a?(Hash) && flow["scopes"].is_a?(Hash) && flow["scopes"].any?
    end
  end

  def build_finding(severity:, issue:, message:, remediation:, metadata: {})
    {
      severity: severity,
      issue: issue,
      message: message,
      remediation: remediation,
      metadata: metadata,
    }
  end

  def calculate_summary(findings)
    summary = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    }

    findings.each do |finding|
      case finding[:severity].to_s.upcase
      when "CRITICAL" then summary[:critical] += 1
      when "HIGH" then summary[:high] += 1
      when "MEDIUM" then summary[:medium] += 1
      when "LOW" then summary[:low] += 1
      end
    end

    summary
  end

  def severity_rank(severity)
    case severity.to_s.upcase
    when "CRITICAL" then 4
    when "HIGH" then 3
    when "MEDIUM" then 2
    when "LOW" then 1
    else 0
    end
  end

  def generate_recommendations(findings, coverage, schemes)
    recommendations = []

    if coverage[:unauthenticated_operations].positive?
      recommendations << "Add security requirements to #{coverage[:unauthenticated_operations]} unauthenticated operations."
    end

    if schemes.empty?
      recommendations << "Define at least one security scheme under components.securitySchemes or securityDefinitions."
    end

    findings.each do |finding|
      case finding[:issue]
      when "HTTP Basic authentication detected"
        recommendations << "Replace HTTP Basic authentication with short-lived bearer tokens."
      when "API key exposed in query string"
        recommendations << "Move API key exchange to headers such as Authorization: ApiKey <token>."
      when "Insecure server endpoint"
        recommendations << "Update server URLs to HTTPS and issue TLS certificates."
      when "HTTP scheme enabled"
        recommendations << "Restrict allowed transport schemes to HTTPS only."
      end
    end

    recommendations.uniq
  end
end

# ============================================================================
# TOOL REGISTRATION
# ============================================================================
ApiSchemaSecurityReviewerTool.register!
