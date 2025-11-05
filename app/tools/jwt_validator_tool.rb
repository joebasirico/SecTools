# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

# JWT Security Validator
# Validates and analyzes JSON Web Tokens for security vulnerabilities
class JwtValidatorTool
  include SecurityTool

  configure_tool(
    name: "JWT Security Validator",
    description: "Decode and validate JWTs, check for security vulnerabilities and best practices",
    category: "Authentication Security",
  )

  input_field :jwt_token, type: :text, label: "JWT Token",
                          placeholder: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                          required: true

  input_field :secret_key, type: :password, label: "Secret Key (Optional - for signature verification)",
                           placeholder: "your-secret-key",
                           required: false

  output_format :html, :json

  # Insecure algorithms that should not be used
  INSECURE_ALGORITHMS = ["none", "HS256", "RS256"].freeze unless defined?(INSECURE_ALGORITHMS)
  DEPRECATED_ALGORITHMS = ["HS384", "HS512"].freeze unless defined?(DEPRECATED_ALGORITHMS)
  RECOMMENDED_ALGORITHMS = ["RS256", "ES256", "PS256", "EdDSA"].freeze unless defined?(RECOMMENDED_ALGORITHMS)

  # Security vulnerabilities to check
  SECURITY_CHECKS = [
    :check_algorithm_none,
    :check_weak_algorithm,
    :check_expired_token,
    :check_missing_expiration,
    :check_long_expiration,
    :check_missing_claims,
    :check_audience_claim,
    :check_issuer_claim,
    :check_subject_claim,
    :check_token_age,
    :check_sensitive_data,
  ].freeze unless defined?(SECURITY_CHECKS)

  def execute(params)
    jwt_token = params[:jwt_token]&.strip
    secret_key = params[:secret_key]&.strip

    if jwt_token.blank?
      return {
               error: "No JWT token provided",
               header: {},
               payload: {},
               signature: {},
               vulnerabilities: [],
               recommendations: [],
               security_score: { score: 0, grade: "F" },
             }
    end

    begin
      # Parse JWT
      parts = jwt_token.split(".")

      unless parts.length == 3
        return {
                 error: "Invalid JWT format. Expected 3 parts (header.payload.signature), got #{parts.length}",
                 header: {},
                 payload: {},
                 signature: {},
                 vulnerabilities: [],
                 recommendations: ["Ensure JWT follows the format: header.payload.signature"],
                 security_score: { score: 0, grade: "F" },
               }
      end

      # Decode header and payload
      header = decode_base64_json(parts[0])
      payload = decode_base64_json(parts[1])
      signature_part = parts[2]

      # Verify signature if secret provided
      signature_info = if secret_key.present?
          verify_signature(jwt_token, secret_key, header)
        else
          { verified: false, message: "No secret key provided for verification" }
        end

      # Run security checks
      vulnerabilities = run_security_checks(header, payload)
      recommendations = generate_recommendations(header, payload, vulnerabilities, signature_info)
      security_score = calculate_security_score(header, payload, vulnerabilities, signature_info)

      # Format dates in payload
      formatted_payload = format_payload(payload)

      {
        jwt_token: jwt_token,
        analyzed_at: Time.now.utc,
        header: header,
        payload: formatted_payload,
        signature: signature_info,
        vulnerabilities: vulnerabilities,
        recommendations: recommendations,
        security_score: security_score,
        token_info: extract_token_info(header, payload),
      }
    rescue StandardError => e
      {
        error: "Failed to parse JWT: #{e.message}",
        header: {},
        payload: {},
        signature: {},
        vulnerabilities: [],
        recommendations: ["Ensure the JWT is properly formatted and Base64URL encoded"],
        security_score: { score: 0, grade: "F" },
      }
    end
  end

  private

  def decode_base64_json(base64_string)
    # Add padding if needed
    padded = base64_string + "=" * (4 - base64_string.length % 4)
    # Replace URL-safe characters
    padded = padded.tr("-_", "+/")

    decoded = Base64.decode64(padded)
    JSON.parse(decoded, symbolize_names: true)
  rescue StandardError => e
    { error: "Failed to decode: #{e.message}" }
  end

  def verify_signature(jwt_token, secret_key, header)
    algorithm = header[:alg]&.upcase
    parts = jwt_token.split(".")

    # Get signing input (header.payload)
    signing_input = parts[0..1].join(".")
    signature_bytes = Base64.urlsafe_decode64(parts[2] + "=" * (4 - parts[2].length % 4))

    case algorithm
    when "HS256", "HS384", "HS512"
      verify_hmac_signature(signing_input, signature_bytes, secret_key, algorithm)
    when "RS256", "RS384", "RS512"
      verify_rsa_signature(signing_input, signature_bytes, secret_key, algorithm)
    when "ES256", "ES384", "ES512"
      verify_ecdsa_signature(signing_input, signature_bytes, secret_key, algorithm)
    when "NONE"
      { verified: false, message: "Algorithm 'none' is insecure - no signature verification performed" }
    else
      { verified: false, message: "Unsupported algorithm: #{algorithm}" }
    end
  rescue StandardError => e
    { verified: false, message: "Signature verification failed: #{e.message}" }
  end

  def verify_hmac_signature(signing_input, signature_bytes, secret_key, algorithm)
    digest = case algorithm
      when "HS256" then OpenSSL::Digest::SHA256.new
      when "HS384" then OpenSSL::Digest::SHA384.new
      when "HS512" then OpenSSL::Digest::SHA512.new
      end

    expected_signature = OpenSSL::HMAC.digest(digest, secret_key, signing_input)

    if secure_compare(expected_signature, signature_bytes)
      { verified: true, message: "Signature verified successfully using #{algorithm}", algorithm: algorithm }
    else
      { verified: false, message: "Signature verification failed - invalid signature or wrong secret key", algorithm: algorithm }
    end
  end

  def verify_rsa_signature(signing_input, signature_bytes, public_key_pem, algorithm)
    digest = case algorithm
      when "RS256" then OpenSSL::Digest::SHA256.new
      when "RS384" then OpenSSL::Digest::SHA384.new
      when "RS512" then OpenSSL::Digest::SHA512.new
      end

    public_key = OpenSSL::PKey::RSA.new(public_key_pem)

    if public_key.verify(digest, signature_bytes, signing_input)
      { verified: true, message: "Signature verified successfully using #{algorithm}", algorithm: algorithm }
    else
      { verified: false, message: "RSA signature verification failed", algorithm: algorithm }
    end
  rescue StandardError => e
    { verified: false, message: "RSA verification error: #{e.message}", algorithm: algorithm }
  end

  def verify_ecdsa_signature(signing_input, signature_bytes, public_key_pem, algorithm)
    digest = case algorithm
      when "ES256" then OpenSSL::Digest::SHA256.new
      when "ES384" then OpenSSL::Digest::SHA384.new
      when "ES512" then OpenSSL::Digest::SHA512.new
      end

    public_key = OpenSSL::PKey::EC.new(public_key_pem)

    if public_key.verify(digest, signature_bytes, signing_input)
      { verified: true, message: "Signature verified successfully using #{algorithm}", algorithm: algorithm }
    else
      { verified: false, message: "ECDSA signature verification failed", algorithm: algorithm }
    end
  rescue StandardError => e
    { verified: false, message: "ECDSA verification error: #{e.message}", algorithm: algorithm }
  end

  def secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    result = 0
    a.bytes.zip(b.bytes) { |x, y| result |= x ^ y }
    result.zero?
  end

  def run_security_checks(header, payload)
    vulnerabilities = []

    SECURITY_CHECKS.each do |check_method|
      result = send(check_method, header, payload)
      vulnerabilities << result if result
    end

    vulnerabilities
  end

  def check_algorithm_none(header, _payload)
    algorithm = header[:alg]&.downcase

    if algorithm == "none"
      {
        name: "Algorithm 'none' Detected",
        severity: "CRITICAL",
        description: "JWT uses 'none' algorithm which provides no cryptographic security",
        impact: "Anyone can forge tokens - complete authentication bypass possible",
        cwe: "CWE-327",
      }
    end
  end

  def check_weak_algorithm(header, _payload)
    algorithm = header[:alg]&.upcase

    if algorithm == "HS256"
      {
        name: "Weak HMAC Algorithm",
        severity: "HIGH",
        description: "JWT uses HS256 which is symmetric and less secure than asymmetric algorithms",
        impact: "Secret key must be shared with all parties; key compromise affects all tokens",
        cwe: "CWE-326",
      }
    elsif DEPRECATED_ALGORITHMS.include?(algorithm)
      {
        name: "Deprecated Algorithm",
        severity: "MEDIUM",
        description: "JWT uses #{algorithm} which is considered deprecated",
        impact: "May not be supported in future implementations",
        cwe: "CWE-327",
      }
    end
  end

  def check_expired_token(header, payload)
    exp = payload[:exp]
    return nil unless exp

    exp_time = Time.at(exp)

    if exp_time < Time.now
      {
        name: "Expired Token",
        severity: "HIGH",
        description: "Token expired at #{exp_time.utc}",
        impact: "Token should not be accepted - expired #{time_ago(exp_time)} ago",
        cwe: "CWE-613",
      }
    end
  end

  def check_missing_expiration(header, payload)
    unless payload[:exp]
      {
        name: "Missing Expiration Claim",
        severity: "HIGH",
        description: "JWT does not have an expiration time (exp claim)",
        impact: "Token never expires - can be used indefinitely if compromised",
        cwe: "CWE-613",
      }
    end
  end

  def check_long_expiration(header, payload)
    exp = payload[:exp]
    iat = payload[:iat] || Time.now.to_i

    return nil unless exp

    lifetime_seconds = exp - iat
    lifetime_hours = lifetime_seconds / 3600.0

    if lifetime_hours > 24
      {
        name: "Excessive Token Lifetime",
        severity: "MEDIUM",
        description: "Token lifetime is #{lifetime_hours.round(1)} hours (> 24 hours)",
        impact: "Long-lived tokens increase risk window if compromised",
        cwe: "CWE-613",
      }
    end
  end

  def check_missing_claims(header, payload)
    required_claims = [:sub, :iat]
    missing = required_claims.reject { |claim| payload.key?(claim) }

    if missing.any?
      {
        name: "Missing Standard Claims",
        severity: "MEDIUM",
        description: "JWT missing recommended claims: #{missing.join(", ")}",
        impact: "Reduced token security and traceability",
        cwe: "CWE-1390",
      }
    end
  end

  def check_audience_claim(header, payload)
    unless payload[:aud]
      {
        name: "Missing Audience Claim",
        severity: "LOW",
        description: "JWT does not specify an audience (aud claim)",
        impact: "Token can be used with any service - increases attack surface",
        cwe: "CWE-1390",
      }
    end
  end

  def check_issuer_claim(header, payload)
    unless payload[:iss]
      {
        name: "Missing Issuer Claim",
        severity: "LOW",
        description: "JWT does not specify an issuer (iss claim)",
        impact: "Cannot verify token origin - reduces accountability",
        cwe: "CWE-1390",
      }
    end
  end

  def check_subject_claim(header, payload)
    unless payload[:sub]
      {
        name: "Missing Subject Claim",
        severity: "LOW",
        description: "JWT does not specify a subject (sub claim)",
        impact: "Cannot identify the principal - reduces token usability",
        cwe: "CWE-1390",
      }
    end
  end

  def check_token_age(header, payload)
    iat = payload[:iat]
    return nil unless iat

    issued_time = Time.at(iat)
    age_seconds = Time.now - issued_time
    age_hours = age_seconds / 3600.0

    if age_hours > 24 && !payload[:exp]
      {
        name: "Old Token Without Expiration",
        severity: "MEDIUM",
        description: "Token was issued #{time_ago(issued_time)} ago and has no expiration",
        impact: "Old tokens without expiration pose security risks",
        cwe: "CWE-613",
      }
    end
  end

  def check_sensitive_data(header, payload)
    sensitive_keys = [:password, :secret, :api_key, :token, :ssn, :credit_card]
    found_keys = payload.keys.select { |k| sensitive_keys.any? { |sk| k.to_s.downcase.include?(sk.to_s) } }

    if found_keys.any?
      {
        name: "Potential Sensitive Data in Payload",
        severity: "HIGH",
        description: "JWT payload contains potentially sensitive fields: #{found_keys.join(", ")}",
        impact: "JWT payloads are only Base64 encoded - anyone can read sensitive data",
        cwe: "CWE-312",
      }
    end
  end

  def generate_recommendations(header, payload, vulnerabilities, signature_info)
    recommendations = []

    # Algorithm recommendations
    algorithm = header[:alg]&.upcase
    if algorithm == "NONE" || algorithm == "HS256"
      recommendations << "Use asymmetric algorithms like RS256, ES256, or PS256 instead of #{algorithm}"
    end

    # Expiration recommendations
    unless payload[:exp]
      recommendations << "Add an expiration time (exp claim) to limit token lifetime"
    end

    # Claims recommendations
    unless payload[:iss]
      recommendations << "Add issuer claim (iss) to identify token origin"
    end

    unless payload[:aud]
      recommendations << "Add audience claim (aud) to restrict token usage"
    end

    unless payload[:sub]
      recommendations << "Add subject claim (sub) to identify the principal"
    end

    # Signature recommendations
    unless signature_info[:verified]
      recommendations << "Verify token signature to ensure authenticity"
    end

    # General recommendations
    if vulnerabilities.any? { |v| v[:severity] == "CRITICAL" }
      recommendations << "URGENT: Address critical vulnerabilities immediately"
    end

    recommendations << "Implement token rotation and refresh token patterns" if recommendations.length < 3
    recommendations << "Store tokens securely (HttpOnly cookies or secure storage)" if recommendations.length < 3
    recommendations << "Implement proper token revocation mechanisms" if recommendations.length < 3

    recommendations
  end

  def calculate_security_score(header, payload, vulnerabilities, signature_info)
    score = 100

    # Deduct points for vulnerabilities
    vulnerabilities.each do |vuln|
      case vuln[:severity]
      when "CRITICAL"
        score -= 30
      when "HIGH"
        score -= 20
      when "MEDIUM"
        score -= 10
      when "LOW"
        score -= 5
      end
    end

    # Bonus points for good practices
    score += 5 if payload[:exp] && !check_expired_token(header, payload)
    score += 5 if payload[:iss]
    score += 5 if payload[:aud]
    score += 5 if signature_info[:verified]

    algorithm = header[:alg]&.upcase
    score += 10 if RECOMMENDED_ALGORITHMS.include?(algorithm)

    score = [[score, 0].max, 100].min

    {
      score: score,
      grade: score_to_grade(score),
      rating: score_to_rating(score),
      max_score: 100,
    }
  end

  def score_to_grade(score)
    case score
    when 90..100 then "A"
    when 80...90 then "B"
    when 70...80 then "C"
    when 60...70 then "D"
    else "F"
    end
  end

  def score_to_rating(score)
    case score
    when 90..100 then "Excellent"
    when 80...90 then "Good"
    when 70...80 then "Fair"
    when 60...70 then "Poor"
    when 40...60 then "Weak"
    else "Insecure"
    end
  end

  def format_payload(payload)
    formatted = payload.dup

    # Format timestamps
    [:exp, :iat, :nbf].each do |time_field|
      if formatted[time_field]
        time = Time.at(formatted[time_field])
        formatted["#{time_field}_formatted".to_sym] = time.utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        formatted["#{time_field}_relative".to_sym] = time_ago(time)
      end
    end

    formatted
  end

  def extract_token_info(header, payload)
    info = {
      algorithm: header[:alg],
      type: header[:typ] || "JWT",
      key_id: header[:kid],
    }

    if payload[:exp]
      exp_time = Time.at(payload[:exp])
      info[:expires_at] = exp_time.utc.strftime("%Y-%m-%d %H:%M:%S UTC")
      info[:is_expired] = exp_time < Time.now
      info[:time_until_expiry] = time_until(exp_time) if exp_time > Time.now
    end

    if payload[:iat]
      iat_time = Time.at(payload[:iat])
      info[:issued_at] = iat_time.utc.strftime("%Y-%m-%d %H:%M:%S UTC")
      info[:token_age] = time_ago(iat_time)
    end

    info[:issuer] = payload[:iss] if payload[:iss]
    info[:subject] = payload[:sub] if payload[:sub]
    info[:audience] = payload[:aud] if payload[:aud]

    info
  end

  def time_ago(time)
    seconds = Time.now - time
    return "just now" if seconds < 60

    minutes = seconds / 60
    return "#{minutes.to_i} minute(s) ago" if minutes < 60

    hours = minutes / 60
    return "#{hours.to_i} hour(s) ago" if hours < 24

    days = hours / 24
    "#{days.to_i} day(s) ago"
  end

  def time_until(time)
    seconds = time - Time.now
    return "now" if seconds < 60

    minutes = seconds / 60
    return "in #{minutes.to_i} minute(s)" if minutes < 60

    hours = minutes / 60
    return "in #{hours.to_i} hour(s)" if hours < 24

    days = hours / 24
    "in #{days.to_i} day(s)"
  end
end

JwtValidatorTool.register!
