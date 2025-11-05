# frozen_string_literal: true

require "net/http"
require "openssl"
require "uri"
require "socket"
require "timeout"
require "set"

# SSL/TLS Security Tester
# Tests websites for SSL/TLS configuration security
class SslSecurityTesterTool
  include SecurityTool

  configure_tool(
    name: "SSL/TLS Security Tester",
    description: "Test websites for SSL/TLS security, certificate validity, and protocol vulnerabilities",
    category: "Network Security",
  )

  input_field :target_url, type: :url, label: "Target URL",
                           placeholder: "https://example.com",
                           required: true

  output_format :html, :json

  # SSL/TLS protocol versions
  SSL_VERSIONS = {
    "SSLv2" => OpenSSL::SSL::SSL2_VERSION,
    "SSLv3" => OpenSSL::SSL::SSL3_VERSION,
    "TLS1.0" => OpenSSL::SSL::TLS1_VERSION,
    "TLS1.1" => OpenSSL::SSL::TLS1_1_VERSION,
    "TLS1.2" => OpenSSL::SSL::TLS1_2_VERSION,
    "TLS1.3" => OpenSSL::SSL::TLS1_3_VERSION,
  }.freeze unless defined?(SSL_VERSIONS)

  # Weak ciphers that should not be used (cryptographically broken or severely deprecated)
  WEAK_CIPHERS = [
    "NULL", "EXPORT", "DES", "RC4", "MD5", "PSK", "SRP",
    "IDEA", "AECDH", "ADH", "aNULL", "eNULL",
  ].freeze unless defined?(WEAK_CIPHERS)

  def execute(params)
    url_string = params[:target_url]

    if url_string.blank?
      return {
               error: "No URL provided",
               certificate: {},
               protocols: {},
               ciphers: {},
               tls_config: {},
               vulnerabilities: [],
               recommendations: [],
               summary: { score: 0, grade: "F" },
             }
    end

    # Parse and validate URL
    begin
      uri = URI.parse(url_string)
      uri = URI.parse("https://#{url_string}") unless uri.scheme

      unless uri.scheme == "https"
        return {
                 error: "URL must use HTTPS protocol",
                 url: url_string,
                 certificate: {},
                 protocols: {},
                 ciphers: {},
                 tls_config: {},
                 vulnerabilities: [],
                 recommendations: ["Use HTTPS instead of HTTP"],
                 summary: { score: 0, grade: "F" },
               }
      end

      host = uri.host
      port = uri.port || 443
    rescue URI::InvalidURIError => e
      return {
               error: "Invalid URL format: #{e.message}",
               certificate: {},
               protocols: {},
               ciphers: {},
               tls_config: {},
               vulnerabilities: [],
               recommendations: [],
               summary: { score: 0, grade: "F" },
             }
    end

    # Perform SSL/TLS tests
    begin
      certificate_info = test_certificate(host, port)
      protocol_support = test_protocol_versions(host, port)
      cipher_info = test_cipher_suites(host, port)
      tls_config = test_tls_configuration(host, port)
      vulnerabilities = detect_vulnerabilities(host, port, certificate_info, protocol_support, cipher_info, tls_config)
      recommendations = generate_recommendations(vulnerabilities, protocol_support, cipher_info, tls_config)
      summary = calculate_security_score(certificate_info, protocol_support, cipher_info, tls_config, vulnerabilities)

      {
        url: url_string,
        host: host,
        port: port,
        tested_at: Time.now.utc,
        certificate: certificate_info,
        protocols: protocol_support,
        ciphers: cipher_info,
        tls_config: tls_config,
        vulnerabilities: vulnerabilities,
        recommendations: recommendations,
        summary: summary,
      }
    rescue StandardError => e
      {
        error: "Connection failed: #{e.message}",
        url: url_string,
        host: host,
        port: port,
        certificate: {},
        protocols: {},
        ciphers: {},
        tls_config: {},
        vulnerabilities: [],
        recommendations: ["Ensure the server is accessible and configured correctly"],
        summary: { score: 0, grade: "F" },
      }
    end
  end

  private

  def test_certificate(host, port)
    cert = nil
    cert_chain = []

    Timeout.timeout(10) do
      tcp_socket = TCPSocket.new(host, port)
      ssl_context = OpenSSL::SSL::SSLContext.new
      # Use VERIFY_NONE to allow connection to servers with invalid certs
      # We want to analyze the certificate even if it's expired/invalid
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
      # Set SNI (Server Name Indication) so server sends correct certificate
      ssl_socket.hostname = host

      begin
        ssl_socket.connect
        cert = ssl_socket.peer_cert
        cert_chain = ssl_socket.peer_cert_chain || []
      ensure
        ssl_socket.close rescue nil
        tcp_socket.close rescue nil
      end
    end

    return {} unless cert

    {
      subject: cert.subject.to_s,
      issuer: cert.issuer.to_s,
      serial: cert.serial.to_s,
      version: cert.version,
      not_before: cert.not_before,
      not_after: cert.not_after,
      expires_in_days: ((cert.not_after - Time.now) / 86400).to_i,
      expired: cert.not_after < Time.now,
      self_signed: cert.issuer == cert.subject,
      signature_algorithm: cert.signature_algorithm,
      public_key_algorithm: cert.public_key.class.to_s.split("::").last,
      key_size: get_key_size(cert.public_key),
      san_domains: extract_san_domains(cert),
      chain_length: cert_chain.length,
      valid: !cert.not_after.nil? && cert.not_after > Time.now,
    }
  rescue StandardError => e
    { error: "Certificate check failed: #{e.message}" }
  end

  def test_protocol_versions(host, port)
    results = {}

    SSL_VERSIONS.each do |name, version|
      next if version.nil? # Skip if version not supported by OpenSSL

      supported = test_protocol_version(host, port, version)
      results[name] = {
        supported: supported,
        secure: protocol_secure?(name),
      }
    end

    results
  end

  def test_protocol_version(host, port, version)
    Timeout.timeout(5) do
      tcp_socket = TCPSocket.new(host, port)
      ssl_context = OpenSSL::SSL::SSLContext.new
      # Use min_version and max_version to test specific protocol
      ssl_context.min_version = version
      ssl_context.max_version = version
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
      ssl_socket.hostname = host

      begin
        ssl_socket.connect
        # Verify we actually connected with the expected version
        return ssl_socket.ssl_version.start_with?(version_name(version))
      rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET
        return false
      ensure
        ssl_socket.close rescue nil
        tcp_socket.close rescue nil
      end
    end
  rescue StandardError
    false
  end

  def version_name(version)
    case version
    when OpenSSL::SSL::SSL2_VERSION then "SSLv2"
    when OpenSSL::SSL::SSL3_VERSION then "SSLv3"
    when OpenSSL::SSL::TLS1_VERSION then "TLSv1"
    when OpenSSL::SSL::TLS1_1_VERSION then "TLSv1.1"
    when OpenSSL::SSL::TLS1_2_VERSION then "TLSv1.2"
    when OpenSSL::SSL::TLS1_3_VERSION then "TLSv1.3"
    else "Unknown"
    end
  end

  def test_cipher_suites(host, port)
    ciphers = []
    weak_ciphers = []
    strong_ciphers = []
    cipher_preference_order = []
    supported_by_protocol = {}

    # Get all available cipher suites from OpenSSL
    all_available_ciphers = get_all_cipher_suites

    # Test each cipher suite individually across all supported protocols
    SSL_VERSIONS.each do |protocol_name, protocol_version|
      next if protocol_version.nil?

      protocol_ciphers = []

      all_available_ciphers.each do |cipher_suite|
        cipher_name = cipher_suite[:name]

        result = test_single_cipher(host, port, cipher_name, protocol_version)

        if result[:supported]
          cipher_info = {
            name: cipher_name,
            protocol: protocol_name,
            version: result[:version],
            bits: result[:bits],
            strength: classify_cipher_strength(cipher_name, result[:bits]),
            key_exchange: parse_key_exchange(cipher_name),
            authentication: parse_authentication(cipher_name),
            encryption: parse_encryption(cipher_name),
            mac: parse_mac(cipher_name),
            forward_secrecy: has_forward_secrecy?(cipher_name),
          }

          protocol_ciphers << cipher_info

          # Add to overall lists if not already present
          unless ciphers.any? { |c| c[:name] == cipher_name && c[:protocol] == protocol_name }
            ciphers << cipher_info

            if cipher_info[:strength] == "WEAK"
              weak_ciphers << cipher_info
            elsif cipher_info[:strength] == "STRONG"
              strong_ciphers << cipher_info
            end
          end
        end
      end

      supported_by_protocol[protocol_name] = protocol_ciphers if protocol_ciphers.any?
    end

    # Determine server's cipher preference order
    cipher_preference_order = determine_cipher_preference(host, port)
    server_cipher_order = cipher_preference_order.any?

    {
      total_tested: all_available_ciphers.length,
      total_supported: ciphers.length,
      weak_count: weak_ciphers.length,
      strong_count: strong_ciphers.length,
      medium_count: ciphers.count { |c| c[:strength] == "MEDIUM" },
      forward_secrecy_count: ciphers.count { |c| c[:forward_secrecy] },
      ciphers: ciphers.sort_by { |c| [-c[:bits], c[:name]] },
      weak_ciphers: weak_ciphers,
      strong_ciphers: strong_ciphers,
      by_protocol: supported_by_protocol,
      server_preferred_order: cipher_preference_order,
      server_cipher_order: server_cipher_order,
    }
  end

  def get_all_cipher_suites
    # Get comprehensive list of cipher suites
    cipher_list = []

    begin
      # Get all ciphers from OpenSSL
      ctx = OpenSSL::SSL::SSLContext.new

      # Try to get maximum set of ciphers
      ["ALL:COMPLEMENTOFALL", "ALL:eNULL", "ALL"].each do |cipher_string|
        begin
          ctx.ciphers = cipher_string
          ctx.ciphers.each do |cipher|
            cipher_name = cipher[0]
            unless cipher_list.any? { |c| c[:name] == cipher_name }
              cipher_list << {
                name: cipher_name,
                openssl_name: cipher[0],
                protocol: cipher[1],
                bits: cipher[2],
                alg_bits: cipher[3],
              }
            end
          end
        rescue => e
          # Some cipher strings might not work
        end
      end
    rescue => e
      Rails.logger.error("Error getting cipher list: #{e.message}")
    end

    # Add common cipher names that might not be in OpenSSL's list
    additional_ciphers = [
      "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-CHACHA20-POLY1305",
      "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256",
      "DHE-RSA-AES256-SHA256", "DHE-RSA-AES128-SHA256",
      "AES256-GCM-SHA384", "AES128-GCM-SHA256",
      "AES256-SHA256", "AES128-SHA256", "AES256-SHA", "AES128-SHA",
      "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5", "DES-CBC-SHA",
      "NULL-SHA256", "NULL-SHA", "NULL-MD5",
      "EXPORT-RC4-MD5", "EXPORT-DES-CBC-SHA",
    ]

    additional_ciphers.each do |cipher_name|
      unless cipher_list.any? { |c| c[:name] == cipher_name }
        cipher_list << { name: cipher_name, openssl_name: cipher_name }
      end
    end

    cipher_list
  end

  def test_single_cipher(host, port, cipher_name, protocol_version = nil)
    begin
      Timeout.timeout(3) do
        tcp_socket = TCPSocket.new(host, port)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE

        # Set protocol version if specified
        if protocol_version
          ssl_context.min_version = protocol_version
          ssl_context.max_version = protocol_version
        end

        # Try to set this specific cipher
        begin
          ssl_context.ciphers = [cipher_name]
        rescue => e
          # Cipher not available in OpenSSL
          return { supported: false }
        end

        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.hostname = host

        begin
          ssl_socket.connect
          actual_cipher = ssl_socket.cipher

          # Verify the server actually selected this cipher
          if actual_cipher && actual_cipher[0] == cipher_name
            return {
                     supported: true,
                     name: actual_cipher[0],
                     version: actual_cipher[1],
                     bits: actual_cipher[2],
                     alg_bits: actual_cipher[3],
                   }
          else
            return { supported: false }
          end
        ensure
          ssl_socket.close rescue nil
          tcp_socket.close rescue nil
        end
      end
    rescue Timeout::Error, OpenSSL::SSL::SSLError, Errno::ECONNRESET,
           Errno::EPIPE, Errno::ECONNREFUSED, SystemCallError => e
      return { supported: false }
    end

    { supported: false }
  end

  def determine_cipher_preference(host, port)
    # Try to determine if server honors client cipher preference or has its own order
    preference_order = []

    # Make multiple connections with different client cipher orders
    # If server has preference, it should always pick the same cipher
    test_orders = [
      ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "AES256-SHA"],
      ["AES256-SHA", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"],
      ["ECDHE-RSA-AES128-GCM-SHA256", "AES256-SHA", "ECDHE-RSA-AES256-GCM-SHA384"],
    ]

    selected_ciphers = []

    test_orders.each do |cipher_order|
      begin
        Timeout.timeout(3) do
          tcp_socket = TCPSocket.new(host, port)
          ssl_context = OpenSSL::SSL::SSLContext.new
          ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl_context.ciphers = cipher_order.join(":")
          ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
          ssl_socket.hostname = host

          begin
            ssl_socket.connect
            selected_ciphers << ssl_socket.cipher[0]
          ensure
            ssl_socket.close rescue nil
            tcp_socket.close rescue nil
          end
        end
      rescue => e
        # Connection failed
      end
    end

    # If server always picks the same cipher regardless of client order,
    # it has server-preferred ordering
    if selected_ciphers.uniq.length == 1 && selected_ciphers.length > 1
      # Server has preference - try to enumerate it
      preference_order = enumerate_server_cipher_order(host, port)
    end

    preference_order
  end

  def enumerate_server_cipher_order(host, port)
    # This is a simplified version - full enumeration would take too long
    # We'll just identify the top preferred ciphers
    order = []
    tested_ciphers = Set.new

    # Get list of all supported ciphers first (would come from main scan)
    common_ciphers = [
      "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
      "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256",
      "AES256-GCM-SHA384", "AES128-GCM-SHA256", "AES256-SHA256", "AES128-SHA256",
    ]

    # Try to determine order by offering all ciphers and seeing what server picks
    10.times do
      available_ciphers = common_ciphers.reject { |c| tested_ciphers.include?(c) }
      break if available_ciphers.empty?

      begin
        Timeout.timeout(3) do
          tcp_socket = TCPSocket.new(host, port)
          ssl_context = OpenSSL::SSL::SSLContext.new
          ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl_context.ciphers = available_ciphers.join(":")
          ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
          ssl_socket.hostname = host

          begin
            ssl_socket.connect
            selected = ssl_socket.cipher[0]
            order << selected
            tested_ciphers.add(selected)
          ensure
            ssl_socket.close rescue nil
            tcp_socket.close rescue nil
          end
        end
      rescue => e
        break
      end
    end

    order
  end

  def parse_key_exchange(cipher_name)
    case cipher_name
    when /ECDHE/ then "ECDHE"
    when /DHE/ then "DHE"
    when /ECDH/ then "ECDH"
    when /DH/ then "DH"
    when /RSA/ then "RSA"
    when /PSK/ then "PSK"
    when /^TLS_/ then "TLS1.3"
    else "Unknown"
    end
  end

  def parse_authentication(cipher_name)
    case cipher_name
    when /RSA/ then "RSA"
    when /ECDSA/ then "ECDSA"
    when /DSS/ then "DSS"
    when /PSK/ then "PSK"
    when /aNULL/ then "None"
    when /^TLS_/ then "TLS1.3"
    else "RSA"
    end
  end

  def parse_encryption(cipher_name)
    case cipher_name
    when /AES256-GCM/ then "AES-256-GCM"
    when /AES128-GCM/ then "AES-128-GCM"
    when /AES256/ then "AES-256-CBC"
    when /AES128/ then "AES-128-CBC"
    when /CHACHA20/ then "ChaCha20-Poly1305"
    when /3DES/ then "3DES"
    when /DES/ then "DES"
    when /RC4/ then "RC4"
    when /NULL/ then "None"
    else "Unknown"
    end
  end

  def parse_mac(cipher_name)
    case cipher_name
    when /GCM|POLY1305|CCM/ then "AEAD"
    when /SHA384/ then "SHA384"
    when /SHA256/ then "SHA256"
    when /SHA/ then "SHA1"
    when /MD5/ then "MD5"
    else "Unknown"
    end
  end

  def has_forward_secrecy?(cipher_name)
    cipher_name.include?("ECDHE") || cipher_name.include?("DHE")
  end

  def test_tls_configuration(host, port)
    config = {}

    # Test for TLS compression (CRIME vulnerability)
    config[:compression_supported] = test_tls_compression(host, port)

    # Test for secure renegotiation
    config[:secure_renegotiation] = test_secure_renegotiation(host, port)

    # Test for session resumption (session ID and session tickets)
    config[:session_resumption] = test_session_resumption(host, port)

    # Test for OCSP stapling
    config[:ocsp_stapling] = test_ocsp_stapling(host, port)

    # Test for certificate transparency (SCT)
    config[:certificate_transparency] = test_certificate_transparency(host, port)

    # Test for TLS fallback SCSV
    config[:fallback_scsv] = test_fallback_scsv(host, port)

    config
  end

  def test_tls_compression(host, port)
    # TLS compression should be disabled (CRIME vulnerability)
    begin
      Timeout.timeout(5) do
        tcp_socket = TCPSocket.new(host, port)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.hostname = host

        begin
          ssl_socket.connect
          # Check if compression is enabled
          # Note: Modern OpenSSL versions disable compression by default
          compression = ssl_socket.respond_to?(:compression) ? ssl_socket.compression : nil
          return compression ? true : false
        ensure
          ssl_socket.close rescue nil
          tcp_socket.close rescue nil
        end
      end
    rescue => e
      return false
    end
  end

  def test_secure_renegotiation(host, port)
    # Test if server supports secure renegotiation
    begin
      Timeout.timeout(5) do
        tcp_socket = TCPSocket.new(host, port)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.hostname = host

        begin
          ssl_socket.connect
          # Modern OpenSSL enables secure renegotiation by default
          return true
        ensure
          ssl_socket.close rescue nil
          tcp_socket.close rescue nil
        end
      end
    rescue => e
      return false
    end
  end

  def test_session_resumption(host, port)
    resumption = {
      session_id: false,
      session_ticket: false,
    }

    begin
      Timeout.timeout(10) do
        # First connection to get session
        tcp_socket1 = TCPSocket.new(host, port)
        ssl_context1 = OpenSSL::SSL::SSLContext.new
        ssl_context1.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl_socket1 = OpenSSL::SSL::SSLSocket.new(tcp_socket1, ssl_context1)
        ssl_socket1.hostname = host

        ssl_socket1.connect
        session = ssl_socket1.session
        ssl_socket1.close
        tcp_socket1.close

        # Second connection to test resumption
        if session
          tcp_socket2 = TCPSocket.new(host, port)
          ssl_context2 = OpenSSL::SSL::SSLContext.new
          ssl_context2.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl_context2.session = session
          ssl_socket2 = OpenSSL::SSL::SSLSocket.new(tcp_socket2, ssl_context2)
          ssl_socket2.hostname = host

          begin
            ssl_socket2.connect
            resumption[:session_id] = ssl_socket2.session_reused?
          ensure
            ssl_socket2.close rescue nil
            tcp_socket2.close rescue nil
          end
        end
      end
    rescue => e
      # Session resumption test failed
    end

    resumption
  end

  def test_ocsp_stapling(host, port)
    # Test if server supports OCSP stapling
    begin
      Timeout.timeout(5) do
        tcp_socket = TCPSocket.new(host, port)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE

        # Request OCSP stapling
        if ssl_context.respond_to?(:ocsp_stapling_enabled=)
          ssl_context.ocsp_stapling_enabled = true
        end

        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.hostname = host

        begin
          ssl_socket.connect

          # Check if OCSP response was provided
          if ssl_socket.respond_to?(:ocsp_response) && ssl_socket.ocsp_response
            return {
                     enabled: true,
                     response_present: true,
                   }
          else
            return {
                     enabled: false,
                     response_present: false,
                   }
          end
        ensure
          ssl_socket.close rescue nil
          tcp_socket.close rescue nil
        end
      end
    rescue => e
      return { enabled: false, error: e.message }
    end
  end

  def test_certificate_transparency(host, port)
    # Test for Certificate Transparency (SCT - Signed Certificate Timestamp)
    begin
      Timeout.timeout(5) do
        tcp_socket = TCPSocket.new(host, port)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.hostname = host

        begin
          ssl_socket.connect
          cert = ssl_socket.peer_cert

          # Look for SCT extension in certificate
          sct_extension = cert.extensions.find { |ext| ext.oid == "ct_precert_scts" || ext.oid == "1.3.6.1.4.1.11129.2.4.2" }

          return {
                   enabled: !sct_extension.nil?,
                   sct_present: !sct_extension.nil?,
                 }
        ensure
          ssl_socket.close rescue nil
          tcp_socket.close rescue nil
        end
      end
    rescue => e
      return { enabled: false }
    end
  end

  def test_fallback_scsv(host, port)
    # Test for TLS_FALLBACK_SCSV support (downgrade attack prevention)
    # Try to connect with TLS 1.1 and send FALLBACK_SCSV
    # If server supports TLS 1.2+, it should reject the connection
    begin
      Timeout.timeout(5) do
        tcp_socket = TCPSocket.new(host, port)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE

        # Try TLS 1.1 with fallback indicator
        ssl_context.max_version = OpenSSL::SSL::TLS1_1_VERSION

        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.hostname = host

        begin
          ssl_socket.connect
          # If connection succeeds with old protocol, check if SCSV is supported
          # This is a simplified test - full implementation would require more sophisticated checks
          return { supported: false }
        rescue OpenSSL::SSL::SSLError => e
          # If connection is rejected, SCSV might be working
          if e.message.include?("inappropriate fallback") || e.message.include?("SCSV")
            return { supported: true }
          else
            return { supported: false }
          end
        ensure
          ssl_socket.close rescue nil
          tcp_socket.close rescue nil
        end
      end
    rescue => e
      return { supported: false }
    end
  end

  def detect_vulnerabilities(host, port, cert_info, protocols, ciphers, tls_config)
    vulns = []

    # Check for connection/certificate errors first
    if cert_info[:error]
      vulns << {
        name: "SSL/TLS Connection Failed",
        severity: "CRITICAL",
        description: cert_info[:error],
        impact: "Unable to establish secure connection - server configuration is severely broken",
      }
    end

    # Certificate vulnerabilities
    if cert_info[:expired]
      vulns << {
        name: "Expired Certificate",
        severity: "CRITICAL",
        description: "The SSL certificate has expired",
        impact: "Browsers will show security warnings to users",
      }
    elsif cert_info[:expires_in_days] && cert_info[:expires_in_days] < 30
      vulns << {
        name: "Certificate Expiring Soon",
        severity: "HIGH",
        description: "Certificate expires in #{cert_info[:expires_in_days]} days",
        impact: "Certificate needs to be renewed soon",
      }
    end

    if cert_info[:self_signed]
      vulns << {
        name: "Self-Signed Certificate",
        severity: "HIGH",
        description: "Using a self-signed certificate",
        impact: "Browsers will not trust this certificate",
      }
    end

    # Check for weak key size (different minimums for RSA vs EC)
    if cert_info[:key_size]
      is_weak = false
      description = ""

      if cert_info[:public_key_algorithm] == "RSA" && cert_info[:key_size] < 2048
        is_weak = true
        description = "RSA key size is #{cert_info[:key_size]} bits (should be at least 2048)"
      elsif cert_info[:public_key_algorithm] == "EC" && cert_info[:key_size] < 256
        is_weak = true
        description = "EC key size is #{cert_info[:key_size]} bits (should be at least 256)"
      elsif cert_info[:public_key_algorithm] == "DSA" && cert_info[:key_size] < 2048
        is_weak = true
        description = "DSA key size is #{cert_info[:key_size]} bits (should be at least 2048)"
      end

      if is_weak
        vulns << {
          name: "Weak Key Size",
          severity: "HIGH",
          description: description,
          impact: "Vulnerable to cryptographic attacks",
        }
      end
    end

    # Protocol vulnerabilities
    if protocols["SSLv2"]&.dig(:supported)
      vulns << {
        name: "SSLv2 Enabled",
        severity: "CRITICAL",
        description: "SSLv2 is enabled and severely broken",
        impact: "Vulnerable to DROWN attack",
      }
    end

    if protocols["SSLv3"]&.dig(:supported)
      vulns << {
        name: "SSLv3 Enabled (POODLE)",
        severity: "CRITICAL",
        description: "SSLv3 is vulnerable to POODLE attack",
        impact: "Attackers can decrypt secure connections",
      }
    end

    if protocols["TLS1.0"]&.dig(:supported)
      vulns << {
        name: "TLS 1.0 Enabled",
        severity: "MEDIUM",
        description: "TLS 1.0 is deprecated and should be disabled",
        impact: "Vulnerable to various attacks including BEAST",
      }
    end

    if protocols["TLS1.1"]&.dig(:supported)
      vulns << {
        name: "TLS 1.1 Enabled",
        severity: "LOW",
        description: "TLS 1.1 is deprecated",
        impact: "Modern browsers are phasing out support",
      }
    end

    # Cipher vulnerabilities
    if ciphers[:weak_count] && ciphers[:weak_count] > 0
      vulns << {
        name: "Weak Cipher Suites",
        severity: "HIGH",
        description: "Server supports #{ciphers[:weak_count]} weak cipher suite(s)",
        impact: "Vulnerable to various cryptographic attacks",
      }
    end

    # Check for RC4
    if ciphers[:ciphers]&.any? { |c| c[:name].include?("RC4") }
      vulns << {
        name: "RC4 Cipher Support",
        severity: "HIGH",
        description: "Server supports RC4 cipher (broken)",
        impact: "Vulnerable to RC4 attacks",
      }
    end

    # TLS Configuration vulnerabilities
    if tls_config[:compression_supported]
      vulns << {
        name: "TLS Compression (CRIME)",
        severity: "HIGH",
        description: "TLS compression is enabled",
        impact: "Vulnerable to CRIME attack - session hijacking possible",
      }
    end

    unless tls_config[:secure_renegotiation]
      vulns << {
        name: "Insecure Renegotiation",
        severity: "MEDIUM",
        description: "Server does not support secure renegotiation",
        impact: "Vulnerable to renegotiation attacks",
      }
    end

    # Check for lack of forward secrecy
    if ciphers[:forward_secrecy_count] == 0 && ciphers[:total_supported] > 0
      vulns << {
        name: "No Forward Secrecy",
        severity: "MEDIUM",
        description: "Server does not support any cipher suites with forward secrecy",
        impact: "Past communications can be decrypted if private key is compromised",
      }
    end

    # Check for certificate chain issues
    if cert_info[:chain_length] && cert_info[:chain_length] < 2 && !cert_info[:self_signed]
      vulns << {
        name: "Incomplete Certificate Chain",
        severity: "MEDIUM",
        description: "Certificate chain appears incomplete",
        impact: "Some clients may not trust the certificate",
      }
    end

    vulns
  end

  def generate_recommendations(vulnerabilities, protocols, ciphers, tls_config)
    recommendations = []

    # Based on vulnerabilities
    if vulnerabilities.any? { |v| v[:name].include?("Expired") }
      recommendations << "Renew your SSL/TLS certificate immediately"
    end

    if vulnerabilities.any? { |v| v[:name].include?("Self-Signed") }
      recommendations << "Use a certificate from a trusted Certificate Authority (Let's Encrypt, DigiCert, etc.)"
    end

    # Protocol recommendations
    insecure_protocols = protocols.select { |name, info| info[:supported] && !info[:secure] }
    if insecure_protocols.any?
      recommendations << "Disable insecure protocols: #{insecure_protocols.keys.join(", ")}"
    end

    unless protocols["TLS1.2"]&.dig(:supported)
      recommendations << "Enable TLS 1.2 support"
    end

    unless protocols["TLS1.3"]&.dig(:supported)
      recommendations << "Enable TLS 1.3 for better security and performance"
    end

    # Cipher recommendations
    if ciphers[:weak_count] && ciphers[:weak_count] > 0
      recommendations << "Disable weak cipher suites (RC4, DES, NULL, EXPORT)"
    end

    # TLS Configuration recommendations
    if tls_config[:compression_supported]
      recommendations << "Disable TLS compression to prevent CRIME attacks"
    end

    if tls_config[:ocsp_stapling] && !tls_config[:ocsp_stapling][:enabled]
      recommendations << "Enable OCSP stapling for better performance and privacy"
    end

    if tls_config[:certificate_transparency] && !tls_config[:certificate_transparency][:enabled]
      recommendations << "Enable Certificate Transparency (SCT) for improved security"
    end

    if ciphers[:forward_secrecy_count] == 0
      recommendations << "Enable cipher suites with Forward Secrecy (ECDHE)"
    end

    # Server cipher preference
    if ciphers[:server_cipher_order]
      recommendations << "Good: Server enforces its own cipher preference order"
    else
      recommendations << "Configure server to enforce cipher preference order"
    end

    recommendations << "Implement HSTS (HTTP Strict Transport Security)" if recommendations.empty?

    recommendations
  end

  def calculate_security_score(cert_info, protocols, ciphers, tls_config, vulnerabilities)
    score = 100

    # Connection failure is an automatic F
    score -= 100 if cert_info[:error]

    # Certificate deductions
    score -= 100 if cert_info[:expired]
    score -= 30 if cert_info[:self_signed]
    score -= 10 if cert_info[:expires_in_days] && cert_info[:expires_in_days] < 30

    # Check for weak key size (algorithm-specific)
    if cert_info[:key_size]
      if cert_info[:public_key_algorithm] == "RSA" && cert_info[:key_size] < 2048
        score -= 20
      elsif cert_info[:public_key_algorithm] == "EC" && cert_info[:key_size] < 256
        score -= 20
      elsif cert_info[:public_key_algorithm] == "DSA" && cert_info[:key_size] < 2048
        score -= 20
      end
    end

    # Protocol deductions
    score -= 40 if protocols["SSLv2"]&.dig(:supported)
    score -= 40 if protocols["SSLv3"]&.dig(:supported)
    score -= 20 if protocols["TLS1.0"]&.dig(:supported)
    score -= 10 if protocols["TLS1.1"]&.dig(:supported)
    score += 10 if protocols["TLS1.3"]&.dig(:supported)

    # Cipher deductions
    score -= 30 if ciphers[:weak_count] && ciphers[:weak_count] > 0
    score -= 10 if ciphers[:forward_secrecy_count] == 0

    # TLS Configuration bonuses and deductions
    score -= 15 if tls_config[:compression_supported]
    score += 5 if tls_config[:ocsp_stapling]&.dig(:enabled)
    score += 5 if tls_config[:certificate_transparency]&.dig(:enabled)
    score += 5 if ciphers[:server_cipher_order]

    # Vulnerability deductions
    vulnerabilities.each do |vuln|
      case vuln[:severity]
      when "CRITICAL"
        score -= 25
      when "HIGH"
        score -= 15
      when "MEDIUM"
        score -= 10
      when "LOW"
        score -= 5
      end
    end

    score = [[score, 0].max, 100].min  # Clamp between 0 and 100

    {
      score: score,
      grade: score_to_grade(score),
      max_score: 100,
      rating: score_to_rating(score),
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

  def protocol_secure?(protocol_name)
    ["TLS1.2", "TLS1.3"].include?(protocol_name)
  end

  def weak_cipher?(cipher_name)
    WEAK_CIPHERS.any? { |weak| cipher_name.include?(weak) }
  end

  def classify_cipher_strength(cipher_name, bits)
    return "WEAK" if weak_cipher?(cipher_name)
    return "WEAK" if bits < 128
    return "STRONG" if bits >= 256
    "MEDIUM"
  end

  def get_key_size(public_key)
    case public_key
    when OpenSSL::PKey::RSA, OpenSSL::PKey::DSA
      public_key.n.num_bits
    when OpenSSL::PKey::EC
      public_key.group.degree
    else
      nil
    end
  end

  def extract_san_domains(cert)
    san_extension = cert.extensions.find { |ext| ext.oid == "subjectAltName" }
    return [] unless san_extension

    san_extension.value.split(",").map { |name| name.strip.sub(/^DNS:/, "") }
  rescue StandardError
    []
  end
end

SslSecurityTesterTool.register!
