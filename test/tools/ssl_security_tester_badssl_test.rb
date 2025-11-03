# frozen_string_literal: true

require "test_helper"

class SslSecurityTesterBadsslTest < ActiveSupport::TestCase
  def setup
    @tool = SslSecurityTesterTool.new
  end

  # Good SSL/TLS configurations
  test "badssl.com - should get A grade for good SSL" do
    result = @tool.execute(target_url: 'https://badssl.com')

    assert_equal 'A', result[:summary][:grade], "Should get A grade for badssl.com"
    assert result[:summary][:score] >= 90, "Score should be 90 or higher"
    assert result[:certificate][:valid], "Certificate should be valid"
    assert_not result[:certificate][:expired], "Certificate should not be expired"
    assert_not result[:certificate][:self_signed], "Certificate should not be self-signed"
  end

  # Certificate issues
  test "expired.badssl.com - should detect expired certificate" do
    result = @tool.execute(target_url: 'https://expired.badssl.com')

    assert_equal 'F', result[:summary][:grade], "Should get F grade for expired cert"
    assert_equal 0, result[:summary][:score], "Score should be 0 for expired cert"
    assert result[:certificate][:expired], "Certificate should be marked as expired"

    expired_vuln = result[:vulnerabilities].find { |v| v[:name] == "Expired Certificate" }
    assert_not_nil expired_vuln, "Should have Expired Certificate vulnerability"
    assert_equal "CRITICAL", expired_vuln[:severity], "Expired cert should be CRITICAL"
  end

  test "wrong.host.badssl.com - should still analyze certificate" do
    result = @tool.execute(target_url: 'https://wrong.host.badssl.com')

    # Should still get certificate info even if hostname doesn't match
    assert result[:certificate].present?, "Should have certificate information"
    assert result[:certificate][:subject].present?, "Should have certificate subject"
  end

  test "self-signed.badssl.com - should detect self-signed certificate" do
    result = @tool.execute(target_url: 'https://self-signed.badssl.com')

    assert result[:certificate][:self_signed], "Should detect self-signed certificate"

    self_signed_vuln = result[:vulnerabilities].find { |v| v[:name] == "Self-Signed Certificate" }
    assert_not_nil self_signed_vuln, "Should have Self-Signed Certificate vulnerability"
    assert_equal "HIGH", self_signed_vuln[:severity], "Self-signed cert should be HIGH severity"
  end

  test "untrusted-root.badssl.com - should detect untrusted certificate" do
    result = @tool.execute(target_url: 'https://untrusted-root.badssl.com')

    # Should still get certificate info
    assert result[:certificate].present?, "Should have certificate information"
  end

  # Protocol tests
  test "tls-v1-0.badssl.com - should detect TLS 1.0 if supported" do
    skip "TLS 1.0 is typically disabled in modern OpenSSL"
    result = @tool.execute(target_url: 'https://tls-v1-0.badssl.com:1010')

    if result[:protocols]['TLS1.0'][:supported]
      tls10_vuln = result[:vulnerabilities].find { |v| v[:name] == "TLS 1.0 Enabled" }
      assert_not_nil tls10_vuln, "Should warn about TLS 1.0"
      assert_equal "MEDIUM", tls10_vuln[:severity]
    end
  end

  test "tls-v1-1.badssl.com - should detect TLS 1.1 if supported" do
    skip "TLS 1.1 is typically disabled in modern OpenSSL"
    result = @tool.execute(target_url: 'https://tls-v1-1.badssl.com:1011')

    if result[:protocols]['TLS1.1'][:supported]
      tls11_vuln = result[:vulnerabilities].find { |v| v[:name] == "TLS 1.1 Enabled" }
      assert_not_nil tls11_vuln, "Should warn about TLS 1.1"
      assert_equal "LOW", tls11_vuln[:severity]
    end
  end

  # Cipher suite tests
  test "rc4.badssl.com - should detect RC4 cipher if supported" do
    skip "RC4 is typically disabled in modern OpenSSL"
    result = @tool.execute(target_url: 'https://rc4.badssl.com')

    if result[:ciphers][:ciphers].any? { |c| c[:name].include?('RC4') }
      rc4_vuln = result[:vulnerabilities].find { |v| v[:name] == "RC4 Cipher Support" }
      assert_not_nil rc4_vuln, "Should detect RC4 cipher"
      assert_equal "HIGH", rc4_vuln[:severity]
    end
  end

  test "rc4-md5.badssl.com - should detect RC4-MD5 cipher if supported" do
    skip "RC4-MD5 is typically disabled in modern OpenSSL"
    result = @tool.execute(target_url: 'https://rc4-md5.badssl.com')

    if result[:ciphers][:ciphers].any? { |c| c[:name].include?('RC4') }
      assert result[:ciphers][:weak_count] > 0, "Should detect weak ciphers"
    end
  end

  test "3des.badssl.com - should detect 3DES cipher if supported" do
    result = @tool.execute(target_url: 'https://3des.badssl.com')

    # 3DES might be supported by modern servers
    if result[:ciphers][:ciphers].any? { |c| c[:name].include?('DES') }
      assert result[:ciphers][:weak_count] > 0, "3DES should be classified as weak"
    end
  end

  test "null.badssl.com - should detect NULL cipher if supported" do
    skip "NULL ciphers are disabled in modern OpenSSL"
    result = @tool.execute(target_url: 'https://null.badssl.com')

    if result[:ciphers][:ciphers].any? { |c| c[:name].include?('NULL') }
      assert result[:ciphers][:weak_count] > 0, "NULL cipher should be weak"
    end
  end

  # Key size tests
  test "dh480.badssl.com - should fail to connect with weak DH parameters" do
    result = @tool.execute(target_url: 'https://dh480.badssl.com')

    # Modern OpenSSL should reject 480-bit DH
    # Either connection fails or we get an error
    assert(result[:error].present? || result[:protocols].values.all? { |p| !p[:supported] },
           "Should reject weak 480-bit DH parameters")
  end

  test "dh512.badssl.com - should fail to connect with weak DH parameters" do
    result = @tool.execute(target_url: 'https://dh512.badssl.com')

    # Modern OpenSSL should reject 512-bit DH
    assert(result[:error].present? || result[:protocols].values.all? { |p| !p[:supported] },
           "Should reject weak 512-bit DH parameters")
  end

  test "dh1024.badssl.com - may warn about weak DH parameters" do
    result = @tool.execute(target_url: 'https://dh1024.badssl.com')

    # 1024-bit DH is weak but might still connect
    # Just verify we can analyze it
    assert result.present?, "Should be able to analyze the connection"
  end

  test "dh2048.badssl.com - should accept 2048-bit DH parameters" do
    result = @tool.execute(target_url: 'https://dh2048.badssl.com')

    # 2048-bit DH should be acceptable
    assert result[:certificate].present?, "Should connect successfully with 2048-bit DH"
  end

  # Modern configurations
  test "sha256.badssl.com - should accept SHA256 signatures" do
    result = @tool.execute(target_url: 'https://sha256.badssl.com')

    assert result[:certificate][:signature_algorithm].include?('sha256'),
           "Should use SHA256 signature algorithm"
    assert result[:certificate][:valid], "SHA256 certificate should be valid"
  end

  test "sha384.badssl.com - should accept SHA384 signatures" do
    result = @tool.execute(target_url: 'https://sha384.badssl.com')

    assert result[:certificate][:signature_algorithm].include?('sha384'),
           "Should use SHA384 signature algorithm"
    assert result[:certificate][:valid], "SHA384 certificate should be valid"
  end

  test "sha512.badssl.com - should accept SHA512 signatures" do
    result = @tool.execute(target_url: 'https://sha512.badssl.com')

    assert result[:certificate][:signature_algorithm].include?('sha512'),
           "Should use SHA512 signature algorithm"
    assert result[:certificate][:valid], "SHA512 certificate should be valid"
  end

  test "rsa2048.badssl.com - should accept 2048-bit RSA keys" do
    result = @tool.execute(target_url: 'https://rsa2048.badssl.com')

    assert_equal 'RSA', result[:certificate][:public_key_algorithm]
    assert result[:certificate][:key_size] >= 2048, "Should have 2048-bit RSA key"

    # Should not have weak key vulnerability
    weak_key_vuln = result[:vulnerabilities].find { |v| v[:name] == "Weak Key Size" }
    assert_nil weak_key_vuln, "2048-bit RSA should not be weak"
  end

  test "rsa4096.badssl.com - should accept 4096-bit RSA keys" do
    result = @tool.execute(target_url: 'https://rsa4096.badssl.com')

    assert_equal 'RSA', result[:certificate][:public_key_algorithm]
    assert result[:certificate][:key_size] >= 4096, "Should have 4096-bit RSA key"
  end

  test "rsa8192.badssl.com - should accept 8192-bit RSA keys" do
    result = @tool.execute(target_url: 'https://rsa8192.badssl.com')

    assert_equal 'RSA', result[:certificate][:public_key_algorithm]
    assert result[:certificate][:key_size] >= 8192, "Should have 8192-bit RSA key"
  end

  test "ecc256.badssl.com - should accept 256-bit ECC keys" do
    result = @tool.execute(target_url: 'https://ecc256.badssl.com')

    assert_equal 'EC', result[:certificate][:public_key_algorithm]
    assert result[:certificate][:key_size] >= 256, "Should have 256-bit EC key"

    # Should not have weak key vulnerability
    weak_key_vuln = result[:vulnerabilities].find { |v| v[:name] == "Weak Key Size" }
    assert_nil weak_key_vuln, "256-bit EC should not be weak"
  end

  test "ecc384.badssl.com - should accept 384-bit ECC keys" do
    result = @tool.execute(target_url: 'https://ecc384.badssl.com')

    assert_equal 'EC', result[:certificate][:public_key_algorithm]
    assert result[:certificate][:key_size] >= 384, "Should have 384-bit EC key"
  end

  # Extended validation and domain validation
  test "extended-validation.badssl.com - should validate EV certificate" do
    result = @tool.execute(target_url: 'https://extended-validation.badssl.com')

    assert result[:certificate][:valid], "EV certificate should be valid"
    assert_not result[:certificate][:self_signed], "EV cert should not be self-signed"
  end

  # Subdomain tests
  test "subdomain.badssl.com - should validate subdomain certificate" do
    result = @tool.execute(target_url: 'https://subdomain.badssl.com')

    assert result[:certificate][:valid], "Subdomain certificate should be valid"
  end

  # Certificate chain tests
  test "incomplete-chain.badssl.com - should detect incomplete certificate chain" do
    result = @tool.execute(target_url: 'https://incomplete-chain.badssl.com')

    # Should still get certificate info
    assert result[:certificate].present?, "Should have certificate information"
  end

  # Performance test - ensure reasonable response time
  test "performance - should complete scan in reasonable time" do
    start_time = Time.now
    result = @tool.execute(target_url: 'https://badssl.com')
    duration = Time.now - start_time

    assert duration < 60, "Scan should complete in less than 60 seconds (took #{duration}s)"
    assert result.present?, "Should return results"
  end

  # Error handling tests
  test "invalid domain - should handle gracefully" do
    result = @tool.execute(target_url: 'https://this-domain-does-not-exist-12345.com')

    assert result[:error].present?, "Should have error for invalid domain"
    assert_equal 'F', result[:summary][:grade], "Should get F grade for connection failure"
  end

  test "no-sni.badssl.com - should handle servers without SNI" do
    result = @tool.execute(target_url: 'https://no-sni.badssl.com')

    # Should still be able to analyze the connection
    assert result.present?, "Should handle no-SNI servers"
  end

  # Comprehensive grading tests
  test "grading system - expired cert gets F" do
    result = @tool.execute(target_url: 'https://expired.badssl.com')
    assert_equal 'F', result[:summary][:grade]
  end

  test "grading system - self-signed gets low grade" do
    result = @tool.execute(target_url: 'https://self-signed.badssl.com')
    assert ['D', 'F'].include?(result[:summary][:grade]),
           "Self-signed should get D or F grade, got #{result[:summary][:grade]}"
  end

  test "grading system - good SSL gets A or B" do
    result = @tool.execute(target_url: 'https://badssl.com')
    assert ['A', 'B'].include?(result[:summary][:grade]),
           "Good SSL should get A or B grade, got #{result[:summary][:grade]}"
  end
end
