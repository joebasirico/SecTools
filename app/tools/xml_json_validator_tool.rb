# XML/JSON Schema Validator Tool
# Description: Validate and test for XXE, JSON injection, and schema vulnerabilities

class XmlJsonValidatorTool
  include SecurityTool

  configure_tool(
    name: "XML/JSON Schema Validator",
    description: "Validate XML and JSON content, test for XXE (XML External Entity) vulnerabilities, JSON injection risks, schema poisoning, and other parsing-related security issues.",
    category: "Code Security"
  )

  input_field :content_type,
              type: :select,
              label: "Content Type",
              options: ["XML", "JSON"],
              required: true

  input_field :content,
              type: :text,
              label: "XML or JSON Content",
              placeholder: "Paste your XML or JSON content here",
              required: true

  input_field :deep_scan,
              type: :checkbox,
              label: "Perform Deep Security Scan",
              placeholder: "Check for advanced vulnerabilities and injection patterns",
              required: false

  output_format :html, :json

  def execute(params)
    content_type = params[:content_type]
    content = params[:content]&.strip
    deep_scan = params[:deep_scan] == "1"

    return { error: "Content is required" } if content.blank?

    results = {
      content_type: content_type,
      valid: false,
      vulnerabilities: [],
      warnings: [],
      info: [],
      risk_level: :low,
      recommendations: []
    }

    if content_type == "XML"
      analyze_xml(content, results, deep_scan)
    else
      analyze_json(content, results, deep_scan)
    end

    # Calculate risk level
    calculate_risk_level(results)

    results
  rescue StandardError => e
    { error: "Error analyzing content: #{e.message}" }
  end

  private

  def analyze_xml(content, results, deep_scan)
    # Check for XXE vulnerabilities
    check_xxe_patterns(content, results)

    # Check for DTD usage
    check_dtd_usage(content, results)

    # Check for external entity references
    check_external_entities(content, results)

    # Try to parse XML
    begin
      doc = Nokogiri::XML(content) do |config|
        config.strict.nonet.noent
      end

      if doc.errors.empty?
        results[:valid] = true
        results[:info] << {
          type: "Valid XML",
          message: "XML structure is valid"
        }

        # Analyze structure
        analyze_xml_structure(doc, results, deep_scan)
      else
        results[:valid] = false
        results[:warnings] << {
          type: "Parse Errors",
          message: "XML has parsing errors",
          details: doc.errors.map(&:to_s)
        }
      end
    rescue Nokogiri::XML::SyntaxError => e
      results[:valid] = false
      results[:vulnerabilities] << {
        severity: :low,
        type: "Malformed XML",
        message: "XML syntax error: #{e.message}"
      }
    end

    # Deep scan checks
    if deep_scan
      check_xml_bomb(content, results)
      check_xml_injection_points(content, results)
      check_xpath_injection(content, results)
    end
  end

  def check_xxe_patterns(content, results)
    xxe_patterns = [
      { pattern: /<!ENTITY.*SYSTEM/i, name: "SYSTEM Entity", severity: :critical },
      { pattern: /<!ENTITY.*PUBLIC/i, name: "PUBLIC Entity", severity: :high },
      { pattern: /<!ENTITY.*file:/i, name: "File Protocol", severity: :critical },
      { pattern: /<!ENTITY.*http:/i, name: "HTTP Protocol", severity: :high },
      { pattern: /<!ENTITY.*ftp:/i, name: "FTP Protocol", severity: :high },
      { pattern: /<!ENTITY.*php:/i, name: "PHP Wrapper", severity: :critical },
      { pattern: /<!ENTITY.*expect:/i, name: "Expect Protocol", severity: :critical },
      { pattern: /<!ENTITY.*data:/i, name: "Data URI", severity: :high }
    ]

    xxe_patterns.each do |pattern_info|
      if content.match?(pattern_info[:pattern])
        results[:vulnerabilities] << {
          severity: pattern_info[:severity],
          type: "XXE - #{pattern_info[:name]}",
          message: "Potential XXE vulnerability detected using #{pattern_info[:name]}",
          impact: "Could lead to file disclosure, SSRF, or denial of service",
          line: find_line_number(content, pattern_info[:pattern])
        }
      end
    end
  end

  def check_dtd_usage(content, results)
    if content.match?(/<!DOCTYPE/i)
      results[:warnings] << {
        type: "DTD Usage",
        message: "Document Type Definition (DTD) detected",
        recommendation: "Disable DTD processing in production to prevent XXE attacks"
      }
    end
  end

  def check_external_entities(content, results)
    if content.match?(/<!ENTITY\s+\w+\s+SYSTEM/i)
      results[:vulnerabilities] << {
        severity: :critical,
        type: "External Entity Declaration",
        message: "External entity declaration found",
        impact: "Allows reading arbitrary files or making network requests",
        recommendation: "Remove external entity declarations and disable external entity processing"
      }
    end
  end

  def check_xml_bomb(content, results)
    # Check for billion laughs attack pattern
    entity_count = content.scan(/<!ENTITY/).length
    entity_refs = content.scan(/&\w+;/).length

    if entity_count > 10 && entity_refs > entity_count * 5
      results[:vulnerabilities] << {
        severity: :high,
        type: "Potential XML Bomb (Billion Laughs)",
        message: "Detected pattern similar to XML bomb attack",
        details: "#{entity_count} entities with #{entity_refs} references",
        impact: "Could cause denial of service through memory exhaustion"
      }
    end
  end

  def analyze_xml_structure(doc, results, deep_scan)
    results[:structure] = {
      root_element: doc.root&.name,
      total_elements: doc.xpath("//*").length,
      total_attributes: doc.xpath("//@*").length,
      namespaces: doc.collect_namespaces
    }

    # Check for suspicious patterns
    if deep_scan
      # Check for CDATA sections
      cdata_sections = doc.xpath("//text()[contains(., '<![CDATA[')]")
      if cdata_sections.any?
        results[:info] << {
          type: "CDATA Sections",
          message: "Found #{cdata_sections.length} CDATA section(s)",
          recommendation: "Review CDATA content for injection risks"
        }
      end
    end
  end

  def check_xml_injection_points(content, results)
    # Check for user-controlled data patterns
    injection_indicators = [
      '${', '#{', '%{', '{{',  # Template injection
      '<script', 'javascript:',  # XSS
      'SELECT ', 'UNION ',  # SQLi
      '../', '..\\',  # Path traversal
    ]

    injection_indicators.each do |indicator|
      if content.include?(indicator)
        results[:warnings] << {
          type: "Potential Injection Point",
          message: "Found suspicious pattern: #{indicator}",
          recommendation: "Ensure proper input validation and output encoding"
        }
      end
    end
  end

  def check_xpath_injection(content, results)
    xpath_patterns = [
      /\[.*or.*\]/i,
      /\[.*and.*\]/i,
      /\[.*'.*=.*'\]/
    ]

    xpath_patterns.each do |pattern|
      if content.match?(pattern)
        results[:warnings] << {
          type: "Potential XPath Injection",
          message: "Detected pattern that could indicate XPath injection",
          recommendation: "Use parameterized XPath queries"
        }
        break
      end
    end
  end

  def analyze_json(content, results, deep_scan)
    begin
      parsed = JSON.parse(content)
      results[:valid] = true

      results[:info] << {
        type: "Valid JSON",
        message: "JSON structure is valid"
      }

      # Analyze structure
      analyze_json_structure(parsed, results)

      # Security checks
      check_json_injection(content, results, deep_scan)
      check_prototype_pollution(parsed, results) if deep_scan
      check_sensitive_data_exposure(parsed, results)

    rescue JSON::ParserError => e
      results[:valid] = false
      results[:vulnerabilities] << {
        severity: :low,
        type: "Malformed JSON",
        message: "JSON parsing error: #{e.message}"
      }
    end
  end

  def analyze_json_structure(parsed, results)
    results[:structure] = {
      type: parsed.class.name,
      keys: parsed.is_a?(Hash) ? parsed.keys : nil,
      size: parsed.is_a?(Hash) ? parsed.size : (parsed.is_a?(Array) ? parsed.length : nil),
      depth: calculate_depth(parsed)
    }

    # Check for excessive depth
    if results[:structure][:depth] > 20
      results[:warnings] << {
        type: "Deep Nesting",
        message: "JSON has excessive nesting depth (#{results[:structure][:depth]} levels)",
        impact: "Could cause stack overflow or performance issues"
      }
    end
  end

  def calculate_depth(obj, current_depth = 0)
    return current_depth unless obj.is_a?(Hash) || obj.is_a?(Array)

    max_depth = current_depth
    values = obj.is_a?(Hash) ? obj.values : obj

    values.each do |value|
      depth = calculate_depth(value, current_depth + 1)
      max_depth = depth if depth > max_depth
    end

    max_depth
  end

  def check_json_injection(content, results, deep_scan)
    # Check for common injection patterns
    injection_patterns = [
      { pattern: /__proto__/, name: "Prototype Pollution", severity: :high },
      { pattern: /constructor.*prototype/, name: "Constructor Manipulation", severity: :high },
      { pattern: /<script/i, name: "XSS Pattern", severity: :medium },
      { pattern: /javascript:/i, name: "JavaScript Protocol", severity: :medium },
      { pattern: /on\w+\s*=/i, name: "Event Handler", severity: :medium }
    ]

    injection_patterns.each do |pattern_info|
      if content.match?(pattern_info[:pattern])
        results[:vulnerabilities] << {
          severity: pattern_info[:severity],
          type: pattern_info[:name],
          message: "Detected potential #{pattern_info[:name].downcase} pattern",
          line: find_line_number(content, pattern_info[:pattern])
        }
      end
    end

    if deep_scan
      # Check for SQL injection patterns in JSON values
      sql_patterns = [
        /'\s*or\s*'1'\s*=\s*'1/i,
        /'\s*or\s*1\s*=\s*1/i,
        /union\s+select/i,
        /;\s*drop\s+table/i
      ]

      sql_patterns.each do |pattern|
        if content.match?(pattern)
          results[:vulnerabilities] << {
            severity: :high,
            type: "SQL Injection Pattern",
            message: "Detected potential SQL injection pattern in JSON content",
            recommendation: "Use parameterized queries and input validation"
          }
          break
        end
      end
    end
  end

  def check_prototype_pollution(parsed, results)
    dangerous_keys = ['__proto__', 'constructor', 'prototype']

    check_keys_recursive = lambda do |obj, path = []|
      if obj.is_a?(Hash)
        obj.each do |key, value|
          if dangerous_keys.include?(key.to_s)
            results[:vulnerabilities] << {
              severity: :critical,
              type: "Prototype Pollution Risk",
              message: "Found dangerous key '#{key}' at path: #{path.join('.')}.#{key}",
              impact: "Could lead to prototype pollution in JavaScript environments",
              recommendation: "Remove or sanitize this key before processing"
            }
          end
          check_keys_recursive.call(value, path + [key])
        end
      elsif obj.is_a?(Array)
        obj.each_with_index do |item, index|
          check_keys_recursive.call(item, path + ["[#{index}]"])
        end
      end
    end

    check_keys_recursive.call(parsed)
  end

  def check_sensitive_data_exposure(parsed, results)
    sensitive_keys = [
      'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
      'private_key', 'access_token', 'refresh_token', 'auth', 'authorization',
      'credit_card', 'ssn', 'social_security'
    ]

    found_sensitive = []

    check_sensitive_recursive = lambda do |obj, path = []|
      if obj.is_a?(Hash)
        obj.each do |key, value|
          key_lower = key.to_s.downcase
          if sensitive_keys.any? { |sk| key_lower.include?(sk) }
            found_sensitive << "#{path.join('.')}.#{key}"
          end
          check_sensitive_recursive.call(value, path + [key])
        end
      elsif obj.is_a?(Array)
        obj.each_with_index do |item, index|
          check_sensitive_recursive.call(item, path + ["[#{index}]"])
        end
      end
    end

    check_sensitive_recursive.call(parsed)

    if found_sensitive.any?
      results[:warnings] << {
        type: "Sensitive Data Exposure",
        message: "Found #{found_sensitive.length} key(s) that may contain sensitive data",
        keys: found_sensitive,
        recommendation: "Ensure sensitive data is properly encrypted and not logged"
      }
    end
  end

  def find_line_number(content, pattern)
    content.lines.each_with_index do |line, index|
      return index + 1 if line.match?(pattern)
    end
    nil
  end

  def calculate_risk_level(results)
    critical_count = results[:vulnerabilities].count { |v| v[:severity] == :critical }
    high_count = results[:vulnerabilities].count { |v| v[:severity] == :high }
    medium_count = results[:vulnerabilities].count { |v| v[:severity] == :medium }

    results[:risk_level] = if critical_count > 0
                            :critical
                          elsif high_count > 0
                            :high
                          elsif medium_count > 0
                            :medium
                          elsif results[:warnings].any?
                            :low
                          else
                            :secure
                          end

    results[:recommendations] = generate_recommendations(results)
  end

  def generate_recommendations(results)
    recommendations = []

    if results[:content_type] == "XML"
      recommendations << "Disable DTD processing and external entity resolution in XML parser"
      recommendations << "Use secure XML parser settings (nonet, noent, nodefaultns)"
      recommendations << "Validate XML against a strict schema (XSD)"
      recommendations << "Implement input size limits to prevent DoS attacks"
    else
      recommendations << "Validate JSON against a strict schema (JSON Schema)"
      recommendations << "Sanitize object keys before merging with existing objects"
      recommendations << "Implement depth and size limits for JSON parsing"
      recommendations << "Never use eval() or Function() constructor with JSON data"
    end

    if results[:vulnerabilities].any?
      recommendations << "Fix all identified vulnerabilities before processing this content"
      recommendations << "Implement proper input validation and sanitization"
    end

    recommendations << "Consider using a security-focused parser library"
    recommendations << "Log and monitor parsing errors for security incidents"

    recommendations
  end
end

XmlJsonValidatorTool.register!
