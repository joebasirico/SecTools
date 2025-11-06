# Base64/Encoding Decoder Tool
# Description: Multi-format encoder/decoder utility for security testing

class EncodingDecoderTool
  include SecurityTool

  configure_tool(
    name: "Base64/Encoding Decoder",
    description: "Decode, encode, and analyze various encoding formats commonly used in security testing. Supports Base64, Hex, URL encoding, HTML entities, Unicode, ROT13, and more. Includes auto-detection and multi-stage decoding.",
    category: "Authentication Security"
  )

  input_field :operation,
              type: :select,
              label: "Operation",
              options: ["Decode", "Encode", "Auto-Detect & Decode"],
              required: true

  input_field :encoding_type,
              type: :select,
              label: "Encoding Type",
              options: ["Base64", "Base64 URL-Safe", "Hex", "URL Encoding", "HTML Entities", "Unicode Escape", "ROT13", "Binary", "ASCII"],
              required: false

  input_field :input_text,
              type: :text,
              label: "Input Text",
              placeholder: "Enter text to encode/decode",
              required: true

  input_field :multi_decode,
              type: :checkbox,
              label: "Multi-Stage Decode",
              placeholder: "Attempt to decode multiple times until plain text",
              required: false

  output_format :html, :json

  def execute(params)
    operation = params[:operation]
    encoding_type = params[:encoding_type]
    input_text = params[:input_text]&.strip
    multi_decode = params[:multi_decode] == "1"

    return { error: "Input text is required" } if input_text.blank?

    results = {
      operation: operation,
      encoding_type: encoding_type,
      input: input_text,
      output: nil,
      detected_encodings: [],
      stages: [],
      character_analysis: {},
      possible_interpretations: []
    }

    begin
      if operation == "Auto-Detect & Decode"
        auto_detect_and_decode(input_text, results, multi_decode)
      elsif operation == "Decode"
        decode_text(input_text, encoding_type, results)
      else
        encode_text(input_text, encoding_type, results)
      end

      # Perform character analysis
      analyze_output(results)

      # Check if output looks like JWT, hash, or other security token
      identify_security_tokens(results)

    rescue StandardError => e
      results[:error] = "Error during #{operation.downcase}: #{e.message}"
    end

    results
  end

  private

  def auto_detect_and_decode(input_text, results, multi_decode)
    current_text = input_text
    max_iterations = multi_decode ? 10 : 1
    iteration = 0

    while iteration < max_iterations
      detected = detect_encoding(current_text)

      if detected.empty?
        break
      end

      # Try the most likely encoding
      encoding_info = detected.first
      results[:detected_encodings] << encoding_info

      decoded = decode_with_type(current_text, encoding_info[:type])

      if decoded && decoded != current_text
        results[:stages] << {
          iteration: iteration + 1,
          detected_as: encoding_info[:name],
          confidence: encoding_info[:confidence],
          input: current_text[0..100] + (current_text.length > 100 ? "..." : ""),
          output: decoded[0..100] + (decoded.length > 100 ? "..." : "")
        }

        current_text = decoded
        iteration += 1
      else
        break
      end
    end

    results[:output] = current_text
    results[:total_stages] = iteration
  end

  def detect_encoding(text)
    detections = []

    # Base64 detection
    if text.match?(/^[A-Za-z0-9+\/]+=*$/) && text.length % 4 == 0
      detections << { type: "base64", name: "Base64", confidence: :high }
    end

    # Base64 URL-safe detection
    if text.match?(/^[A-Za-z0-9_-]+=*$/)
      detections << { type: "base64url", name: "Base64 URL-Safe", confidence: :medium }
    end

    # Hex detection
    if text.match?(/^[0-9A-Fa-f]+$/) && text.length.even?
      detections << { type: "hex", name: "Hexadecimal", confidence: :high }
    end

    # URL encoding detection
    if text.include?('%') && text.match?(/%[0-9A-Fa-f]{2}/)
      detections << { type: "url", name: "URL Encoding", confidence: :high }
    end

    # HTML entities detection
    if text.include?('&') && text.match?(/&[#\w]+;/)
      detections << { type: "html", name: "HTML Entities", confidence: :high }
    end

    # Unicode escape detection
    if text.include?('\\u') && text.match?(/\\u[0-9A-Fa-f]{4}/)
      detections << { type: "unicode", name: "Unicode Escape", confidence: :high }
    end

    # Binary detection
    if text.match?(/^[01\s]+$/)
      detections << { type: "binary", name: "Binary", confidence: :medium }
    end

    detections.sort_by { |d| d[:confidence] == :high ? 0 : 1 }
  end

  def decode_text(input_text, encoding_type, results)
    type_key = encoding_type.downcase.gsub(/[^a-z]/, '')

    decoded = decode_with_type(input_text, type_key)

    if decoded
      results[:output] = decoded
      results[:success] = true
    else
      results[:error] = "Failed to decode as #{encoding_type}"
    end
  end

  def decode_with_type(text, type)
    case type
    when "base64"
      Base64.decode64(text)
    when "base64urlsafe", "base64url"
      Base64.urlsafe_decode64(text)
    when "hex", "hexadecimal"
      [text].pack('H*')
    when "url", "urlencoding"
      CGI.unescape(text)
    when "html", "htmlentities"
      CGI.unescapeHTML(text)
    when "unicode", "unicodeescape"
      text.gsub(/\\u([0-9A-Fa-f]{4})/) { |m| [$1.hex].pack('U') }
    when "rot13"
      text.tr('A-Za-z', 'N-ZA-Mn-za-m')
    when "binary"
      text.gsub(/\s+/, '').scan(/.{8}/).map { |b| b.to_i(2).chr }.join
    when "ascii"
      text.split.map { |n| n.to_i.chr }.join
    else
      nil
    end
  rescue StandardError
    nil
  end

  def encode_text(input_text, encoding_type, results)
    type_key = encoding_type.downcase.gsub(/[^a-z]/, '')

    encoded = case type_key
              when "base64"
                Base64.encode64(input_text).gsub("\n", '')
              when "base64urlsafe", "base64url"
                Base64.urlsafe_encode64(input_text).gsub("\n", '')
              when "hex", "hexadecimal"
                input_text.unpack1('H*')
              when "url", "urlencoding"
                CGI.escape(input_text)
              when "html", "htmlentities"
                CGI.escapeHTML(input_text)
              when "unicode", "unicodeescape"
                input_text.chars.map { |c| "\\u#{c.ord.to_s(16).rjust(4, '0')}" }.join
              when "rot13"
                input_text.tr('A-Za-z', 'N-ZA-Mn-za-m')
              when "binary"
                input_text.bytes.map { |b| b.to_s(2).rjust(8, '0') }.join(' ')
              when "ascii"
                input_text.bytes.join(' ')
              else
                "Unsupported encoding type"
              end

    results[:output] = encoded
    results[:success] = true
  rescue StandardError => e
    results[:error] = "Failed to encode as #{encoding_type}: #{e.message}"
  end

  def analyze_output(results)
    return unless results[:output]

    output = results[:output]

    results[:character_analysis] = {
      length: output.length,
      bytes: output.bytesize,
      printable: output.chars.all? { |c| c =~ /[[:print:]]/ },
      ascii_only: output.ascii_only?,
      contains_null_bytes: output.include?("\x00"),
      line_count: output.lines.count,
      word_count: output.split.count
    }

    # Calculate entropy
    results[:character_analysis][:entropy] = calculate_entropy(output).round(2)

    # Character type distribution
    char_types = {
      uppercase: output.count('A-Z'),
      lowercase: output.count('a-z'),
      digits: output.count('0-9'),
      special: output.count('^A-Za-z0-9'),
      whitespace: output.count(" \t\n\r")
    }
    results[:character_analysis][:character_types] = char_types
  end

  def calculate_entropy(string)
    return 0 if string.empty?

    frequencies = Hash.new(0)
    string.each_char { |char| frequencies[char] += 1 }

    entropy = 0
    string.length.times do |i|
      freq = frequencies[string[i]].to_f / string.length
      entropy -= freq * Math.log2(freq) if freq > 0
    end

    entropy
  end

  def identify_security_tokens(results)
    return unless results[:output]

    output = results[:output]

    # Check for JWT
    if output.match?(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/)
      results[:possible_interpretations] << {
        type: "JWT (JSON Web Token)",
        confidence: :high,
        message: "Output appears to be a JWT token",
        action: "Use the JWT Validator tool for detailed analysis"
      }
    end

    # Check for common hash formats
    hash_patterns = [
      { pattern: /^[a-f0-9]{32}$/i, name: "MD5 Hash" },
      { pattern: /^[a-f0-9]{40}$/i, name: "SHA-1 Hash" },
      { pattern: /^[a-f0-9]{64}$/i, name: "SHA-256 Hash" },
      { pattern: /^[a-f0-9]{128}$/i, name: "SHA-512 Hash" }
    ]

    hash_patterns.each do |hash_info|
      if output.match?(hash_info[:pattern])
        results[:possible_interpretations] << {
          type: hash_info[:name],
          confidence: :high,
          message: "Output appears to be a #{hash_info[:name]}",
          action: "This is a one-way hash and cannot be decoded"
        }
        break
      end
    end

    # Check for UUID
    if output.match?(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
      results[:possible_interpretations] << {
        type: "UUID",
        confidence: :high,
        message: "Output is a Universally Unique Identifier (UUID)"
      }
    end

    # Check for API key patterns
    api_key_patterns = [
      { pattern: /^sk_live_/, name: "Stripe API Key" },
      { pattern: /^AKIA/, name: "AWS Access Key" },
      { pattern: /^AIza/, name: "Google API Key" },
      { pattern: /^gh[pousr]_/, name: "GitHub Token" }
    ]

    api_key_patterns.each do |api_info|
      if output.match?(api_info[:pattern])
        results[:possible_interpretations] << {
          type: api_info[:name],
          confidence: :high,
          message: "Output appears to be a #{api_info[:name]}",
          warning: "This is sensitive data - handle with care!"
        }
      end
    end

    # Check for JSON
    begin
      JSON.parse(output)
      results[:possible_interpretations] << {
        type: "JSON Data",
        confidence: :high,
        message: "Output is valid JSON",
        action: "Use the XML/JSON Validator for detailed analysis"
      }
    rescue JSON::ParserError
      # Not JSON
    end

    # Check for XML
    if output.match?(/<\?xml|<!DOCTYPE|<[a-zA-Z]/)
      results[:possible_interpretations] << {
        type: "XML Data",
        confidence: :medium,
        message: "Output appears to contain XML",
        action: "Use the XML/JSON Validator for detailed analysis"
      }
    end
  end
end

EncodingDecoderTool.register!
