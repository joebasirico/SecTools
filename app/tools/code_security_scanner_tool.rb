# frozen_string_literal: true

require 'zip'
require 'tempfile'
require_relative '../../lib/security_rule_loader'

# Code Security Scanner
# Analyzes source code for common security vulnerabilities
class CodeSecurityScannerTool
  include SecurityTool

  configure_tool(
    name: "Code Security Scanner",
    description: "Scan source code for common vulnerabilities (SQLi, XSS, IDOR, JWT issues, etc.)",
    category: "Code Security"
  )

  input_field :source_file, type: :file, label: "Source File or ZIP",
              placeholder: "Upload a source file (.rb, .js, .py, .php, .java) or ZIP archive",
              required: true,
              accept: '.rb,.js,.jsx,.ts,.tsx,.py,.php,.java,.go,.rs,.erb,.haml,.slim,.zip'
  input_field :scan_depth, type: :checkbox, label: "Deep Scan",
              placeholder: "Enable more thorough scanning (may take longer)",
              required: false

  output_format :html, :json

  # Load vulnerability patterns from YAML files
  def self.vulnerability_patterns
    @vulnerability_patterns ||= SecurityRuleLoader.load_all_rules
  end

  def execute(params)
    file_content = params[:source_file]
    @deep_scan = params[:scan_depth] == '1' || params[:scan_depth] == true

    if file_content.blank?
      return {
        error: "No file provided",
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
      }
    end

    # Check if it's a ZIP file
    files_to_scan = if zip_file?(file_content)
                      extract_zip_files(file_content)
                    else
                      # Single file - try to detect language from content if filename doesn't help
                      filename = params[:filename] || 'uploaded_file'
                      language = detect_language(filename)
                      language = detect_language_from_content(file_content) if language == :unknown

                      [{ name: filename, content: file_content, language: language }]
                    end

    if files_to_scan.empty?
      return {
        error: "No scannable files found",
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
      }
    end

    # Scan all files
    all_findings = []
    files_to_scan.each do |file|
      findings = scan_file(file[:name], file[:content], file[:language])
      all_findings.concat(findings)
    end

    # Calculate summary
    summary = calculate_summary(all_findings)

    {
      files_scanned: files_to_scan.length,
      findings: all_findings.sort_by { |f| -severity_rank(f[:severity]) },
      summary: summary,
      scan_type: @deep_scan ? 'Deep Scan' : 'Standard Scan'
    }
  end

  private

  def zip_file?(content)
    # Check for ZIP magic number (PK)
    content.start_with?('PK')
  end

  def extract_zip_files(zip_content)
    files = []

    begin
      # Create a temporary file to store the ZIP
      Tempfile.create(['upload', '.zip']) do |temp_file|
        temp_file.binmode
        temp_file.write(zip_content)
        temp_file.rewind

        # Extract and read files
        Zip::File.open(temp_file.path) do |zip_file|
          zip_file.each do |entry|
            next if entry.directory?
            next unless scannable_file?(entry.name)
            # Skip files larger than 5MB
            next if entry.size > 5_242_880

            content = entry.get_input_stream.read
            language = detect_language(entry.name)

            files << {
              name: entry.name,
              content: content,
              language: language
            }
          end
        end
      end
    rescue StandardError => e
      Rails.logger.error("ZIP extraction error: #{e.message}")
    end

    files
  end

  def scannable_file?(filename)
    # Only scan source code files
    extensions = ['.rb', '.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.go', '.rs', '.erb', '.haml', '.slim']
    extensions.any? { |ext| filename.downcase.end_with?(ext) }
  end

  def detect_language(filename)
    case filename.downcase
    when /\.rb$/, /\.erb$/, /\.haml$/, /\.slim$/
      :ruby
    when /\.js$/, /\.jsx$/, /\.ts$/, /\.tsx$/
      :javascript
    when /\.py$/
      :python
    when /\.php$/
      :php
    when /\.java$/
      :java
    else
      :unknown
    end
  end

  def detect_language_from_content(content)
    # Try to detect language from content patterns
    return :ruby if content.match?(/class\s+\w+|def\s+\w+|params\[|\.where\(|\.find|require\s+['"]|bundle\s+exec|ApplicationController/)
    return :javascript if content.match?(/function\s+\w+\s*\(|const\s+\w+\s*=|let\s+\w+\s*=|document\.|window\.|require\(['"]|=>/)
    return :python if content.match?(/def\s+\w+\s*\(.*\):|\bimport\s+\w+|from\s+\w+\s+import/)
    return :php if content.match?(/<\?php|<\?=|\$_GET|\$_POST/)
    return :java if content.match?(/public\s+class\s+\w+|public\s+static\s+void\s+main/)

    :unknown
  end

  def scan_file(filename, content, language)
    findings = []
    lines = content.split("\n")

    # Load rules from YAML files
    rules = self.class.vulnerability_patterns

    rules.each do |vuln_type, vuln_info|
      vuln_info[:patterns].each do |pattern|
        # Skip if pattern doesn't match this language
        next unless pattern[:languages].include?(language)

        lines.each_with_index do |line, index|
          next if line.strip.start_with?('#', '//', '/*', '*')  # Skip comments

          if line.match?(pattern[:regex])
            findings << {
              file: filename,
              line_number: index + 1,
              line_content: line.strip,
              vulnerability_type: vuln_info[:name],
              severity: vuln_info[:severity],
              description: pattern[:desc],
              recommendation: pattern[:recommendation],
              example: pattern[:example],
              code_snippet: get_code_snippet(lines, index)
            }
          end
        end
      end
    end

    findings
  end

  def get_code_snippet(lines, line_index, context_lines = 2)
    start_line = [line_index - context_lines, 0].max
    end_line = [line_index + context_lines, lines.length - 1].min

    snippet = []
    (start_line..end_line).each do |i|
      prefix = i == line_index ? '>>> ' : '    '
      snippet << "#{prefix}#{i + 1}: #{lines[i]}"
    end

    snippet.join("\n")
  end

  def severity_rank(severity)
    case severity.to_s.upcase
    when 'CRITICAL' then 4
    when 'HIGH' then 3
    when 'MEDIUM' then 2
    when 'LOW' then 1
    else 0
    end
  end

  def calculate_summary(findings)
    summary = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }

    findings.each do |finding|
      case finding[:severity].to_s.upcase
      when 'CRITICAL'
        summary[:critical] += 1
      when 'HIGH'
        summary[:high] += 1
      when 'MEDIUM'
        summary[:medium] += 1
      when 'LOW'
        summary[:low] += 1
      end
    end

    summary
  end
end

CodeSecurityScannerTool.register!
