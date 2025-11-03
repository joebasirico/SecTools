# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'
require 'fileutils'
require 'digest'

# Dependency Validator with OSV Database Integration
# Checks project dependencies against the OSV vulnerability database
class DepValidatorTool
  include SecurityTool

  # Cache expires after 30 days
  CACHE_EXPIRATION_DAYS = 30

  configure_tool(
    name: "Dependency Validator",
    description: "Scan project dependencies for vulnerabilities using OSV database",
    category: "Dependency Security"
  )

  input_field :dependency_file, type: :file, label: "Dependency File",
              placeholder: "Upload Gemfile.lock, package-lock.json, or requirements.txt",
              required: true,
              accept: '.lock,.json,.txt'
  input_field :force_refresh, type: :checkbox, label: "Force Refresh Cache",
              placeholder: "Bypass cache and fetch fresh data from OSV",
              required: false
  output_format :html, :json

  def execute(params)
    file_content = params[:dependency_file]
    @force_refresh = params[:force_refresh] == '1' || params[:force_refresh] == true

    if file_content.blank?
      return {
        error: "No file provided",
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
      }
    end

    # Initialize cache
    ensure_cache_directory

    # Detect file type and parse dependencies
    ecosystem, dependencies = parse_dependencies(file_content)

    if dependencies.empty?
      return {
        error: "Could not parse dependencies from file",
        ecosystem: ecosystem,
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
      }
    end

    # Check each dependency against OSV database (with caching)
    vulnerabilities = check_vulnerabilities(ecosystem, dependencies)

    # Build dependency tree with issues
    tree = build_dependency_tree(dependencies, vulnerabilities)

    # Generate recommendations
    recommendations = generate_recommendations(vulnerabilities, ecosystem)

    # Calculate summary
    summary = calculate_summary(vulnerabilities)

    {
      ecosystem: ecosystem,
      total_dependencies: dependencies.length,
      vulnerabilities: vulnerabilities,
      dependency_tree: tree,
      recommendations: recommendations,
      summary: summary
    }
  end

  private

  def parse_dependencies(file_content)
    # Detect file type based on content
    if file_content.include?('GEM') && file_content.include?('specs:')
      return ['RubyGems', parse_gemfile_lock(file_content)]
    elsif file_content.include?('"dependencies"') || file_content.include?('"packages"')
      return ['npm', parse_package_lock(file_content)]
    elsif file_content.match?(/^[\w-]+==/)
      return ['PyPI', parse_requirements_txt(file_content)]
    else
      return ['Unknown', []]
    end
  end

  def parse_gemfile_lock(content)
    dependencies = []
    in_specs = false

    content.each_line do |line|
      if line.strip == 'specs:'
        in_specs = true
        next
      end

      next unless in_specs

      # Break on next section
      break if line.match?(/^[A-Z]/) && !line.strip.start_with?(' ')

      # Match gem lines like "    rails (7.0.4)"
      if line.match?(/^\s{4}(\S+)\s+\((.+)\)/)
        match = line.match(/^\s{4}(\S+)\s+\((.+)\)/)
        name = match[1]
        version = match[2]
        dependencies << { name: name, version: version, type: 'direct' }
      end
    end

    dependencies
  end

  def parse_package_lock(content)
    dependencies = []

    begin
      data = JSON.parse(content)

      # package-lock.json v2/v3 format
      if data['packages']
        data['packages'].each do |path, package|
          next if path.empty? # Skip root package

          name = package['name'] || path.split('node_modules/').last
          version = package['version']

          dependencies << {
            name: name,
            version: version,
            type: data.dig('dependencies', name) ? 'direct' : 'transitive'
          } if version
        end
      # package-lock.json v1 format
      elsif data['dependencies']
        data['dependencies'].each do |name, package|
          dependencies << {
            name: name,
            version: package['version'],
            type: 'direct'
          }
        end
      end
    rescue JSON::ParserError
      # Return empty if invalid JSON
    end

    dependencies
  end

  def parse_requirements_txt(content)
    dependencies = []

    content.each_line do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')

      # Match package==version or package>=version
      if line.match?(/^([\w-]+)\s*([=><]=?)\s*(.+)$/)
        match = line.match(/^([\w-]+)\s*([=><]=?)\s*(.+)$/)
        name = match[1]
        version = match[3]

        dependencies << { name: name, version: version, type: 'direct' }
      end
    end

    dependencies
  end

  def check_vulnerabilities(ecosystem, dependencies)
    vulnerabilities = []

    dependencies.each do |dep|
      vulns = query_osv(ecosystem, dep[:name], dep[:version])

      vulns.each do |vuln|
        vulnerabilities << {
          dependency: dep[:name],
          version: dep[:version],
          type: dep[:type],
          vulnerability_id: vuln['id'],
          summary: vuln['summary'],
          details: vuln['details'],
          severity: extract_severity(vuln),
          cvss_score: extract_cvss_score(vuln),
          fixed_versions: extract_fixed_versions(vuln),
          references: extract_references(vuln)
        }
      end
    end

    vulnerabilities
  end

  def query_osv(ecosystem, package_name, version)
    # Check cache first unless force refresh is requested
    unless @force_refresh
      cached_result = get_cached_result(ecosystem, package_name, version)
      return cached_result if cached_result
    end

    # Fetch from API
    begin
      uri = URI('https://api.osv.dev/v1/query')
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = 10
      http.read_timeout = 10

      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/json'

      request.body = {
        package: {
          name: package_name,
          ecosystem: ecosystem
        },
        version: version
      }.to_json

      response = http.request(request)

      if response.code == '200'
        data = JSON.parse(response.body)
        result = data['vulns'] || []

        # Cache the result
        cache_result(ecosystem, package_name, version, result)

        return result
      else
        return []
      end
    rescue StandardError => e
      Rails.logger.error("OSV API error: #{e.message}")
      return []
    end
  end

  def extract_severity(vuln)
    # Check for severity in database_specific or severity array
    if vuln['database_specific'] && vuln['database_specific']['severity']
      return vuln['database_specific']['severity']
    elsif vuln['severity']
      return vuln['severity'].first['type'] if vuln['severity'].is_a?(Array)
    end

    # Fall back to CVSS score if available
    score = extract_cvss_score(vuln)
    return cvss_to_severity(score) if score

    'UNKNOWN'
  end

  def extract_cvss_score(vuln)
    return nil unless vuln['severity']

    vuln['severity'].each do |sev|
      if sev['type'] == 'CVSS_V3' || sev['type'] == 'CVSS_V2'
        return sev['score']&.to_f
      end
    end

    nil
  end

  def cvss_to_severity(score)
    return 'CRITICAL' if score >= 9.0
    return 'HIGH' if score >= 7.0
    return 'MEDIUM' if score >= 4.0
    'LOW'
  end

  def extract_fixed_versions(vuln)
    fixed = []

    return fixed unless vuln['affected']

    vuln['affected'].each do |affected|
      next unless affected['ranges']

      affected['ranges'].each do |range|
        if range['events']
          range['events'].each do |event|
            fixed << event['fixed'] if event['fixed']
          end
        end
      end
    end

    fixed.uniq
  end

  def extract_references(vuln)
    return [] unless vuln['references']

    vuln['references'].map do |ref|
      { type: ref['type'], url: ref['url'] }
    end
  end

  def build_dependency_tree(dependencies, vulnerabilities)
    tree = []

    # Group vulnerabilities by dependency
    vuln_map = vulnerabilities.group_by { |v| v[:dependency] }

    dependencies.each do |dep|
      vulns = vuln_map[dep[:name]] || []

      tree << {
        name: dep[:name],
        version: dep[:version],
        type: dep[:type],
        has_vulnerabilities: vulns.any?,
        vulnerability_count: vulns.length,
        max_severity: vulns.map { |v| severity_rank(v[:severity]) }.max || 0,
        vulnerabilities: vulns.map { |v| v[:vulnerability_id] }
      }
    end

    # Sort by severity (critical first)
    tree.sort_by { |node| -node[:max_severity] }
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

  def generate_recommendations(vulnerabilities, ecosystem)
    recommendations = []

    # Group by dependency
    vuln_by_dep = vulnerabilities.group_by { |v| v[:dependency] }

    vuln_by_dep.each do |dep_name, vulns|
      fixed_versions = vulns.flat_map { |v| v[:fixed_versions] }.uniq.compact

      if fixed_versions.any?
        latest_fix = fixed_versions.max

        recommendation = {
          dependency: dep_name,
          current_version: vulns.first[:version],
          recommended_version: latest_fix,
          vulnerability_count: vulns.length,
          max_severity: vulns.map { |v| v[:severity] }.max_by { |s| severity_rank(s) }
        }

        # Add ecosystem-specific upgrade command
        case ecosystem
        when 'RubyGems'
          recommendation[:command] = "bundle update #{dep_name}"
        when 'npm'
          recommendation[:command] = "npm update #{dep_name}"
        when 'PyPI'
          recommendation[:command] = "pip install --upgrade #{dep_name}"
        end

        recommendations << recommendation
      else
        # No fix available
        recommendations << {
          dependency: dep_name,
          current_version: vulns.first[:version],
          recommended_version: nil,
          vulnerability_count: vulns.length,
          max_severity: vulns.map { |v| v[:severity] }.max_by { |s| severity_rank(s) },
          command: "No fix available - consider alternative package"
        }
      end
    end

    recommendations.sort_by { |r| -severity_rank(r[:max_severity]) }
  end

  def calculate_summary(vulnerabilities)
    summary = {
      total: vulnerabilities.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0
    }

    vulnerabilities.each do |vuln|
      case vuln[:severity].to_s.upcase
      when 'CRITICAL'
        summary[:critical] += 1
      when 'HIGH'
        summary[:high] += 1
      when 'MEDIUM'
        summary[:medium] += 1
      when 'LOW'
        summary[:low] += 1
      else
        summary[:unknown] += 1
      end
    end

    summary
  end

  # Cache management methods
  def cache_directory
    Rails.root.join('tmp', 'osv_cache')
  end

  def ensure_cache_directory
    FileUtils.mkdir_p(cache_directory) unless Dir.exist?(cache_directory)
  end

  def cache_key(ecosystem, package_name, version)
    # Create a unique cache key based on ecosystem, package, and version
    raw_key = "#{ecosystem}:#{package_name}:#{version}"
    Digest::SHA256.hexdigest(raw_key)
  end

  def cache_file_path(ecosystem, package_name, version)
    key = cache_key(ecosystem, package_name, version)
    cache_directory.join("#{key}.json")
  end

  def get_cached_result(ecosystem, package_name, version)
    file_path = cache_file_path(ecosystem, package_name, version)

    return nil unless File.exist?(file_path)

    # Check if cache is expired (older than 30 days)
    file_age_days = (Time.now - File.mtime(file_path)) / 86400.0
    if file_age_days > CACHE_EXPIRATION_DAYS
      # Cache expired, delete it
      File.delete(file_path)
      return nil
    end

    # Read and parse cached data
    begin
      cached_data = JSON.parse(File.read(file_path))
      cached_data['vulns']
    rescue JSON::ParserError, StandardError => e
      Rails.logger.error("Cache read error: #{e.message}")
      # Delete corrupted cache file
      File.delete(file_path) if File.exist?(file_path)
      nil
    end
  end

  def cache_result(ecosystem, package_name, version, result)
    file_path = cache_file_path(ecosystem, package_name, version)

    begin
      # Store the result in the same format as OSV API response
      cache_data = {
        'vulns' => result,
        'cached_at' => Time.now.iso8601
      }

      File.write(file_path, JSON.pretty_generate(cache_data))
    rescue StandardError => e
      Rails.logger.error("Cache write error: #{e.message}")
    end
  end
end

DepValidatorTool.register!
