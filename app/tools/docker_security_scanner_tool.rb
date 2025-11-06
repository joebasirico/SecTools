# Docker/Container Security Scanner Tool
# Description: Scan Dockerfiles and container configurations for security issues

class DockerSecurityScannerTool
  include SecurityTool

  configure_tool(
    name: "Docker/Container Security Scanner",
    description: "Scan Dockerfiles and container configurations for security vulnerabilities, misconfigurations, and best practice violations. Checks for insecure base images, exposed secrets, privilege escalation, and more.",
    category: "Infrastructure Security"
  )

  input_field :input_type,
              type: :select,
              label: "Input Type",
              options: ["Dockerfile Content", "Docker Compose File"],
              required: true

  input_field :content,
              type: :text,
              label: "Dockerfile or Docker Compose Content",
              placeholder: "FROM ubuntu:20.04\nRUN apt-get update...",
              required: true

  output_format :html, :json

  def execute(params)
    input_type = params[:input_type]
    content = params[:content]&.strip

    return { error: "Content is required" } if content.blank?

    results = {
      input_type: input_type,
      vulnerabilities: [],
      warnings: [],
      best_practices: [],
      info: [],
      security_score: 100,
      risk_level: :low,
      recommendations: []
    }

    if input_type.include?("Dockerfile")
      scan_dockerfile(content, results)
    else
      scan_docker_compose(content, results)
    end

    # Calculate final score and risk
    calculate_security_score(results)

    results
  rescue StandardError => e
    { error: "Error scanning container configuration: #{e.message}" }
  end

  private

  def scan_dockerfile(content, results)
    lines = content.lines.map(&:strip)

    # Parse Dockerfile instructions
    instructions = parse_dockerfile(lines)

    # Security checks
    check_base_image(instructions, results)
    check_root_user(instructions, results)
    check_exposed_secrets(content, results)
    check_latest_tag(instructions, results)
    check_package_updates(instructions, results)
    check_exposed_ports(instructions, results)
    check_healthcheck(instructions, results)
    check_copy_vs_add(instructions, results)
    check_apt_get_practices(instructions, results)
    check_security_updates(instructions, results)
    check_setuid_setgid(instructions, results)
    check_shell_form(instructions, results)
  end

  def parse_dockerfile(lines)
    instructions = []
    current_instruction = nil

    lines.each do |line|
      next if line.empty? || line.start_with?('#')

      if line.match?(/^[A-Z]+/)
        current_instruction = { type: line.split.first, content: line, line: line }
        instructions << current_instruction
      elsif current_instruction
        current_instruction[:content] += " #{line}"
      end
    end

    instructions
  end

  def check_base_image(instructions, results)
    from_instructions = instructions.select { |i| i[:type] == 'FROM' }

    return if from_instructions.empty?

    from_instructions.each do |from_instr|
      image = from_instr[:content].split[1]

      # Check for unofficial or unknown base images
      official_prefixes = ['ubuntu', 'debian', 'alpine', 'centos', 'fedora', 'node', 'python', 'ruby', 'golang', 'openjdk', 'nginx', 'redis', 'postgres', 'mysql']

      is_official = official_prefixes.any? { |prefix| image.downcase.start_with?(prefix) }

      unless is_official
        results[:warnings] << {
          type: "Unofficial Base Image",
          message: "Using potentially unofficial base image: #{image}",
          line: from_instr[:line],
          recommendation: "Prefer official images from trusted sources"
        }
        results[:security_score] -= 10
      end

      # Check for distroless or minimal base images (good practice)
      if image.include?('distroless') || image.include?('scratch')
        results[:best_practices] << {
          type: "Minimal Base Image",
          message: "Using minimal/distroless base image (good practice)"
        }
      end
    end
  end

  def check_root_user(instructions, results)
    user_instructions = instructions.select { |i| i[:type] == 'USER' }

    if user_instructions.empty?
      results[:vulnerabilities] << {
        severity: :high,
        type: "Running as Root",
        message: "No USER instruction found - container will run as root",
        impact: "Privilege escalation risk if container is compromised",
        recommendation: "Add USER instruction to run as non-root user"
      }
      results[:security_score] -= 20
    else
      last_user = user_instructions.last[:content].split[1]
      if last_user == 'root' || last_user == '0'
        results[:vulnerabilities] << {
          severity: :high,
          type: "Running as Root",
          message: "Container explicitly runs as root user",
          recommendation: "Create and use a non-root user"
        }
        results[:security_score] -= 20
      end
    end
  end

  def check_exposed_secrets(content, results)
    secret_patterns = [
      { pattern: /password\s*=\s*[^\s]+/i, name: "Password" },
      { pattern: /api[_-]?key\s*=\s*[^\s]+/i, name: "API Key" },
      { pattern: /secret\s*=\s*[^\s]+/i, name: "Secret" },
      { pattern: /token\s*=\s*[^\s]+/i, name: "Token" },
      { pattern: /AKIA[0-9A-Z]{16}/, name: "AWS Access Key" },
      { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, name: "Private Key" }
    ]

    secret_patterns.each do |pattern_info|
      if content.match?(pattern_info[:pattern])
        results[:vulnerabilities] << {
          severity: :critical,
          type: "Hardcoded Secret",
          message: "Potential #{pattern_info[:name]} found in Dockerfile",
          impact: "Credentials exposed in image layers",
          recommendation: "Use environment variables or secrets management"
        }
        results[:security_score] -= 30
      end
    end
  end

  def check_latest_tag(instructions, results)
    from_instructions = instructions.select { |i| i[:type] == 'FROM' }

    from_instructions.each do |from_instr|
      image = from_instr[:content].split[1]

      if image.end_with?(':latest') || !image.include?(':')
        results[:warnings] << {
          type: "Using 'latest' Tag",
          message: "Base image uses 'latest' tag or no tag: #{image}",
          line: from_instr[:line],
          impact: "Unpredictable builds, harder to reproduce issues",
          recommendation: "Pin to specific version tags"
        }
        results[:security_score] -= 10
      end
    end
  end

  def check_package_updates(instructions, results)
    run_instructions = instructions.select { |i| i[:type] == 'RUN' }

    has_update = run_instructions.any? { |r| r[:content] =~ /apt-get update|yum update|apk update/ }
    has_upgrade = run_instructions.any? { |r| r[:content] =~ /apt-get upgrade|yum upgrade|apk upgrade/ }

    if has_update && !has_upgrade
      results[:info] << {
        type: "Package Update Without Upgrade",
        message: "Updates package lists but doesn't upgrade packages",
        recommendation: "Consider running upgrade to get security patches"
      }
    end

    # Check if update and install are in the same RUN command
    run_instructions.each do |run_instr|
      content = run_instr[:content]

      if content.include?('apt-get') && content.include?('update')
        unless content.include?('install')
          results[:warnings] << {
            type: "Separate Update Command",
            message: "apt-get update in separate RUN command",
            line: run_instr[:line],
            impact: "Creates unnecessary image layers and cache issues",
            recommendation: "Combine update and install in same RUN command"
          }
          results[:security_score] -= 5
        end
      end
    end
  end

  def check_exposed_ports(instructions, results)
    expose_instructions = instructions.select { |i| i[:type] == 'EXPOSE' }

    dangerous_ports = {
      '22' => 'SSH',
      '23' => 'Telnet',
      '3389' => 'RDP',
      '5432' => 'PostgreSQL',
      '3306' => 'MySQL',
      '27017' => 'MongoDB',
      '6379' => 'Redis'
    }

    expose_instructions.each do |expose_instr|
      ports = expose_instr[:content].split[1..-1]

      ports.each do |port|
        port_num = port.split('/').first

        if dangerous_ports.key?(port_num)
          results[:warnings] << {
            type: "Sensitive Port Exposed",
            message: "Exposing #{dangerous_ports[port_num]} port #{port_num}",
            line: expose_instr[:line],
            recommendation: "Ensure this service is not exposed publicly"
          }
          results[:security_score] -= 5
        end
      end
    end
  end

  def check_healthcheck(instructions, results)
    has_healthcheck = instructions.any? { |i| i[:type] == 'HEALTHCHECK' }

    unless has_healthcheck
      results[:best_practices] << {
        type: "Missing HEALTHCHECK",
        message: "No HEALTHCHECK instruction defined",
        recommendation: "Add HEALTHCHECK for better container monitoring"
      }
    end
  end

  def check_copy_vs_add(instructions, results)
    add_instructions = instructions.select { |i| i[:type] == 'ADD' }

    add_instructions.each do |add_instr|
      # ADD should only be used for tar files or URLs
      src = add_instr[:content].split[1]

      unless src.end_with?('.tar', '.tar.gz', '.tgz', '.tar.bz2') || src.start_with?('http')
        results[:warnings] << {
          type: "Use COPY Instead of ADD",
          message: "Using ADD for simple file copy",
          line: add_instr[:line],
          recommendation: "Use COPY for simple file copying, ADD only for tar extraction"
        }
        results[:security_score] -= 3
      end
    end
  end

  def check_apt_get_practices(instructions, results)
    run_instructions = instructions.select { |i| i[:type] == 'RUN' }

    run_instructions.each do |run_instr|
      content = run_instr[:content]

      # Check for missing -y flag
      if content.include?('apt-get install') && !content.include?('-y') && !content.include?('--yes')
        results[:warnings] << {
          type: "Missing -y Flag",
          message: "apt-get install without -y flag",
          line: run_instr[:line],
          impact: "Build may hang waiting for user input"
        }
      end

      # Check for missing --no-install-recommends
      if content.include?('apt-get install') && !content.include?('--no-install-recommends')
        results[:best_practices] << {
          type: "Consider --no-install-recommends",
          message: "apt-get install without --no-install-recommends",
          recommendation: "Use --no-install-recommends to reduce image size"
        }
      end

      # Check for missing rm -rf /var/lib/apt/lists/*
      if content.include?('apt-get install') && !content.include?('rm -rf /var/lib/apt/lists')
        results[:best_practices] << {
          type: "Apt Cache Not Cleaned",
          message: "apt-get install without cleaning cache",
          recommendation: "Add '&& rm -rf /var/lib/apt/lists/*' to reduce image size"
        }
      end
    end
  end

  def check_security_updates(instructions, results)
    run_instructions = instructions.select { |i| i[:type] == 'RUN' }

    has_security_updates = run_instructions.any? do |r|
      r[:content].include?('security') || r[:content].include?('upgrade')
    end

    if has_security_updates
      results[:best_practices] << {
        type: "Security Updates Applied",
        message: "Dockerfile includes security updates (good practice)"
      }
    end
  end

  def check_setuid_setgid(instructions, results)
    run_instructions = instructions.select { |i| i[:type] == 'RUN' }

    run_instructions.each do |run_instr|
      if run_instr[:content].match?(/chmod.*[4567]\d{3}/)
        results[:vulnerabilities] << {
          severity: :medium,
          type: "SETUID/SETGID Permission",
          message: "Setting SETUID/SETGID bits on files",
          line: run_instr[:line],
          impact: "Could allow privilege escalation",
          recommendation: "Avoid SETUID/SETGID unless absolutely necessary"
        }
        results[:security_score] -= 15
      end
    end
  end

  def check_shell_form(instructions, results)
    # CMD and ENTRYPOINT should use exec form, not shell form
    cmd_instructions = instructions.select { |i| i[:type] == 'CMD' || i[:type] == 'ENTRYPOINT' }

    cmd_instructions.each do |cmd_instr|
      content = cmd_instr[:content]

      # Shell form doesn't start with [
      unless content.include?('[')
        results[:warnings] << {
          type: "Shell Form Used",
          message: "#{cmd_instr[:type]} uses shell form instead of exec form",
          line: cmd_instr[:line],
          impact: "Process will run as PID != 1, signal handling issues",
          recommendation: "Use exec form: #{cmd_instr[:type]} [\"executable\", \"param\"]"
        }
        results[:security_score] -= 5
      end
    end
  end

  def scan_docker_compose(content, results)
    begin
      # Parse YAML
      compose = YAML.load(content)

      unless compose.is_a?(Hash) && compose['services']
        return results[:error] = "Invalid docker-compose.yml format"
      end

      services = compose['services']

      services.each do |service_name, service_config|
        check_privileged_mode(service_name, service_config, results)
        check_volume_mounts(service_name, service_config, results)
        check_network_mode(service_name, service_config, results)
        check_capabilities(service_name, service_config, results)
        check_security_opt(service_name, service_config, results)
      end

    rescue Psych::SyntaxError => e
      results[:error] = "YAML parse error: #{e.message}"
    end
  end

  def check_privileged_mode(service_name, config, results)
    if config['privileged'] == true
      results[:vulnerabilities] << {
        severity: :critical,
        type: "Privileged Mode",
        message: "Service '#{service_name}' runs in privileged mode",
        impact: "Container has full access to host system",
        recommendation: "Remove privileged mode unless absolutely necessary"
      }
      results[:security_score] -= 40
    end
  end

  def check_volume_mounts(service_name, config, results)
    volumes = config['volumes'] || []

    dangerous_mounts = [
      { path: '/var/run/docker.sock', risk: :critical, message: "Docker socket mounted - full control over Docker daemon" },
      { path: '/etc', risk: :high, message: "System /etc directory mounted" },
      { path: '/proc', risk: :high, message: "Process filesystem mounted" },
      { path: '/sys', risk: :high, message: "System filesystem mounted" },
      { path: '/', risk: :critical, message: "Root filesystem mounted" }
    ]

    volumes.each do |volume|
      mount_path = volume.is_a?(String) ? volume.split(':')[1] : nil
      next unless mount_path

      dangerous_mounts.each do |danger|
        if mount_path.start_with?(danger[:path])
          results[:vulnerabilities] << {
            severity: danger[:risk],
            type: "Dangerous Volume Mount",
            message: "Service '#{service_name}': #{danger[:message]}",
            mount: volume,
            recommendation: "Avoid mounting sensitive host paths"
          }
          results[:security_score] -= (danger[:risk] == :critical ? 30 : 20)
        end
      end
    end
  end

  def check_network_mode(service_name, config, results)
    if config['network_mode'] == 'host'
      results[:vulnerabilities] << {
        severity: :high,
        type: "Host Network Mode",
        message: "Service '#{service_name}' uses host network mode",
        impact: "Container shares host network stack - no network isolation",
        recommendation: "Use bridge network mode for better isolation"
      }
      results[:security_score] -= 20
    end
  end

  def check_capabilities(service_name, config, results)
    cap_add = config['cap_add'] || []

    dangerous_capabilities = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH']

    cap_add.each do |capability|
      if dangerous_capabilities.include?(capability)
        results[:warnings] << {
          type: "Dangerous Capability Added",
          message: "Service '#{service_name}' adds capability: #{capability}",
          impact: "Increases attack surface",
          recommendation: "Only add necessary capabilities"
        }
        results[:security_score] -= 10
      end
    end
  end

  def check_security_opt(service_name, config, results)
    security_opt = config['security_opt'] || []

    if security_opt.include?('apparmor:unconfined') || security_opt.include?('seccomp:unconfined')
      results[:vulnerabilities] << {
        severity: :high,
        type: "Security Features Disabled",
        message: "Service '#{service_name}' disables AppArmor or Seccomp",
        impact: "Removes important security protections",
        recommendation: "Remove unconfined security options"
      }
      results[:security_score] -= 25
    end
  end

  def calculate_security_score(results)
    # Ensure score doesn't go below 0
    results[:security_score] = [results[:security_score], 0].max

    # Calculate risk level
    results[:risk_level] = if results[:vulnerabilities].any? { |v| v[:severity] == :critical }
                            :critical
                          elsif results[:vulnerabilities].any? { |v| v[:severity] == :high }
                            :high
                          elsif results[:vulnerabilities].any? { |v| v[:severity] == :medium }
                            :medium
                          elsif results[:warnings].any?
                            :low
                          else
                            :secure
                          end

    # Generate grade
    results[:grade] = case results[:security_score]
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
    recommendations = [
      "Use specific version tags instead of 'latest'",
      "Run containers as non-root user with USER instruction",
      "Minimize image size by using multi-stage builds",
      "Scan images regularly with container security tools",
      "Implement least privilege principle for capabilities",
      "Use read-only root filesystem where possible",
      "Sign and verify images before deployment",
      "Regularly update base images for security patches"
    ]

    if results[:vulnerabilities].any?
      recommendations.unshift("CRITICAL: Fix all identified vulnerabilities before deployment")
    end

    recommendations
  end
end

DockerSecurityScannerTool.register!
