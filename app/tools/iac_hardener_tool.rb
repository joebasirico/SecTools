# frozen_string_literal: true

require "json"
require "yaml"
require "set"
require "zip"
require "tempfile"

# Infrastructure-as-Code Hardener
# Audits Terraform, CloudFormation, and Kubernetes manifests for risky defaults
class IacHardenerTool
  include SecurityTool

  configure_tool(
    name: "Infrastructure-as-Code Hardener",
    description: "Analyze Terraform, CloudFormation, and Kubernetes IaC for insecure configurations",
    category: "Cloud Security",
  )

  input_field :iac_file,
              type: :file,
              label: "IaC File or ZIP Archive",
              placeholder: "Upload .tf, .yaml, .json, or .zip bundle",
              required: true,
              accept: ".tf,.tf.json,.yaml,.yml,.json,.template,.zip"

  input_field :deep_scan,
              type: :checkbox,
              label: "Enable deeper heuristics (may increase false positives)",
              placeholder: "Toggle additional pattern checks",
              required: false

  output_format :html, :json

  SUPPORTED_TYPES = [:terraform, :kubernetes, :cloudformation].freeze unless defined?(SUPPORTED_TYPES)

  def execute(params)
    file_content = params[:iac_file]
    deep_scan = params[:deep_scan] == "1" || params[:deep_scan] == true

    if file_content.blank?
      return {
        error: "No IaC file provided",
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      }
    end

    files = extract_files(file_content, params[:filename])

    if files.empty?
      return {
        error: "No scannable IaC files found",
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      }
    end

    all_findings = []
    file_stats = Hash.new(0)
    unsupported = []

    files.each do |file|
      type = detect_iac_type(file[:name], file[:content])
      file_stats[type] += 1 if SUPPORTED_TYPES.include?(type)

      findings = case type
                 when :terraform
                   analyze_terraform(file[:name], file[:content], deep_scan)
                 when :kubernetes
                   analyze_kubernetes(file[:name], file[:content], deep_scan)
                 when :cloudformation
                   analyze_cloudformation(file[:name], file[:content], deep_scan)
                 else
                   unsupported << file[:name]
                   []
                 end
      all_findings.concat(findings)
    end

    summary = calculate_summary(all_findings)
    recommendations = generate_recommendations(all_findings)

    {
      files_analyzed: files.length,
      file_breakdown: file_stats,
      unsupported_files: unsupported,
      findings: all_findings.sort_by { |f| -severity_rank(f[:severity]) },
      recommendations: recommendations,
      summary: summary,
      scanned_at: Time.now.utc,
    }
  rescue StandardError => e
    {
      error: "Failed to analyze IaC files: #{e.message}",
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    }
  end

  private

  def extract_files(content, original_filename = nil)
    if zip_file?(content)
      extract_zip_files(content)
    else
      filename = original_filename || "uploaded_file"
      [{ name: filename, content: content }]
    end
  end

  def zip_file?(content)
    content.start_with?("PK")
  end

  def extract_zip_files(zip_content)
    files = []

    Tempfile.create(["iac_upload", ".zip"]) do |temp_file|
      temp_file.binmode
      temp_file.write(zip_content)
      temp_file.rewind

      Zip::File.open(temp_file.path) do |zip_file|
        zip_file.each do |entry|
          next if entry.directory?
          next unless iac_extension?(entry.name)
          next if entry.size > 5_242_880 # 5 MB limit

          files << {
            name: entry.name,
            content: entry.get_input_stream.read,
          }
        end
      end
    end

    files
  rescue StandardError => e
    []
  end

  def iac_extension?(filename)
    filename.downcase.end_with?(".tf", ".tf.json", ".yaml", ".yml", ".json", ".template")
  end

  def detect_iac_type(filename, content)
    downcase_name = filename.to_s.downcase

    return :terraform if downcase_name.end_with?(".tf", ".tf.json")
    return :cloudformation if downcase_name.end_with?(".template")

    parsed_docs = parse_yaml_or_json(content)

    Array(parsed_docs).each do |doc|
      next unless doc.is_a?(Hash)

      if terraform_json?(doc)
        return :terraform
      elsif kubernetes_manifest?(doc)
        return :kubernetes
      elsif cloudformation_template?(doc)
        return :cloudformation
      end
    end

    :unknown
  end

  def parse_yaml_or_json(content)
    begin
      parsed = JSON.parse(content)
      return parsed.is_a?(Array) ? parsed : [parsed]
    rescue JSON::ParserError
      docs = []
      YAML.safe_load_stream(content, aliases: true) { |doc| docs << doc }
      return docs
    end
  rescue Psych::SyntaxError
    []
  end

  def terraform_json?(doc)
    doc.key?("resource") || doc.key?("provider") || doc.key?("terraform")
  end

  def kubernetes_manifest?(doc)
    doc.key?("apiVersion") && doc.key?("kind") && doc.key?("metadata")
  end

  def cloudformation_template?(doc)
    doc.key?("AWSTemplateFormatVersion") || doc.key?("Resources")
  end

  def analyze_terraform(filename, content, deep_scan)
    findings = []
    lines = content.split("\n")

    if content.match?(/resource\s+"aws_security_group"/) || content.match?(/resource\s+"google_compute_firewall"/)
      insecure_cidr_regex = /["']0\.0\.0\.0\/0["']/
      lines.each_with_index do |line, index|
        next unless line.match?(insecure_cidr_regex)

        findings << build_finding(
          severity: "CRITICAL",
          issue: "Unrestricted network access",
          message: "CIDR block 0.0.0.0/0 detected in security group or firewall rule.",
          recommendation: "Restrict ingress CIDR ranges to trusted networks or use security group references.",
          file: filename,
          line: index + 1,
          resource: "network_rule",
        )
      end
    end

    if content.match?(/resource\s+"aws_s3_bucket"/)
      findings.concat check_terraform_s3(filename, lines)
    end

    if content.match?(/resource\s+"aws_db_instance"/) && content.match?(/publicly_accessible\s*=\s*true/)
      findings << build_regex_finding(
        filename,
        lines,
        /publicly_accessible\s*=\s*true/,
        severity: "HIGH",
        issue: "Public database instance",
        message: "RDS instance marked as publicly accessible.",
        recommendation: "Set publicly_accessible to false and place the database in private subnets.",
        resource: "aws_db_instance",
      )
    end

    if content.match?(/resource\s+"aws_iam_policy"/) || content.match?(/data\s+"aws_iam_policy_document"/)
      findings.concat check_terraform_iam(filename, lines)
    end

    if deep_scan && content.match?(/kms_key_id\s*=\s*null|server_side_encryption_configuration\W+/).nil?
      findings << build_finding(
        severity: "LOW",
        issue: "Encryption not enforced",
        message: "Unable to find server-side encryption settings for storage resources.",
        recommendation: "Review S3 buckets, EBS volumes, and RDS instances to ensure encryption is configured.",
        file: filename,
        resource: "encryption",
      )
    end

    findings
  end

  def check_terraform_s3(filename, lines)
    findings = []

    if (match = find_line(lines, /acl\s*=\s*["']public-read(-write)?["']/))
      findings << build_finding(
        severity: "HIGH",
        issue: "Public S3 bucket ACL",
        message: "Bucket ACL allows public read/write access.",
        recommendation: "Use private ACLs and control access through IAM policies or bucket policies.",
        file: filename,
        line: match[:line],
        resource: "aws_s3_bucket",
      )
    end

    unless lines.any? { |line| line.match?(/server_side_encryption_configuration|bucket_encryption/) }
      findings << build_finding(
        severity: "MEDIUM",
        issue: "S3 bucket missing encryption block",
        message: "No server-side encryption configuration block detected.",
        recommendation: "Add server_side_encryption_configuration to enforce encryption at rest.",
        file: filename,
        resource: "aws_s3_bucket",
      )
    end

    findings
  end

  def check_terraform_iam(filename, lines)
    findings = []

    wildcard_regex = /"Action"\s*:\s*"\*".*"Resource"\s*:\s*"\*"/
    if lines.join(" ").match?(wildcard_regex)
      findings << build_finding(
        severity: "CRITICAL",
        issue: "Wildcard IAM policy",
        message: "IAM policy allows '*' on both Action and Resource.",
        recommendation: "Restrict IAM actions and resources to least privilege permissions.",
        file: filename,
        resource: "iam_policy",
      )
    end

    if (match = find_line(lines, /Effect\s*=\s*"Allow".*Principal\s*=\s*"*"|Effect\s*"\s*:\s*"Allow".*"Principal"\s*:\s*"*"/))
      findings << build_finding(
        severity: "HIGH",
        issue: "IAM policy with wildcard principal",
        message: "Policy statement grants access to any principal.",
        recommendation: "Limit principals to specific AWS accounts, roles, or federated identities.",
        file: filename,
        line: match[:line],
        resource: "iam_policy",
      )
    end

    findings
  end

  def analyze_kubernetes(filename, content, _deep_scan)
    findings = []
    documents = []

    begin
      documents = parse_yaml_or_json(content)
    rescue StandardError
      return findings
    end

    Array(documents).each do |doc|
      next unless doc.is_a?(Hash)

      kind = doc["kind"].to_s
      metadata_name = doc.dig("metadata", "name")
      pod_spec = extract_pod_spec(doc)
      next unless pod_spec

      containers = Array(pod_spec["containers"]) + Array(pod_spec["initContainers"])
      containers.compact.each do |container|
        findings.concat analyze_container_security(filename, kind, metadata_name, container)
      end

      if pod_spec["hostNetwork"]
        findings << build_k8s_finding(
          filename,
          kind,
          metadata_name,
          "HIGH",
          "Host networking enabled",
          "Pod shares node network namespace (hostNetwork: true).",
          "Disable hostNetwork unless absolutely necessary; configure NetworkPolicies instead.",
        )
      end

      if pod_spec["hostPID"] || pod_spec["hostIPC"]
        findings << build_k8s_finding(
          filename,
          kind,
          metadata_name,
          "HIGH",
          "Host namespace access",
          "Pod has access to host PID/IPC namespaces.",
          "Remove hostPID/hostIPC flags and rely on container namespaces.",
        )
      end

      if pod_spec["serviceAccountName"].nil? && pod_spec["automountServiceAccountToken"] != false
        findings << build_k8s_finding(
          filename,
          kind,
          metadata_name,
          "MEDIUM",
          "Default service account in use",
          "Pod uses the default service account with potential cluster-wide permissions.",
          "Create a dedicated service account scoped with RBAC and disable automountServiceAccountToken when not required.",
        )
      end
    end

    findings
  end

  def analyze_container_security(filename, kind, name, container)
    findings = []
    security_context = container["securityContext"] || {}

    if security_context["privileged"]
      findings << build_k8s_finding(
        filename,
        kind,
        name,
        "CRITICAL",
        "Privileged container",
        "Container '#{container['name']}' runs with privileged=true.",
        "Remove privileged mode and grant only required capabilities.",
      )
    end

    if security_context["allowPrivilegeEscalation"]
      findings << build_k8s_finding(
        filename,
        kind,
        name,
        "HIGH",
        "Privilege escalation allowed",
        "Container '#{container['name']}' permits privilege escalation.",
        "Set allowPrivilegeEscalation to false unless absolutely necessary.",
      )
    end

    unless security_context["runAsNonRoot"]
      findings << build_k8s_finding(
        filename,
        kind,
        name,
        "MEDIUM",
        "runAsNonRoot missing",
        "Container '#{container['name']}' does not set runAsNonRoot: true.",
        "Set runAsNonRoot and specify a non-root runAsUser to prevent root execution.",
      )
    end

    capabilities = security_context.dig("capabilities", "add")
    if Array(capabilities).include?("SYS_ADMIN")
      findings << build_k8s_finding(
        filename,
        kind,
        name,
        "HIGH",
        "Dangerous capability SYS_ADMIN",
        "Container '#{container['name']}' adds the SYS_ADMIN capability.",
        "Remove SYS_ADMIN and restrict capabilities to the minimum required set.",
      )
    end

    findings
  end

  def extract_pod_spec(doc)
    return doc["spec"] if %w[Pod DaemonSet Job CronJob StatefulSet ReplicaSet Deployment].include?(doc["kind"].to_s)

    template_spec = doc.dig("spec", "template", "spec")
    template_spec if template_spec.is_a?(Hash)
  end

  def analyze_cloudformation(filename, content, _deep_scan)
    findings = []
    documents = []

    begin
      documents = parse_yaml_or_json(content)
    rescue StandardError
      return findings
    end

    Array(documents).each do |doc|
      next unless doc.is_a?(Hash)

      resources = doc["Resources"]
      next unless resources.is_a?(Hash)

      resources.each do |logical_id, resource|
        next unless resource.is_a?(Hash)

        type = resource["Type"]
        properties = resource["Properties"] || {}

        case type
        when "AWS::S3::Bucket"
          if %w[PublicRead PublicReadWrite AuthenticatedRead].include?(properties["AccessControl"])
            findings << build_cf_finding(
              filename,
              logical_id,
              "HIGH",
              "Public S3 bucket ACL",
              "Bucket '#{logical_id}' uses AccessControl '#{properties['AccessControl']}'.",
              "Use private buckets and control access via IAM policies or CloudFront origin access identities.",
            )
          end

          unless properties.key?("BucketEncryption")
            findings << build_cf_finding(
              filename,
              logical_id,
              "MEDIUM",
              "Bucket encryption missing",
              "Bucket '#{logical_id}' does not configure BucketEncryption.",
              "Add BucketEncryption with SSE-S3 or SSE-KMS to enforce encryption at rest.",
            )
          end
        when "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"
          statements = Array(properties.dig("PolicyDocument", "Statement"))
          statements.each do |statement|
            next unless statement.is_a?(Hash)

            if wildcard?(statement["Action"]) && wildcard?(statement["Resource"])
              findings << build_cf_finding(
                filename,
                logical_id,
                "CRITICAL",
                "Wildcard IAM permissions",
                "Policy '#{logical_id}' allows Action '*' on Resource '*'.",
                "Scope actions and resources to the minimum required set.",
              )
            end

            if wildcard?(statement["Principal"])
              findings << build_cf_finding(
                filename,
                logical_id,
                "HIGH",
                "Wildcard principal in IAM policy",
                "Policy '#{logical_id}' trusts any principal.",
                "Restrict trust relationships to specific AWS accounts, roles, or services.",
              )
            end
          end
        when "AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"
          ingress_rules = Array(properties["SecurityGroupIngress"])
          ingress_rules = [properties] if type == "AWS::EC2::SecurityGroupIngress"

          ingress_rules.each do |rule|
            next unless rule.is_a?(Hash)

            if ["0.0.0.0/0", "::/0"].include?(rule["CidrIp"]) || ["0.0.0.0/0", "::/0"].include?(rule["CidrIpv6"])
              findings << build_cf_finding(
                filename,
                logical_id,
                "CRITICAL",
                "Security group open to the world",
                "Security group '#{logical_id}' allows ingress from #{rule['CidrIp'] || rule['CidrIpv6']}.",
                "Restrict CIDR ranges or reference security groups for inbound access.",
              )
            end
          end
        end
      end
    end

    findings
  end

  def wildcard?(value)
    case value
    when String
      value.strip == "*" || value.strip == "*:*"
    when Array
      value.any? { |v| wildcard?(v) }
    when Hash
      value.values.any? { |v| wildcard?(v) }
    else
      false
    end
  end

  def build_finding(severity:, issue:, message:, recommendation:, file:, resource:, line: nil)
    {
      severity: severity,
      issue: issue,
      message: message,
      recommendation: recommendation,
      file: file,
      resource: resource,
      line: line,
    }
  end

  def build_regex_finding(filename, lines, regex, severity:, issue:, message:, recommendation:, resource:)
    match = find_line(lines, regex)
    build_finding(
      severity: severity,
      issue: issue,
      message: message,
      recommendation: recommendation,
      file: filename,
      resource: resource,
      line: match ? match[:line] : nil,
    )
  end

  def find_line(lines, regex)
    lines.each_with_index do |line, index|
      return { line: index + 1, content: line.strip } if line.match?(regex)
    end
    nil
  end

  def build_k8s_finding(filename, kind, name, severity, issue, message, recommendation)
    {
      severity: severity,
      issue: issue,
      message: message,
      recommendation: recommendation,
      file: filename,
      resource: "#{kind}/#{name}",
    }
  end

  def build_cf_finding(filename, logical_id, severity, issue, message, recommendation)
    {
      severity: severity,
      issue: issue,
      message: message,
      recommendation: recommendation,
      file: filename,
      resource: logical_id,
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

  def generate_recommendations(findings)
    recs = findings.map { |finding| finding[:recommendation] }
    recs.compact.uniq
  end
end

# ============================================================================
# TOOL REGISTRATION
# ============================================================================
IacHardenerTool.register!
