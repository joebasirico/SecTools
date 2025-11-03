# frozen_string_literal: true

require 'yaml'

# Security Rule Loader
# Loads and parses security scanning rules from YAML files
class SecurityRuleLoader
  RULES_PATH = Rails.root.join('config', 'security_rules')

  class << self
    # Load all security rules from YAML files
    def load_all_rules
      rules = {}

      Dir.glob(RULES_PATH.join('*.yml')).each do |file_path|
        rule_data = load_rule_file(file_path)
        next unless rule_data

        rule_id = File.basename(file_path, '.yml')
        rules[rule_id.to_sym] = parse_rule(rule_data)
      end

      rules
    end

    # Load a specific rule file
    def load_rule(rule_name)
      file_path = RULES_PATH.join("#{rule_name}.yml")
      return nil unless File.exist?(file_path)

      rule_data = load_rule_file(file_path)
      parse_rule(rule_data) if rule_data
    end

    # Validate a rule file structure
    def validate_rule(rule_data)
      errors = []

      errors << "Missing 'name' field" unless rule_data['name']
      errors << "Missing 'severity' field" unless rule_data['severity']
      errors << "Missing 'patterns' field" unless rule_data['patterns']

      if rule_data['severity'] && !valid_severity?(rule_data['severity'])
        errors << "Invalid severity: #{rule_data['severity']}. Must be CRITICAL, HIGH, MEDIUM, or LOW"
      end

      if rule_data['patterns']
        rule_data['patterns'].each_with_index do |pattern, index|
          errors << "Pattern #{index}: missing 'regex'" unless pattern['regex']
          errors << "Pattern #{index}: missing 'languages'" unless pattern['languages']
          errors << "Pattern #{index}: missing 'description'" unless pattern['description']
        end
      end

      errors
    end

    # List all available rule files
    def list_rules
      Dir.glob(RULES_PATH.join('*.yml')).map do |file_path|
        File.basename(file_path, '.yml')
      end.sort
    end

    # Get rule statistics
    def rule_stats
      rules = load_all_rules

      {
        total_rules: rules.length,
        total_patterns: rules.values.sum { |r| r[:patterns].length },
        by_severity: rules.group_by { |_, r| r[:severity] }
                          .transform_values(&:count),
        rules_list: rules.keys.map(&:to_s).sort
      }
    end

    private

    def load_rule_file(file_path)
      YAML.load_file(file_path)
    rescue StandardError => e
      Rails.logger.error("Failed to load rule file #{file_path}: #{e.message}")
      nil
    end

    def parse_rule(rule_data)
      {
        name: rule_data['name'],
        severity: rule_data['severity'],
        description: rule_data['description'],
        patterns: parse_patterns(rule_data['patterns']),
        references: rule_data['references'] || []
      }
    end

    def parse_patterns(patterns_data)
      return [] unless patterns_data

      patterns_data.map do |pattern|
        {
          regex: Regexp.new(pattern['regex']),
          languages: pattern['languages'].map(&:to_sym),
          desc: pattern['description'],
          example: pattern['example'],
          recommendation: pattern['recommendation']
        }
      end
    end

    def valid_severity?(severity)
      %w[CRITICAL HIGH MEDIUM LOW].include?(severity.upcase)
    end
  end
end
