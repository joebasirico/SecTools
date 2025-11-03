# frozen_string_literal: true

# Base module for all security testing tools
# Include this concern in any class that implements a security tool
module SecurityTool
  extend ActiveSupport::Concern

  included do
    # Class-level attributes for tool metadata
    class_attribute :tool_name, :tool_description, :tool_category, :tool_inputs, :tool_outputs
  end

  class_methods do
    # DSL for defining tool metadata
    def configure_tool(name:, description:, category:)
      self.tool_name = name
      self.tool_description = description
      self.tool_category = category
      self.tool_inputs = []
      self.tool_outputs = []
    end

    # Define input fields for the tool
    def input_field(name, type:, label:, placeholder: nil, required: true, **options)
      self.tool_inputs << {
        name: name,
        type: type,
        label: label,
        placeholder: placeholder,
        required: required,
        options: options
      }
    end

    # Define output format
    def output_format(*formats)
      self.tool_outputs = formats
    end

    # Register this tool in the tool registry
    def register!
      ToolRegistry.register(self)
    end
  end

  # Instance method that must be implemented by each tool
  def execute(params)
    raise NotImplementedError, "#{self.class.name} must implement #execute method"
  end

  # Validate input parameters
  def validate_params(params)
    errors = []
    self.class.tool_inputs.each do |input|
      if input[:required] && params[input[:name]].blank?
        errors << "#{input[:label]} is required"
      end
    end
    errors
  end

  # Format the output
  def format_output(result, format = :html)
    case format
    when :json
      result.to_json
    when :text
      result.to_s
    else
      result
    end
  end
end
