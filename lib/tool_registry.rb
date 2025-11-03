# frozen_string_literal: true

# Registry for all security tools
# Automatically discovers and registers tools from app/tools directory
class ToolRegistry
  @tools = {}

  class << self
    attr_reader :tools

    # Register a tool class
    def register(tool_class)
      key = tool_class.name.underscore.gsub('_tool', '')
      @tools[key] = tool_class
    end

    # Get a tool by key
    def get(key)
      # If tools haven't been loaded yet, discover them
      discover_tools! if @tools.empty?
      @tools[key]
    end

    # Get all tools
    def all
      # If tools haven't been loaded yet, discover them
      discover_tools! if @tools.empty?
      @tools.values
    end

    # Get tools by category
    def by_category(category)
      @tools.values.select { |tool| tool.tool_category == category }
    end

    # Get all categories
    def categories
      # If tools haven't been loaded yet, discover them
      discover_tools! if @tools.empty?
      @tools.values.map(&:tool_category).uniq.sort
    end

    # Auto-discover and load tools from app/tools directory
    def discover_tools!
      tools_path = Rails.root.join('app', 'tools')
      return unless Dir.exist?(tools_path)

      Dir[tools_path.join('**', '*_tool.rb')].sort.each do |file|
        load file
      end
    end

    # Clear all registered tools (useful for testing)
    def clear!
      @tools = {}
    end
  end
end
