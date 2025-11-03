# frozen_string_literal: true

# Auto-discover and register security tools
Rails.application.config.after_initialize do
  ToolRegistry.discover_tools!
end
