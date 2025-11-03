# Adding New Security Tools to SecTools

This guide explains how to extend SecTools with new security testing tools.

## Architecture Overview

SecTools uses a modular, plugin-based architecture:

- **SecurityTool Concern**: Base module that all tools must include
- **ToolRegistry**: Auto-discovers and registers tools from `app/tools/`
- **Tool Classes**: Individual security testing tools

## Creating a New Tool

### Step 1: Create a Tool File

Create a new file in `app/tools/` following the naming convention `*_tool.rb`:

```bash
touch app/tools/my_security_tool.rb
```

### Step 2: Define Your Tool Class

```ruby
# frozen_string_literal: true

class MySecurityTool
  include SecurityTool

  # Configure tool metadata
  configure_tool(
    name: "My Security Tool",
    description: "Brief description of what this tool does",
    category: "Category Name"  # e.g., "Web Application Security", "Authentication Security"
  )

  # Define input fields
  input_field :input_name,
              type: :text,           # :text, :password, :url, :number
              label: "Input Label",
              placeholder: "Example input",
              required: true

  # Define supported output formats
  output_format :html, :json

  # Implement the main execution logic
  def execute(params)
    input = params[:input_name]

    # Your tool logic here
    result = perform_analysis(input)

    # Return a hash with results
    {
      input: input,
      result: result,
      recommendations: generate_recommendations(result)
    }
  end

  private

  def perform_analysis(input)
    # Implementation details
  end

  def generate_recommendations(result)
    # Generate actionable recommendations
  end
end

# Register the tool
MySecurityTool.register!
```

### Step 3: Tool Configuration Options

#### Input Field Types

- `:text` - Multi-line text area
- `:password` - Password field (masked input)
- `:url` - URL input
- `:number` - Numeric input
- `:email` - Email input

#### Input Field Options

```ruby
input_field :field_name,
            type: :text,
            label: "Display Label",
            placeholder: "Hint text",
            required: true,           # true/false
            min: 0,                   # Minimum value (for numbers)
            max: 100,                 # Maximum value (for numbers)
            pattern: "regex"          # Validation pattern
```

#### Categories

Use consistent category names:
- "Web Application Security"
- "Authentication Security"
- "Network Security"
- "Cryptography"
- "Code Analysis"
- "Vulnerability Assessment"

### Step 4: Return Format

The `execute` method should return a hash. The framework will automatically format it for display:

```ruby
{
  # Simple values
  score: 85,
  status: "Pass",

  # Arrays (rendered as lists)
  findings: ["Issue 1", "Issue 2"],

  # Nested hashes
  details: {
    severity: :high,
    description: "Detailed explanation"
  },

  # Arrays of hashes
  vulnerabilities: [
    { type: "XSS", severity: :high, description: "..." },
    { type: "CSRF", severity: :medium, description: "..." }
  ]
}
```

### Step 5: Severity Levels

For security findings, use standard severity levels:

```ruby
{
  severity: :critical  # or :high, :medium, :low, :info
}
```

These will be automatically styled with appropriate colors in the UI.

## Example Tools

### Simple Tool Example

```ruby
class PortScannerTool
  include SecurityTool

  configure_tool(
    name: "Port Scanner",
    description: "Scan for open ports on a target host",
    category: "Network Security"
  )

  input_field :host, type: :text, label: "Target Host", required: true
  input_field :ports, type: :text, label: "Ports (comma-separated)", placeholder: "80,443,8080"

  output_format :html, :json

  def execute(params)
    host = params[:host]
    ports = parse_ports(params[:ports])

    results = ports.map do |port|
      scan_port(host, port)
    end

    {
      host: host,
      scanned_ports: ports.length,
      open_ports: results.select { |r| r[:open] },
      closed_ports: results.reject { |r| r[:open] }
    }
  end

  private

  def parse_ports(port_string)
    # Parse comma-separated port list
  end

  def scan_port(host, port)
    # Implement port scanning logic
  end
end

PortScannerTool.register!
```

## Best Practices

### Security Considerations

1. **Input Validation**: Always validate and sanitize user input
2. **Rate Limiting**: Consider implementing rate limiting for tools that make external requests
3. **Timeouts**: Set appropriate timeouts for network operations
4. **Error Handling**: Use try/catch blocks and provide meaningful error messages
5. **Safe Defaults**: Use secure defaults for all configurations

```ruby
def execute(params)
  # Validate inputs
  errors = validate_params(params)
  raise "Validation failed: #{errors.join(', ')}" if errors.any?

  # Set timeouts
  Timeout.timeout(30) do
    # Tool logic
  end
rescue Timeout::Error
  { error: "Operation timed out after 30 seconds" }
rescue StandardError => e
  { error: "Error: #{e.message}" }
end
```

### Code Organization

1. Keep tool logic in private methods
2. Separate validation, execution, and formatting logic
3. Use descriptive method and variable names
4. Add comments for complex algorithms

### Testing

Create tests for your tools in `test/tools/`:

```ruby
require 'test_helper'

class MySecurityToolTest < ActiveSupport::TestCase
  test "should analyze input correctly" do
    tool = MySecurityTool.new
    result = tool.execute(input: "test")

    assert_not_nil result
    assert result.key?(:result)
  end

  test "should validate required params" do
    tool = MySecurityTool.new
    errors = tool.validate_params({})

    assert_not_empty errors
  end
end
```

## Tool Registry

Tools are automatically discovered and registered when the application starts. The `ToolRegistry` class:

- Scans `app/tools/` for files matching `*_tool.rb`
- Loads and registers each tool class
- Organizes tools by category
- Provides lookup by tool key

## Reloading Tools in Development

In development mode, tools are automatically reloaded when you modify them. If you add a new tool file, restart the Rails server:

```bash
bin/dev
```

## Advanced Features

### Custom Validation

Override the `validate_params` method for custom validation:

```ruby
def validate_params(params)
  errors = super(params)

  if params[:port] && (params[:port].to_i < 1 || params[:port].to_i > 65535)
    errors << "Port must be between 1 and 65535"
  end

  errors
end
```

### Custom Output Formatting

Override the `format_output` method for custom formatting:

```ruby
def format_output(result, format = :html)
  case format
  when :json
    result.to_json
  when :csv
    generate_csv(result)
  when :xml
    generate_xml(result)
  else
    super(result, format)
  end
end
```

### External Dependencies

Add gems to your Gemfile for external libraries:

```ruby
# Gemfile
gem 'nokogiri'  # For HTML/XML parsing
gem 'httparty'  # For HTTP requests
```

Then use in your tool:

```ruby
require 'httparty'

def fetch_data(url)
  response = HTTParty.get(url, timeout: 10)
  response.parsed_response
end
```

## Deployment

When deploying to production:

1. Ensure all tool dependencies are in the Gemfile
2. Run database migrations if you add models
3. Set appropriate environment variables
4. Configure CORS if tools make external requests
5. Review security implications of each tool

## Contributing

When contributing new tools:

1. Follow the coding style of existing tools
2. Include comprehensive error handling
3. Add tests for your tool
4. Document any special requirements or dependencies
5. Update this guide if you add new patterns or features

## Support

For questions or issues:
- Check existing tools in `app/tools/` for examples
- Review the `SecurityTool` concern in `app/models/concerns/security_tool.rb`
- Examine the `ToolRegistry` in `lib/tool_registry.rb`
