# SecTools - Security Testing Tools Platform

A modular, extensible Ruby on Rails application for application and product security testing. SecTools provides a web-based interface for various security testing tools with a plugin architecture that makes adding new tools simple.

## Features

- **Modular Architecture**: Easy-to-extend plugin system for security tools
- **Auto-Discovery**: Tools are automatically discovered and registered
- **Category Organization**: Tools organized by security domain
- **Rich UI**: Modern, responsive interface built with Tailwind CSS
- **Flexible Input/Output**: Support for multiple input types and output formats
- **Built-in Tools**:
  - Password Strength Analyzer
  - JWT Token Decoder
  - HTTP Security Headers Analyzer
  - SQL Injection Pattern Detector

## Requirements

- Ruby 3.4.3 or higher
- Rails 8.0.3 or higher
- SQLite3 (default) or PostgreSQL/MySQL

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd SecTools
```

2. Install dependencies:
```bash
bundle install
```

3. Setup the database:
```bash
rails db:create db:migrate
```

4. Start the development server:
```bash
bin/dev
```

5. Visit http://localhost:3000

## Architecture

### Core Components

**SecurityTool Concern** (`app/models/concerns/security_tool.rb`)
- Base module that all security tools must include
- Provides DSL for defining tool metadata
- Handles input validation and output formatting

**ToolRegistry** (`lib/tool_registry.rb`)
- Auto-discovers tools from `app/tools/` directory
- Maintains registry of available tools
- Provides lookup and filtering capabilities

**Tools** (`app/tools/`)
- Individual security testing tool implementations
- Each tool is a standalone class that includes SecurityTool
- Automatically registered on application startup

### Request Flow

1. User visits homepage → displays all available tools by category
2. User selects a tool → shows tool interface with input fields
3. User submits form → tool executes analysis
4. Results displayed → formatted output with recommendations

## Adding New Tools

Create a new file in `app/tools/`:

```ruby
# app/tools/my_tool.rb
class MyTool
  include SecurityTool

  configure_tool(
    name: "My Security Tool",
    description: "What this tool does",
    category: "Web Application Security"
  )

  input_field :target, type: :text, label: "Target", required: true
  output_format :html, :json

  def execute(params)
    # Your analysis logic here
    { result: "Analysis complete" }
  end
end

MyTool.register!
```

See [ADDING_TOOLS.md](ADDING_TOOLS.md) for comprehensive documentation.

## Available Tools

### Password Strength Analyzer
Analyzes password strength using multiple criteria including length, character diversity, entropy calculation, and common password detection.

**Category**: Authentication Security
**Input**: Password to test

### JWT Token Decoder
Decodes and analyzes JSON Web Tokens, extracting header and payload information with security warnings.

**Category**: Authentication Security
**Input**: JWT token

### HTTP Security Headers Analyzer
Analyzes security-related HTTP headers of websites and provides security scoring and recommendations.

**Category**: Web Application Security
**Input**: Website URL

### SQL Injection Pattern Detector
Detects common SQL injection patterns in input strings including classic OR injection, UNION queries, and time-based attacks.

**Category**: Web Application Security
**Input**: String to analyze

## Development

### Running Tests

```bash
rails test
```

### Code Quality

```bash
bin/rubocop
```

### Security Scanning

```bash
bin/brakeman
```

## Project Structure

```
SecTools/
├── app/
│   ├── controllers/
│   │   ├── home_controller.rb      # Homepage with tool listings
│   │   └── tools_controller.rb     # Tool execution interface
│   ├── models/
│   │   └── concerns/
│   │       └── security_tool.rb    # Base tool module
│   ├── tools/                      # Security tool implementations
│   │   ├── password_strength_tool.rb
│   │   ├── jwt_decoder_tool.rb
│   │   ├── http_header_analyzer_tool.rb
│   │   └── sql_injection_detector_tool.rb
│   └── views/
│       ├── home/
│       │   └── index.html.erb      # Tool listings
│       └── tools/
│           └── show.html.erb       # Tool interface
├── lib/
│   └── tool_registry.rb            # Tool auto-discovery
├── config/
│   └── initializers/
│       └── tool_registry.rb        # Registry initialization
├── ADDING_TOOLS.md                 # Tool development guide
└── README.md                       # This file
```

## Security Considerations

This application is designed for authorized security testing and educational purposes. When using these tools:

- Only test systems you own or have explicit permission to test
- Be aware of rate limiting and respectful of target systems
- Some tools make external network requests
- Never use for malicious purposes
- Follow responsible disclosure practices

## Configuration

### Environment Variables

- `RAILS_ENV`: Application environment (development, test, production)
- `DATABASE_URL`: Database connection string (production)
- `SECRET_KEY_BASE`: Secret key for production (auto-generated)

### Adding Dependencies

If your tools require external gems:

1. Add to Gemfile:
```ruby
gem 'your-dependency'
```

2. Run:
```bash
bundle install
```

3. Restart the server

## Deployment

### Docker

A Dockerfile is included for containerized deployment:

```bash
docker build -t sectools .
docker run -p 3000:3000 sectools
```

### Kamal

The application is configured for Kamal deployment:

```bash
kamal setup
kamal deploy
```

## Contributing

1. Create a feature branch
2. Add your tool following the guidelines in ADDING_TOOLS.md
3. Include tests for your tool
4. Run code quality checks
5. Submit a pull request

## License

This project is provided for educational and authorized security testing purposes.

## Support

For questions or issues:
- Review existing tools in `app/tools/` for examples
- Check [ADDING_TOOLS.md](ADDING_TOOLS.md) for development guide
- Open an issue for bugs or feature requests
