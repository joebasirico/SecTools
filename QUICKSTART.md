# Quick Start Guide

Get SecTools up and running in minutes!

## Start the Application

1. **Install dependencies** (first time only):
```bash
bundle install
```

2. **Setup database** (first time only):
```bash
rails db:create db:migrate
```

3. **Start the server**:
```bash
bin/dev
```

4. **Open your browser**:
```
http://localhost:3000
```

You should see the SecTools homepage with all available security testing tools organized by category.

## Try the Tools

### Password Strength Analyzer
1. Click "Use Tool" on the Password Strength Analyzer
2. Enter a password to test (e.g., "Password123!")
3. Click "Run Analysis"
4. View detailed strength metrics, entropy calculation, and recommendations

### JWT Token Decoder
1. Click "Use Tool" on the JWT Token Decoder
2. Paste a JWT token (you can get one from [jwt.io](https://jwt.io))
3. Click "Run Analysis"
4. View decoded header, payload, and security warnings

### HTTP Security Headers Analyzer
1. Click "Use Tool" on the HTTP Security Headers Analyzer
2. Enter a website URL (e.g., "https://github.com")
3. Click "Run Analysis"
4. View security score, present/missing headers, and recommendations

### SQL Injection Pattern Detector
1. Click "Use Tool" on the SQL Injection Pattern Detector
2. Enter input to test (e.g., "' OR '1'='1")
3. Click "Run Analysis"
4. View detected patterns, risk level, and mitigation recommendations

### XSS Pattern Detector
1. Click "Use Tool" on the XSS Pattern Detector
2. Enter input to test (e.g., "<script>alert('XSS')</script>")
3. Click "Run Analysis"
4. View detected patterns, sanitized output, and security recommendations

## Add Your First Tool

Create a new file `app/tools/my_first_tool.rb`:

```ruby
# frozen_string_literal: true

class MyFirstTool
  include SecurityTool

  configure_tool(
    name: "My First Security Tool",
    description: "A simple example tool",
    category: "Examples"
  )

  input_field :text, type: :text, label: "Text to Analyze", required: true
  output_format :html, :json

  def execute(params)
    text = params[:text]

    {
      input: text,
      length: text.length,
      word_count: text.split.size,
      character_count: text.chars.uniq.size,
      result: "Analysis complete!"
    }
  end
end

MyFirstTool.register!
```

Restart the server and your tool will appear on the homepage!

## Development Workflow

1. **Make changes** to any file
2. **Refresh browser** - changes are auto-reloaded in development
3. **Add new tools** - create files in `app/tools/`
4. **Restart server** - only needed when adding new tools

## Common Commands

```bash
# Start development server
bin/dev

# Run tests
rails test

# Check code quality
bin/rubocop

# Run security scan
bin/brakeman

# Rails console
rails console

# Database console
rails dbconsole
```

## Project Structure at a Glance

```
app/
  tools/           ← Add your security tools here
  controllers/     ← Request handling
  views/           ← UI templates
  models/
    concerns/
      security_tool.rb  ← Base tool interface
lib/
  tool_registry.rb ← Auto-discovery system
config/
  routes.rb        ← URL routing
```

## Next Steps

- Read [ADDING_TOOLS.md](ADDING_TOOLS.md) for detailed tool development guide
- Explore existing tools in `app/tools/` for examples
- Check [README.md](README.md) for comprehensive documentation

## Need Help?

- Review the existing tools for examples
- Check the documentation in ADDING_TOOLS.md
- Examine the SecurityTool concern in `app/models/concerns/security_tool.rb`

Happy security testing!
