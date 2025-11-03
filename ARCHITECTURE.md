# SecTools Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         User Browser                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ HTTP Request
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      Rails Router                            │
│  - root → home#index                                        │
│  - /tools/:id → tools#show                                  │
│  - /tools/:id/execute → tools#execute                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
           ┌───────────┴───────────┐
           ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│ HomeController   │    │ ToolsController  │
│ - index          │    │ - show           │
│                  │    │ - execute        │
└────────┬─────────┘    └────────┬─────────┘
         │                       │
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      Tool Registry                           │
│                                                              │
│  - .all()           → Get all registered tools              │
│  - .get(key)        → Get specific tool                     │
│  - .categories()    → Get all categories                    │
│  - .by_category()   → Get tools in category                 │
│  - .discover_tools! → Auto-load from app/tools/             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ manages
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Tool Instances                            │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  SecurityTool Concern (Base Module)                  │  │
│  │  ---------------------------------------------------- │  │
│  │  Class Methods:                                      │  │
│  │    - configure_tool(name:, description:, category:)  │  │
│  │    - input_field(name, type:, label:, ...)           │  │
│  │    - output_format(*formats)                         │  │
│  │    - register!                                       │  │
│  │                                                       │  │
│  │  Instance Methods:                                   │  │
│  │    - execute(params)  [must implement]               │  │
│  │    - validate_params(params)                         │  │
│  │    - format_output(result, format)                   │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐   │
│  │ Password    │  │ JWT         │  │ HTTP Headers     │   │
│  │ Strength    │  │ Decoder     │  │ Analyzer         │   │
│  │ Tool        │  │ Tool        │  │ Tool             │   │
│  └─────────────┘  └─────────────┘  └──────────────────┘   │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐                          │
│  │ SQL         │  │ XSS         │  ... (extensible)        │
│  │ Injection   │  │ Detector    │                          │
│  │ Detector    │  │ Tool        │                          │
│  └─────────────┘  └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

## Request Flow

### 1. Homepage Request

```
User → GET / → HomeController#index
                      ↓
         ToolRegistry.categories()
         ToolRegistry.by_category(cat)
                      ↓
         Render tools by category
                      ↓
         User sees all available tools
```

### 2. Tool Page Request

```
User → GET /tools/password_strength → ToolsController#show
                                             ↓
                           ToolRegistry.get('password_strength')
                                             ↓
                           Create tool instance
                                             ↓
                           Render tool form (auto-generated from input_fields)
```

### 3. Tool Execution

```
User → POST /tools/password_strength/execute → ToolsController#execute
                                                       ↓
                                    ToolRegistry.get('password_strength')
                                                       ↓
                                    tool.validate_params(params)
                                                       ↓
                                    tool.execute(params)
                                                       ↓
                                    tool.format_output(result)
                                                       ↓
                                    Render results with formatting
```

## Component Details

### SecurityTool Concern

**Responsibilities:**
- Provide base interface for all tools
- Define DSL for tool configuration
- Handle input validation
- Format output for display

**Key Features:**
- Class-level configuration via `configure_tool`
- Dynamic input field definitions
- Automatic validation
- Pluggable output formatters

### ToolRegistry

**Responsibilities:**
- Discover tools in app/tools/
- Register and catalog tools
- Provide lookup mechanisms
- Organize by category

**Discovery Process:**
1. Application starts
2. Initializer runs ToolRegistry.discover_tools!
3. Scans app/tools/ for *_tool.rb files
4. Loads each file
5. Tool class calls .register! at bottom of file
6. Registry stores reference to tool class

### Controllers

**HomeController:**
- Lists all tools grouped by category
- Shows overview of available tools

**ToolsController:**
- `show`: Display tool form (auto-generated)
- `execute`: Run tool and display results

### Views

**Dynamic Form Generation:**
- Reads tool.input_fields
- Generates appropriate form controls
- Handles different input types (text, password, url, etc.)

**Result Rendering:**
- Displays structured results
- Color-codes severity levels
- Shows arrays as lists
- Renders nested hashes

## Data Flow

```
┌────────────┐
│ User Input │
└─────┬──────┘
      │
      ▼
┌─────────────────┐
│ Validation      │ ← validate_params()
└─────┬───────────┘
      │
      ▼
┌─────────────────┐
│ Tool Execution  │ ← execute()
└─────┬───────────┘
      │
      ▼
┌─────────────────┐
│ Result Hash     │
└─────┬───────────┘
      │
      ▼
┌─────────────────┐
│ Format Output   │ ← format_output()
└─────┬───────────┘
      │
      ▼
┌─────────────────┐
│ Display to User │
└─────────────────┘
```

## Tool Lifecycle

### 1. Development
```ruby
# 1. Create file: app/tools/my_tool.rb
class MyTool
  include SecurityTool

  configure_tool(
    name: "My Tool",
    description: "What it does",
    category: "My Category"
  )

  input_field :input, type: :text, label: "Input"

  def execute(params)
    { result: "Done" }
  end
end

MyTool.register!  # ← Self-registers with ToolRegistry
```

### 2. Auto-Discovery
```ruby
# config/initializers/tool_registry.rb runs at startup
ToolRegistry.discover_tools!
  ↓
Loads app/tools/my_tool.rb
  ↓
MyTool class defined
  ↓
MyTool.register! called
  ↓
ToolRegistry stores MyTool class
```

### 3. Runtime
```ruby
# User visits /tools/my_tool
ToolRegistry.get('my_tool')  # Returns MyTool class
  ↓
tool = MyTool.new           # Create instance
  ↓
tool.execute(params)        # Run analysis
  ↓
Results displayed
```

## Extension Points

### 1. Custom Input Types

Add new input field types by handling them in the view:

```ruby
input_field :custom, type: :my_type, label: "Custom"
```

Then in `app/views/tools/show.html.erb`:
```erb
<% when :my_type %>
  <%= custom_input_tag ... %>
```

### 2. Custom Output Formats

Override `format_output`:

```ruby
def format_output(result, format = :html)
  case format
  when :pdf
    generate_pdf(result)
  when :csv
    generate_csv(result)
  else
    super
  end
end
```

### 3. Background Processing

For long-running tools:

```ruby
def execute(params)
  job = AnalysisJob.perform_later(params)
  { job_id: job.id, status: "processing" }
end
```

### 4. Tool Dependencies

Tools can use other tools:

```ruby
def execute(params)
  password_tool = PasswordStrengthTool.new
  password_result = password_tool.execute(password: params[:password])

  # Use result in analysis
  { password_strength: password_result }
end
```

## Security Considerations

### Input Validation
- All parameters validated before execution
- Required field checking built-in
- Tools can add custom validation

### Output Sanitization
- Results rendered with Rails auto-escaping
- HTML in results properly escaped
- User input never directly rendered

### Network Requests
- Timeouts enforced
- Error handling for failed requests
- Rate limiting recommended for production

### Access Control
- Can add authentication before controllers
- Authorization for specific tools
- Audit logging of tool execution

## Performance

### Lazy Loading
- Tools loaded only when needed
- Registry stores class references, not instances
- Instances created per request

### Caching
- Tool list cached in registry
- Categories computed once
- Results not cached (security tools should run fresh)

### Optimization Points
- Add background jobs for slow tools
- Cache external API responses
- Implement rate limiting
- Add pagination for large result sets

## Testing Strategy

### Unit Tests
- Test each tool's execute method
- Test validation logic
- Test edge cases

### Integration Tests
- Test tool registry discovery
- Test controller workflows
- Test form generation

### System Tests
- Test full user workflows
- Test UI rendering
- Test error handling

## Deployment Architecture

```
┌─────────────────┐
│   Load Balancer │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌─────────┐ ┌─────────┐
│ Rails   │ │ Rails   │  (Multiple instances)
│ App     │ │ App     │
└────┬────┘ └────┬────┘
     │           │
     └─────┬─────┘
           ▼
    ┌──────────────┐
    │   Database   │
    └──────────────┘
```

## Summary

The SecTools architecture prioritizes:
- **Simplicity**: Easy to understand and extend
- **Modularity**: Tools are self-contained
- **Discoverability**: Auto-registration of tools
- **Flexibility**: Multiple extension points
- **Security**: Built-in validation and sanitization
- **Maintainability**: Clear separation of concerns

Each tool is independent, making the system highly maintainable and allowing parallel development of new tools.
