# frozen_string_literal: true

# Tool Name: [Tool Name]
# Description: [Brief description of what this tool does]
# Author: [Your Name]
# Created: [Date]

# INSTRUCTIONS FOR USING THIS TEMPLATE:
# 1. Copy this file and rename it to match your tool (e.g., my_security_tool.rb)
# 2. Replace the class name "ToolTemplate" with your tool's name in PascalCase
# 3. Fill in the configure_tool section with your tool's metadata
# 4. Define input fields using the input_field method
# 5. Specify output formats using the output_format method
# 6. Implement the execute method with your tool's logic
# 7. Don't forget to call YourToolClass.register! at the end of the file

class ToolTemplate
  # Include the SecurityTool concern to get all the base functionality
  # This provides tool registration, input validation, and output formatting
  include SecurityTool

  # ============================================================================
  # TOOL CONFIGURATION
  # ============================================================================
  # Define your tool's metadata here
  # Required fields: name, description, category
  configure_tool(
    name: "Your Tool Name",                    # Display name shown in the UI
    description: "Brief description of what your tool does",  # Help text for users
    category: "Tool Category", # Category for organizing tools (e.g., "Code Security", "Authentication Security")
  )

  # ============================================================================
  # INPUT FIELDS
  # ============================================================================
  # Define input fields that users will fill out to use your tool
  # Each input_field call creates one form field in the UI
  #
  # Available field types:
  #   :text      - Single line text input
  #   :textarea  - Multi-line text input
  #   :password  - Password input (masked)
  #   :number    - Numeric input
  #   :checkbox  - Boolean checkbox
  #   :select    - Dropdown selection (requires options parameter)
  #   :file      - File upload
  #
  # Parameters:
  #   - name: Symbol representing the field name (used in params hash)
  #   - type: Field type from the list above
  #   - label: Display label for the field
  #   - placeholder: Example text shown in the field (optional)
  #   - required: Whether the field must be filled (default: true)
  #   - Additional options can be passed as needed

  # Example text input field
  input_field :input_text,
              type: :text,
              label: "Input Text",
              placeholder: "Enter some text here",
              required: true

  # Example optional password field
  input_field :optional_key,
              type: :password,
              label: "Optional Secret Key",
              placeholder: "your-secret-key",
              required: false

  # Example textarea for longer content
  # input_field :code_snippet,
  #             type: :textarea,
  #             label: "Code to Analyze",
  #             placeholder: "Paste your code here",
  #             required: true

  # ============================================================================
  # OUTPUT FORMATS
  # ============================================================================
  # Specify which output formats your tool supports
  # Available formats: :html, :json, :text
  # Most tools support both :html and :json for web and API usage
  output_format :html, :json

  # ============================================================================
  # MAIN EXECUTION METHOD
  # ============================================================================
  # This is the core method that implements your tool's functionality
  # It receives a params hash containing all the input field values
  # It must return a hash with the results
  #
  # @param params [Hash] Input parameters from the form fields
  # @return [Hash] Results to be displayed to the user
  def execute(params)
    # Extract input parameters
    # Use the field names you defined in input_field calls
    input_text = params[:input_text]&.strip
    optional_key = params[:optional_key]&.strip

    # Validate required inputs (optional - SecurityTool provides validation)
    # You can add custom validation here if needed
    if input_text.blank?
      return {
               error: "Input text is required",
               result: nil,
             }
    end

    begin
      # ======================================================================
      # IMPLEMENT YOUR TOOL LOGIC HERE
      # ======================================================================
      # 1. Process the input parameters
      # 2. Perform security analysis, scanning, validation, etc.
      # 3. Generate results and recommendations
      # 4. Return structured data as a hash

      # Example processing:
      result = process_input(input_text)

      # Return structured results
      # The returned hash will be formatted according to the requested output format
      {
        # Basic results
        input: input_text,
        analyzed_at: Time.now.utc,
        result: result,

      # Optional: Include detailed findings
      # findings: [],

      # Optional: Include security score
      # security_score: { score: 85, grade: 'B' },

      # Optional: Include recommendations
      # recommendations: []
      }
    rescue StandardError => e
      # Handle errors gracefully
      # Always return a hash, even on error
      {
        error: "Failed to process input: #{e.message}",
        result: nil,
        analyzed_at: Time.now.utc,
      }
    end
  end

  # ============================================================================
  # PRIVATE HELPER METHODS
  # ============================================================================
  # Add any private helper methods your tool needs below
  # These methods are only accessible within this class

  private

  # Example helper method
  # Implement your core logic in helper methods to keep code organized
  def process_input(input)
    # Your processing logic here
    "Processed: #{input}"
  end

  # Example: Security check helper
  # def check_for_vulnerabilities(data)
  #   vulnerabilities = []
  #   # Add vulnerability checks here
  #   vulnerabilities
  # end

  # Example: Score calculation helper
  # def calculate_security_score(findings)
  #   score = 100
  #   findings.each do |finding|
  #     score -= severity_penalty(finding[:severity])
  #   end
  #   {
  #     score: [[score, 0].max, 100].min,
  #     grade: score_to_grade(score)
  #   }
  # end
end

# ============================================================================
# TOOL REGISTRATION
# ============================================================================
# Register this tool with the ToolRegistry so it can be discovered and used
# IMPORTANT: Don't forget this line or your tool won't be available!
# ToolTemplate.register!
