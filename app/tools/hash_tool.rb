# Tool Name: Hash Tool
# Description: A tool that generates hash digests from input

class HashTool
  include SecurityTool

  configure_tool(
    name: "Hash Digest Tool",
    description: "A tool that calculates the digest from different hash, and signature algorithms.",  # Help text for users
    category: "Authentication Security", # Category for organizing tools (e.g., "Code Security", "Authentication Security")
  )

  HASH_ALGORITHMS = OpenSSL::Digest.constants
    .reject { |c| [:Digest, :DigestError].include?(c) }
    .map(&:to_s)
    .sort

  input_field :input_text,
              type: :text,
              label: "Input Text",
              placeholder: "Enter some text here",
              required: true

  input_field :use_hmac,
              type: :checkbox,
              label: "Calculate HMAC (provide key below)",
              # placeholder: "your-secret-key",
              required: true

  input_field :hmac_key,
              type: :password,
              label: "Optional HMAC Key",
              placeholder: "your-secret-key",
              required: false

  input_field :hash_algorithm,
              type: :select,
              label: "Select Hash Algorithm",
              placeholder: "Please Select...",
              options: HASH_ALGORITHMS,
              required: true

  output_format :html, :json

  def execute(params)
    input_text = params[:input_text]&.strip
    hash_algorithm = params[:hash_algorithm]
    use_hmac = !!params[:use_hmac]
    hmac_key = params[:hmac_key]

    if input_text.blank?
      return {
               error: "Input text is required",
               result: nil,
             }
    end

    begin
      result = if use_hmac
          process_hmac(input_text, hmac_key, hash_algorithm)
        else
          process_input(input_text, hash_algorithm)
        end

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

  def process_input(input, hash_algorithm)
    OpenSSL::Digest.new(hash_algorithm).hexdigest(input)
  end

  def process_hmac(input_text, hmac_key, hash_algorithm)
    OpenSSL::HMAC.hexdigest(hash_algorithm, hmac_key, input_text)
  end
end

# ============================================================================
# TOOL REGISTRATION
# ============================================================================
# Register this tool with the ToolRegistry so it can be discovered and used
# IMPORTANT: Don't forget this line or your tool won't be available!
HashTool.register!
