# frozen_string_literal: true

require 'digest'
require 'net/http'

# Password Strength Analyzer with Have I Been Pwned Integration
# Analyzes password strength and checks against breach database
class PasswordStrengthTool
  include SecurityTool

  configure_tool(
    name: "Password Strength Analyzer",
    description: "Analyze password strength and check against Have I Been Pwned breach database",
    category: "Authentication Security"
  )

  input_field :password, type: :password, label: "Password to Test", placeholder: "Enter password", required: true
  output_format :html, :json

  def execute(params)
    password = params[:password]

    # Calculate basic metrics
    score = calculate_score(password)
    feedback = generate_feedback(password, score)
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(password)

    # Check against Have I Been Pwned
    pwned_data = check_pwned(password)

    {
      password_length: password.length,
      score: score,
      strength: strength_label(score),
      entropy_bits: entropy,
      estimated_crack_time: crack_time,
      character_types: analyze_character_types(password),
      pwned_status: pwned_data[:status],
      pwned_count: pwned_data[:count],
      feedback: feedback
    }
  end

  private

  def calculate_score(password)
    score = 0

    # Length scoring
    score += 1 if password.length >= 8
    score += 1 if password.length >= 12
    score += 1 if password.length >= 16
    score += 1 if password.length >= 20

    # Character diversity
    score += 1 if password.match?(/[a-z]/)
    score += 1 if password.match?(/[A-Z]/)
    score += 1 if password.match?(/[0-9]/)
    score += 1 if password.match?(/[^a-zA-Z0-9]/)

    # Pattern detection (penalties)
    score -= 1 if password.match?(/(.)\1{2,}/) # Repeated characters
    score -= 1 if password.match?(/123|234|345|456|567|678|789|890/) # Sequential numbers
    score -= 1 if password.match?(/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i) # Sequential letters
    score -= 2 if common_password?(password)

    [ [ score, 0 ].max, 10 ].min
  end

  def strength_label(score)
    case score
    when 0..2 then "Very Weak"
    when 3..4 then "Weak"
    when 5..6 then "Moderate"
    when 7..8 then "Strong"
    else "Very Strong"
    end
  end

  def analyze_character_types(password)
    types = []
    types << "lowercase" if password.match?(/[a-z]/)
    types << "uppercase" if password.match?(/[A-Z]/)
    types << "numbers" if password.match?(/[0-9]/)
    types << "special" if password.match?(/[^a-zA-Z0-9]/)
    types.join(", ")
  end

  def generate_feedback(password, score)
    feedback = []

    # Length feedback
    if password.length < 8
      feedback << "Password is too short (minimum 8 characters required)"
    elsif password.length < 12
      feedback << "Consider using at least 12 characters for better security"
    elsif password.length < 16
      feedback << "Good length, but 16+ characters is even better"
    else
      feedback << "Excellent length!"
    end

    # Character diversity feedback
    feedback << "Add lowercase letters" unless password.match?(/[a-z]/)
    feedback << "Add uppercase letters" unless password.match?(/[A-Z]/)
    feedback << "Add numbers" unless password.match?(/[0-9]/)
    feedback << "Add special characters (!@#$%^&*, etc.)" unless password.match?(/[^a-zA-Z0-9]/)

    # Pattern warnings
    feedback << "Avoid repeated characters" if password.match?(/(.)\1{2,}/)
    feedback << "Avoid sequential numbers" if password.match?(/123|234|345|456|567|678|789|890/)
    feedback << "Avoid sequential letters" if password.match?(/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i)

    # Common password warning
    feedback << "This is a commonly used password - NEVER use it!" if common_password?(password)

    # Positive feedback
    feedback << "Great password strength! Keep it safe." if score >= 8

    feedback
  end

  def calculate_entropy(password)
    charset_size = 0
    charset_size += 26 if password.match?(/[a-z]/)
    charset_size += 26 if password.match?(/[A-Z]/)
    charset_size += 10 if password.match?(/[0-9]/)
    charset_size += 32 if password.match?(/[^a-zA-Z0-9]/)

    return 0 if charset_size == 0

    (password.length * Math.log2(charset_size)).round(2)
  end

  def estimate_crack_time(password)
    entropy = calculate_entropy(password)

    # Assuming 10 billion guesses per second (modern GPU)
    seconds = (2 ** entropy) / 10_000_000_000

    format_time(seconds)
  end

  def format_time(seconds)
    return "Instant" if seconds < 1
    return "#{seconds.round} seconds" if seconds < 60
    return "#{(seconds / 60).round} minutes" if seconds < 3600
    return "#{(seconds / 3600).round} hours" if seconds < 86400
    return "#{(seconds / 86400).round} days" if seconds < 2592000
    return "#{(seconds / 2592000).round} months" if seconds < 31536000

    years = (seconds / 31536000).round
    return "#{years} years" if years < 1000
    return "#{years} years (millennia)" if years < 1_000_000
    "#{years} years (geological timescale)"
  end

  def common_password?(password)
    # Top 100 most common passwords
    common = %w[
      password 123456 12345678 qwerty abc123 monkey letmein trustno1 dragon
      baseball iloveyou master sunshine princess football shadow 123123
      654321 superman michael ninja mustang password1 123456789 password123
      welcome login admin 1234567890 solo passw0rd starwars jesus 1234567
      1234 666666 mypass fuck password321 696969 1q2w3e4r qwertyuiop
      computer donald michael1 daniel sunshine1 michelle computer1 freedom
      whatever lovely buster jennifer babygirl family2012 liverpool
      iloveyou1 football1 charlie pokemon secret superman1 love123 dallas
      london ashley 12345 pepper george charlie1 123321 summer hunter
      target love samsung hello1 ashley1 anthony charlie2 oliver cookie
      orange amanda jessica zxcvbnm michelle1 party ranger access whatever1
      michelle2 love jordan google jackson batman lovely1 money
    ]

    common.include?(password.downcase)
  end

  def check_pwned(password)
    begin
      # Create SHA-1 hash of password
      hash = Digest::SHA1.hexdigest(password).upcase
      prefix = hash[0..4]
      suffix = hash[5..-1]

      # Query Have I Been Pwned API (k-Anonymity model)
      uri = URI("https://api.pwnedpasswords.com/range/#{prefix}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = 5
      http.read_timeout = 5

      request = Net::HTTP::Get.new(uri)
      request['User-Agent'] = 'SecTools-PasswordChecker'

      response = http.request(request)

      if response.code == '200'
        # Parse response to find suffix match
        response.body.each_line do |line|
          hash_suffix, count = line.strip.split(':')
          if hash_suffix == suffix
            count_num = count.to_i
            return {
              status: "COMPROMISED",
              count: count_num,
              message: "This password has been seen #{count_num} times in data breaches"
            }
          end
        end

        return {
          status: "SAFE",
          count: 0,
          message: "Not found in breach database"
        }
      else
        puts "not 200: #{response.code}"
        return {
          status: "ERROR",
          count: nil,
          message: "Could not check breach database (API error)"
        }
      end
    rescue StandardError => e
      puts e.message
      return {
        status: "ERROR",
        count: nil,
        message: "Could not check breach database: #{e.message}"
      }
    end
  end
end

PasswordStrengthTool.register!
