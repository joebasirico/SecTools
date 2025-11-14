# frozen_string_literal: true

require 'digest'

# Browser Fingerprinting Tool
# Analyzes browser fingerprints and tracks uniqueness based on EFF's Cover Your Tracks methodology
# Reference: https://coveryourtracks.eff.org/
class BrowserFingerprintTool
  include SecurityTool

  configure_tool(
    name: "Browser Fingerprint Analyzer",
    description: "Analyze your browser's fingerprint, track uniqueness, and assess tracking vulnerability based on EFF's Cover Your Tracks research",
    category: "Privacy & Tracking"
  )

  # This tool collects data via JavaScript on the client side
  # No traditional input fields needed - data is sent via AJAX
  output_format :html, :json

  def execute(params)
    # Extract fingerprint data components
    fingerprint_data = {
      user_agent: params[:user_agent],
      screen_resolution: params[:screen_resolution],
      color_depth: params[:color_depth],
      timezone: params[:timezone],
      language: params[:language],
      platform: params[:platform],
      plugins: params[:plugins],
      canvas_hash: params[:canvas_hash],
      webgl_hash: params[:webgl_hash],
      fonts: params[:fonts],
      has_local_storage: params[:has_local_storage],
      has_session_storage: params[:has_session_storage],
      has_indexed_db: params[:has_indexed_db],
      cpu_class: params[:cpu_class],
      device_memory: params[:device_memory],
      hardware_concurrency: params[:hardware_concurrency],
      max_touch_points: params[:max_touch_points],
      do_not_track: params[:do_not_track],
      cookies_enabled: params[:cookies_enabled]
    }

    # Get IP address from request
    ip_address = params[:ip_address] || "unknown"

    # Generate SHA-512 hash of all fingerprint data
    fingerprint_hash = generate_fingerprint_hash(fingerprint_data)

    # Track the fingerprint in the database
    fingerprint_record = Fingerprint.track_fingerprint(
      fingerprint_hash,
      ip_address,
      fingerprint_data[:user_agent]
    )

    # Calculate uniqueness and tracking scores
    uniqueness_score = fingerprint_record.uniqueness_score
    tracking_likelihood = fingerprint_record.tracking_likelihood

    # Analyze the fingerprint characteristics
    analysis = analyze_fingerprint_characteristics(fingerprint_data)

    {
      ip_address: ip_address,
      fingerprint_hash: fingerprint_hash,
      fingerprint_data: fingerprint_data,
      uniqueness_score: uniqueness_score,
      uniqueness_status: fingerprint_record.uniqueness_status,
      tracking_likelihood: tracking_likelihood,
      tracking_status: fingerprint_record.tracking_status,
      visit_count: fingerprint_record.visit_count,
      first_seen: fingerprint_record.first_seen_at,
      last_seen: fingerprint_record.last_seen_at,
      analysis: analysis,
      total_fingerprints_in_database: Fingerprint.count,
      privacy_tips: generate_privacy_tips(analysis)
    }
  end

  private

  def generate_fingerprint_hash(data)
    # Concatenate all fingerprint components into a string
    fingerprint_string = [
      data[:user_agent],
      data[:screen_resolution],
      data[:color_depth],
      data[:timezone],
      data[:language],
      data[:platform],
      data[:plugins],
      data[:canvas_hash],
      data[:webgl_hash],
      data[:fonts],
      data[:has_local_storage],
      data[:has_session_storage],
      data[:has_indexed_db],
      data[:cpu_class],
      data[:device_memory],
      data[:hardware_concurrency],
      data[:max_touch_points],
      data[:do_not_track],
      data[:cookies_enabled]
    ].join("|")

    # Generate SHA-512 hash
    Digest::SHA512.hexdigest(fingerprint_string)
  end

  def analyze_fingerprint_characteristics(data)
    characteristics = []

    # User Agent analysis
    if data[:user_agent].present?
      ua = data[:user_agent].to_s
      if ua.include?("Chrome") && !ua.include?("Edg")
        characteristics << { name: "Browser", value: "Chrome-based", risk: "Medium", note: "Popular browser reduces uniqueness" }
      elsif ua.include?("Firefox")
        characteristics << { name: "Browser", value: "Firefox", risk: "Medium", note: "Built-in tracking protection available" }
      elsif ua.include?("Safari")
        characteristics << { name: "Browser", value: "Safari", risk: "Medium", note: "ITP tracking protection active" }
      elsif ua.include?("Edg")
        characteristics << { name: "Browser", value: "Edge", risk: "Medium", note: "Moderate user base" }
      else
        characteristics << { name: "Browser", value: "Uncommon", risk: "High", note: "Unusual browser increases uniqueness" }
      end
    end

    # Screen resolution analysis
    if data[:screen_resolution].present?
      common_resolutions = ["1920x1080", "1366x768", "1440x900", "1536x864", "2560x1440"]
      if common_resolutions.include?(data[:screen_resolution])
        characteristics << { name: "Screen Resolution", value: data[:screen_resolution], risk: "Low", note: "Common resolution" }
      else
        characteristics << { name: "Screen Resolution", value: data[:screen_resolution], risk: "High", note: "Uncommon resolution increases trackability" }
      end
    end

    # Canvas fingerprinting
    if data[:canvas_hash].present?
      characteristics << { name: "Canvas Fingerprint", value: "Detected", risk: "High", note: "Canvas fingerprinting can uniquely identify your browser" }
    end

    # WebGL fingerprinting
    if data[:webgl_hash].present?
      characteristics << { name: "WebGL Fingerprint", value: "Detected", risk: "High", note: "WebGL reveals GPU information for tracking" }
    end

    # Fonts analysis
    if data[:fonts].present?
      font_count = data[:fonts].to_s.split(",").length
      if font_count > 50
        characteristics << { name: "Installed Fonts", value: "#{font_count} fonts", risk: "High", note: "Large font list increases uniqueness" }
      elsif font_count > 20
        characteristics << { name: "Installed Fonts", value: "#{font_count} fonts", risk: "Medium", note: "Moderate font list" }
      else
        characteristics << { name: "Installed Fonts", value: "#{font_count} fonts", risk: "Low", note: "Standard font set" }
      end
    end

    # Timezone analysis
    if data[:timezone].present?
      common_timezones = ["-480", "-420", "-360", "-300", "-240", "0", "60", "120"]
      if common_timezones.include?(data[:timezone].to_s)
        characteristics << { name: "Timezone", value: "UTC#{data[:timezone].to_i / 60}", risk: "Low", note: "Common timezone" }
      else
        characteristics << { name: "Timezone", value: "UTC#{data[:timezone].to_i / 60}", risk: "Medium", note: "Less common timezone" }
      end
    end

    # Do Not Track header
    if data[:do_not_track] == "1" || data[:do_not_track] == true
      characteristics << { name: "Do Not Track", value: "Enabled", risk: "Medium", note: "Ironically, DNT header can increase uniqueness" }
    end

    # Hardware concurrency
    if data[:hardware_concurrency].present?
      cores = data[:hardware_concurrency].to_i
      characteristics << { name: "CPU Cores", value: "#{cores} cores", risk: "Medium", note: "Reveals hardware information" }
    end

    # Touch support
    if data[:max_touch_points].to_i > 0
      characteristics << { name: "Touch Support", value: "Enabled", risk: "Medium", note: "Indicates touchscreen device" }
    end

    characteristics
  end

  def generate_privacy_tips(analysis)
    tips = []

    # Check for high-risk characteristics
    high_risk_count = analysis.count { |c| c[:risk] == "High" }

    if high_risk_count > 2
      tips << "Your browser has multiple unique characteristics that make tracking easier"
    end

    # Canvas fingerprinting tip
    if analysis.any? { |c| c[:name] == "Canvas Fingerprint" }
      tips << "Consider using browser extensions that block canvas fingerprinting (e.g., CanvasBlocker for Firefox)"
    end

    # WebGL tip
    if analysis.any? { |c| c[:name] == "WebGL Fingerprint" }
      tips << "Disable WebGL in browser settings to prevent GPU-based fingerprinting"
    end

    # Font tip
    font_char = analysis.find { |c| c[:name] == "Installed Fonts" }
    if font_char && font_char[:risk] == "High"
      tips << "Reduce the number of installed fonts or use a browser that limits font enumeration"
    end

    # General tips
    tips << "Use privacy-focused browsers like Tor Browser or Brave for better fingerprinting resistance"
    tips << "Enable tracking protection features in your browser settings"
    tips << "Visit https://coveryourtracks.eff.org/ to learn more about protecting your privacy"

    tips
  end
end

BrowserFingerprintTool.register!
