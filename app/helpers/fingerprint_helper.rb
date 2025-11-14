# frozen_string_literal: true

module FingerprintHelper
  def uniqueness_color(score)
    return "#ef4444" if score > 70  # High uniqueness = bad (red)
    return "#eab308" if score > 40  # Medium uniqueness
    "#22c55e"  # Low uniqueness = good (green)
  end

  def tracking_color(score)
    return "#ef4444" if score > 70  # Easily trackable = bad (red)
    return "#eab308" if score > 40  # Moderately trackable
    "#22c55e"  # Hard to track = good (green)
  end

  def risk_color(risk)
    case risk.to_s.downcase
    when "high" then "#ef4444"
    when "medium" then "#eab308"
    else "#22c55e"
    end
  end

  def risk_bg_color(risk)
    case risk.to_s.downcase
    when "high" then "rgba(239, 68, 68, 0.1)"
    when "medium" then "rgba(234, 179, 8, 0.1)"
    else "rgba(34, 197, 94, 0.1)"
    end
  end
end
