# frozen_string_literal: true

# Fingerprint model for tracking browser fingerprints
# Stores hashed browser fingerprints and tracks uniqueness
class Fingerprint < ApplicationRecord
  validates :fingerprint_hash, presence: true, uniqueness: true
  validates :visit_count, numericality: { greater_than_or_equal_to: 0 }

  # Find or create a fingerprint record
  # Updates visit count and last_seen_at if fingerprint exists
  def self.track_fingerprint(hash, ip_address, user_agent)
    fingerprint = find_or_initialize_by(fingerprint_hash: hash)

    if fingerprint.new_record?
      fingerprint.first_seen_at = Time.current
      fingerprint.visit_count = 1
      fingerprint.ip_address = ip_address
      fingerprint.user_agent = user_agent
    else
      fingerprint.visit_count += 1
      fingerprint.ip_address = ip_address # Update to latest
      fingerprint.user_agent = user_agent # Update to latest
    end

    fingerprint.last_seen_at = Time.current
    fingerprint.save!

    fingerprint
  end

  # Calculate uniqueness score (0-100)
  # Based on how rare this fingerprint is compared to all fingerprints
  def uniqueness_score
    total = Fingerprint.count
    return 100 if total <= 1

    # Calculate percentile based on visit count
    # More visits = less unique
    # Fewer visits = more unique
    percentile = ((total - Fingerprint.where("visit_count >= ?", visit_count).count).to_f / total * 100).round

    # Ensure score is between 0 and 100
    [[percentile, 0].max, 100].min
  end

  # Calculate tracking likelihood score (0-100)
  # Based on how identifiable/trackable this fingerprint is
  def tracking_likelihood
    total = Fingerprint.count
    return 100 if total <= 1

    # If this fingerprint is unique (only seen once), it's highly trackable
    return 95 if visit_count == 1 && total > 10

    # Calculate how common this fingerprint is
    # Less common = more trackable
    similar_count = Fingerprint.where(visit_count: visit_count).count
    rarity_score = ((total - similar_count).to_f / total * 100).round

    # If we've seen this exact fingerprint multiple times, it's definitely trackable
    if visit_count > 1
      rarity_score = [rarity_score + 20, 100].min
    end

    [[rarity_score, 10].max, 100].min
  end

  # Human-readable status
  def uniqueness_status
    score = uniqueness_score
    case score
    when 90..100 then "Highly Unique"
    when 70..89 then "Very Unique"
    when 50..69 then "Moderately Unique"
    when 30..49 then "Somewhat Common"
    else "Very Common"
    end
  end

  def tracking_status
    score = tracking_likelihood
    case score
    when 90..100 then "Easily Trackable"
    when 70..89 then "Likely Trackable"
    when 50..69 then "Moderately Trackable"
    when 30..49 then "Somewhat Trackable"
    else "Difficult to Track"
    end
  end
end
