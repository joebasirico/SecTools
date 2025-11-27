module ToolsHelper
  def severity_border_class(severity)
    case severity.to_s.upcase
    when 'CRITICAL' then 'border-red-500'
    when 'HIGH' then 'border-orange-500'
    when 'MEDIUM' then 'border-yellow-500'
    when 'LOW' then 'border-blue-500'
    else 'border-gray-600'
    end
  end

  def severity_border_class_tree(rank)
    case rank
    when 4 then 'border-red-500'
    when 3 then 'border-orange-500'
    when 2 then 'border-yellow-500'
    when 1 then 'border-blue-500'
    else 'border-gray-600'
    end
  end

  def severity_badge_class(severity)
    'inline-block px-3 py-1.5 rounded border-2 font-bold text-xs font-mono'
  end

  def severity_badge_style(severity)
    case severity.to_s.upcase
    when 'CRITICAL' then 'background-color: #dc2626; color: white; border-color: #f87171;'
    when 'HIGH' then 'background-color: #ea580c; color: white; border-color: #fb923c;'
    when 'MEDIUM', 'MODERATE' then 'background-color: #eab308; color: #1f2937; border-color: #fde047;'
    when 'LOW' then 'background-color: #2563eb; color: white; border-color: #60a5fa;'
    else 'background-color: #374151; color: #d1d5db; border-color: #6b7280;'
    end
  end

  def severity_badge_class_from_rank(rank)
    'inline-block px-3 py-1.5 rounded border-2 font-bold text-xs font-mono'
  end

  def severity_badge_style_from_rank(rank)
    case rank
    when 4 then 'background-color: #dc2626; color: white; border-color: #f87171;'
    when 3 then 'background-color: #ea580c; color: white; border-color: #fb923c;'
    when 2 then 'background-color: #eab308; color: #1f2937; border-color: #fde047;'
    when 1 then 'background-color: #2563eb; color: white; border-color: #60a5fa;'
    else 'background-color: #374151; color: #d1d5db; border-color: #6b7280;'
    end
  end

  def severity_label_from_rank(rank)
    case rank
    when 4 then 'CRITICAL'
    when 3 then 'HIGH'
    when 2 then 'MEDIUM'
    when 1 then 'LOW'
    else 'UNKNOWN'
    end
  end

  def severity_class(item)
    return '' unless item.is_a?(Hash) && item[:severity]
    case item[:severity]
    when :critical then 'text-red-400 font-bold'
    when :high then 'text-red-500'
    when :medium then 'text-yellow-500'
    when :low then 'text-yellow-400'
    else ''
    end
  end

  def result_class(key, value)
    return 'text-green-300 font-semibold' if key.to_s.include?('score') && value.to_i > 70
    return 'text-red-400 font-semibold' if key.to_s.include?('expired') && value == true
    return 'text-yellow-400 font-semibold' if key.to_s.include?('warning')
    'text-green-400'
  end

  def render_hash(hash)
    content_tag(:div, class: 'space-y-1') do
      hash.map do |k, v|
        content_tag(:div, class: 'flex') do
          concat content_tag(:span, "#{k.to_s.gsub('_', ' ')}: ", class: 'font-bold mr-2', style: 'color: var(--color-text-muted);')
          concat content_tag(:span, v.is_a?(Hash) || v.is_a?(Array) ? v.inspect : v.to_s, style: 'color: var(--color-text-primary);')
        end
      end.join.html_safe
    end
  end
end
