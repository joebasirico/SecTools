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
end
