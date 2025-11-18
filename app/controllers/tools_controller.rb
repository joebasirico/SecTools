class ToolsController < ApplicationController
  def index
    @tools = ToolRegistry.all
    @categories = ToolRegistry.categories
  end

  def show
    @tool_class = ToolRegistry.get(params[:id])
    if @tool_class.nil?
      redirect_to root_path, alert: "Tool not found: #{params[:id]}"
      return
    end
    @tool_instance = @tool_class.new

    # Make IP address available for BrowserFingerprintTool
    if @tool_class.name == 'BrowserFingerprintTool'
      @user_ip_address = get_real_ip
    end
  end

  def execute
    @tool_class = ToolRegistry.get(params[:id])
    if @tool_class.nil?
      redirect_to tools_path, alert: "Tool not found"
      return
    end

    @tool_instance = @tool_class.new

    # Convert string keys to symbol keys for tool params
    tool_params = (params[:tool] || {}).transform_keys(&:to_sym)

    # Handle file uploads - read file content
    tool_params.each do |key, value|
      if value.respond_to?(:read)
        tool_params[key] = value.read
      end
    end

    # Add IP address for BrowserFingerprintTool
    if @tool_class.name == 'BrowserFingerprintTool'
      tool_params[:ip_address] = get_real_ip
    end

    errors = @tool_instance.validate_params(tool_params)

    if errors.any?
      flash.now[:alert] = errors.join(", ")
    else
      begin
        @result = @tool_instance.execute(tool_params)
        @formatted_result = @tool_instance.format_output(@result)
        Rails.logger.info("Tool executed successfully. Result: #{@result.inspect[0..200]}")
      rescue StandardError => e
        flash.now[:alert] = "Error executing tool: #{e.message}"
        Rails.logger.error("Tool execution error: #{e.message}\n#{e.backtrace.join("\n")}")
      end
    end

    Rails.logger.info("Rendering show with @result present: #{@result.present?}, @formatted_result present: #{@formatted_result.present?}")
    render :show
  end

  def download
    @tool_class = ToolRegistry.get(params[:id])
    if @tool_class.nil?
      render json: { error: "Tool not found" }, status: :not_found
      return
    end

    begin
      # Get result data from JSON body if provided (for client-side downloads)
      if request.content_type == 'application/json' && request.body.read.present?
        request.body.rewind
        body_params = JSON.parse(request.body.read)
        @result = body_params['result'].deep_symbolize_keys
      else
        # Otherwise execute the tool
        @tool_instance = @tool_class.new
        tool_params = (params[:tool] || {}).transform_keys(&:to_sym)

        tool_params.each do |key, value|
          if value.respond_to?(:read)
            tool_params[key] = value.read
          end
        end

        errors = @tool_instance.validate_params(tool_params)
        if errors.any?
          render json: { error: errors.join(", ") }, status: :unprocessable_entity
          return
        end

        @result = @tool_instance.execute(tool_params)
      end

      respond_to do |response_format|
        response_format.pdf do
          pdf_data = generate_pdf(@result, @tool_class)
          send_data pdf_data,
                    filename: "#{params[:id]}_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}.pdf",
                    type: 'application/pdf',
                    disposition: 'attachment'
        end

        response_format.json do
          send_data @result.to_json,
                    filename: "#{params[:id]}_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json",
                    type: 'application/json',
                    disposition: 'attachment'
        end

        response_format.csv do
          csv_data = generate_csv(@result, @tool_class.name)
          send_data csv_data,
                    filename: "#{params[:id]}_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}.csv",
                    type: 'text/csv',
                    disposition: 'attachment'
        end
      end
    rescue StandardError => e
      Rails.logger.error("Download error: #{e.message}\n#{e.backtrace.join("\n")}")
      render json: { error: "Error generating report: #{e.message}" }, status: :internal_server_error
    end
  end

  private

  # Get the real client IP address, accounting for proxies/load balancers
  def get_real_ip
    # Try various headers that proxies use to pass the real IP
    # Order matters - we check from most to least reliable

    # Standard forwarded header (most reliable)
    if request.headers['X-Forwarded-For'].present?
      # X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, ...)
      # The first one is typically the real client IP
      request.headers['X-Forwarded-For'].split(',').first.strip
    # Cloudflare
    elsif request.headers['CF-Connecting-IP'].present?
      request.headers['CF-Connecting-IP']
    # Some load balancers
    elsif request.headers['X-Real-IP'].present?
      request.headers['X-Real-IP']
    # Fastly CDN
    elsif request.headers['Fastly-Client-IP'].present?
      request.headers['Fastly-Client-IP']
    # Alternative forwarded header
    elsif request.headers['X-Client-IP'].present?
      request.headers['X-Client-IP']
    # Fall back to remote_ip (Rails' built-in IP detection)
    else
      request.remote_ip
    end
  end

  def generate_csv(result, tool_name)
    require 'csv'

    if tool_name == 'DepValidatorTool'
      CSV.generate do |csv|
        # Header
        csv << ['Vulnerability Report', Time.now.strftime('%Y-%m-%d %H:%M:%S')]
        csv << []
        csv << ['Ecosystem', result[:ecosystem]]
        csv << ['Total Dependencies', result[:total_dependencies]]
        csv << []

        # Summary
        csv << ['SUMMARY']
        csv << ['Critical', result[:summary][:critical]]
        csv << ['High', result[:summary][:high]]
        csv << ['Medium', result[:summary][:medium]]
        csv << ['Low', result[:summary][:low]]
        csv << []

        # Vulnerabilities
        if result[:vulnerabilities].present?
          csv << ['VULNERABILITIES']
          csv << ['ID', 'Dependency', 'Version', 'Severity', 'CVSS Score', 'Summary', 'Fixed Versions']

          result[:vulnerabilities].each do |vuln|
            csv << [
              vuln[:vulnerability_id],
              vuln[:dependency],
              vuln[:version],
              vuln[:severity],
              vuln[:cvss_score] || 'N/A',
              vuln[:summary],
              vuln[:fixed_versions].join(', ')
            ]
          end
          csv << []
        end

        # Recommendations
        if result[:recommendations].present?
          csv << ['RECOMMENDATIONS']
          csv << ['Dependency', 'Current Version', 'Recommended Version', 'Severity', 'Vulnerability Count', 'Command']

          result[:recommendations].each do |rec|
            csv << [
              rec[:dependency],
              rec[:current_version],
              rec[:recommended_version] || 'No fix available',
              rec[:max_severity],
              rec[:vulnerability_count],
              rec[:command]
            ]
          end
        end
      end
    else
      # Generic CSV export for other tools
      CSV.generate do |csv|
        csv << ['Key', 'Value']
        result.each do |key, value|
          csv << [key.to_s, value.is_a?(Hash) || value.is_a?(Array) ? value.to_json : value.to_s]
        end
      end
    end
  end

  def generate_pdf(result, tool_class)
    require 'prawn'
    require 'prawn/table'

    # Helper to sanitize text for PDF (Windows-1252 encoding)
    def sanitize_for_pdf(text)
      return '' if text.nil?
      text.to_s.encode('Windows-1252', invalid: :replace, undef: :replace, replace: '?')
    end

    Prawn::Document.new(page_size: 'A4', margin: 40) do |pdf|
      # Title
      pdf.font_size 24
      pdf.text tool_class.tool_name, style: :bold, color: '22C55E'
      pdf.move_down 5
      pdf.font_size 10
      pdf.text "Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}", color: '666666'
      pdf.move_down 20

      if tool_class.name == 'DepValidatorTool'
        # Ecosystem info
        pdf.font_size 12
        pdf.text "Ecosystem: #{result[:ecosystem]}", style: :bold
        pdf.text "Total Dependencies: #{result[:total_dependencies]}"
        pdf.move_down 15

        # Summary
        pdf.font_size 16
        pdf.text "Summary", style: :bold, color: '22C55E'
        pdf.move_down 10
        pdf.font_size 11

        summary_data = [
          ['Severity', 'Count'],
          ['Critical', result[:summary][:critical].to_s],
          ['High', result[:summary][:high].to_s],
          ['Medium', result[:summary][:medium].to_s],
          ['Low', result[:summary][:low].to_s]
        ]

        pdf.table(summary_data,
                  header: true,
                  cell_style: { border_color: '22C55E', padding: 8 },
                  row_colors: ['F3F4F6', 'FFFFFF'])

        pdf.move_down 20

        # Recommendations
        if result[:recommendations].present? && result[:recommendations].any?
          pdf.font_size 16
          pdf.text "Recommended Fixes (#{result[:recommendations].length})", style: :bold, color: 'EA580C'
          pdf.move_down 10
          pdf.font_size 10

          result[:recommendations].each do |rec|
            pdf.fill_color 'DC2626' if rec[:max_severity] == 'CRITICAL'
            pdf.fill_color 'EA580C' if rec[:max_severity] == 'HIGH'
            pdf.fill_color 'EAB308' if rec[:max_severity] == 'MEDIUM'
            pdf.fill_color '2563EB' if rec[:max_severity] == 'LOW'

            pdf.text sanitize_for_pdf("#{rec[:dependency]} (#{rec[:max_severity]})"), style: :bold
            pdf.fill_color '000000'
            pdf.text sanitize_for_pdf("  Current: #{rec[:current_version]} -> Recommended: #{rec[:recommended_version] || 'No fix available'}")
            pdf.text sanitize_for_pdf("  Vulnerabilities: #{rec[:vulnerability_count]}")
            pdf.text sanitize_for_pdf("  Command: #{rec[:command]}"), color: '666666'
            pdf.move_down 10
          end

          pdf.move_down 10
        end

        # Vulnerabilities
        if result[:vulnerabilities].present? && result[:vulnerabilities].any?
          pdf.start_new_page
          pdf.font_size 16
          pdf.fill_color '22C55E'
          pdf.text "Vulnerability Details (#{result[:vulnerabilities].length})", style: :bold
          pdf.move_down 10
          pdf.fill_color '000000'
          pdf.font_size 9

          result[:vulnerabilities].each do |vuln|
            # Severity color
            pdf.fill_color 'DC2626' if vuln[:severity] == 'CRITICAL'
            pdf.fill_color 'EA580C' if vuln[:severity] == 'HIGH'
            pdf.fill_color 'EAB308' if vuln[:severity] == 'MEDIUM'
            pdf.fill_color '2563EB' if vuln[:severity] == 'LOW'

            pdf.text sanitize_for_pdf("#{vuln[:vulnerability_id]} (#{vuln[:severity]})"), style: :bold, size: 11
            pdf.fill_color '000000'
            pdf.text sanitize_for_pdf("#{vuln[:dependency]} @ #{vuln[:version]}"), size: 9, color: '666666'

            if vuln[:summary].present?
              pdf.move_down 5
              pdf.text "Summary:", style: :bold, size: 9
              pdf.text sanitize_for_pdf(vuln[:summary]), size: 8
            end

            if vuln[:fixed_versions].present? && vuln[:fixed_versions].any?
              pdf.move_down 5
              pdf.text sanitize_for_pdf("Fixed in: #{vuln[:fixed_versions].join(', ')}"), size: 8, color: '22C55E'
            end

            pdf.move_down 15
          end
        end
      else
        # Generic PDF export for other tools
        pdf.font_size 12
        result.each do |key, value|
          pdf.text "#{key.to_s.humanize}:", style: :bold
          pdf.text value.is_a?(Hash) || value.is_a?(Array) ? value.to_json : value.to_s
          pdf.move_down 10
        end
      end

      # Footer
      pdf.number_pages "Page <page> of <total>",
                       at: [pdf.bounds.right - 100, 0],
                       align: :right,
                       size: 9
    end.render
  end
end
