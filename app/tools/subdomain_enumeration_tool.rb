# Subdomain Enumeration Tool
# Description: Discover subdomains for a given domain using multiple techniques

class SubdomainEnumerationTool
  include SecurityTool

  configure_tool(
    name: "Subdomain Enumeration Tool",
    description: "Discover subdomains for a given domain using DNS queries, common subdomain wordlist, and various enumeration techniques. Useful for reconnaissance phase of security testing.",
    category: "Network Security"
  )

  input_field :domain,
              type: :text,
              label: "Target Domain",
              placeholder: "example.com",
              required: true

  input_field :scan_depth,
              type: :select,
              label: "Scan Depth",
              options: ["Quick (Top 50)", "Standard (Top 200)", "Deep (Top 500)"],
              required: true

  output_format :html, :json

  # Common subdomain wordlist
  COMMON_SUBDOMAINS = %w[
    www mail ftp localhost webmail smtp pop pop3 imap admin
    webdisk ns1 ns2 ns3 ns4 mx mx1 mx2 test dev stage staging
    portal vpn api mobile m blog shop store wiki docs help support
    secure ssl cpanel cdn media assets static img images video
    download downloads file files upload uploads cloud backup
    forum community chat beta alpha demo sandbox git svn repository
    mysql db database redis cache queue jobs worker monitoring
    analytics stats log logs metrics grafana kibana jenkins ci cd
    app apps application applications service services gateway
    loadbalancer lb router firewall proxy vpn1 vpn2 mail1 mail2
    smtp1 smtp2 imap1 imap2 pop1 pop2 test1 test2 dev1 dev2
    stage1 stage2 prod production www1 www2 web web1 web2 api1 api2
    old new v1 v2 v3 mobile-api admin-api user-api internal external
    partner partners affiliate affiliates reseller billing payment
    checkout cart account accounts profile profiles dashboard console
    manage management control panel cp whm plesk directadmin
  ] unless defined?(COMMON_SUBDOMAINS)

  def execute(params)
    domain = params[:domain]&.strip&.downcase
    scan_depth = params[:scan_depth]

    return { error: "Domain is required" } if domain.blank?

    # Remove protocol and path if provided
    domain = domain.gsub(/^https?:\/\//, '').split('/').first

    # Validate domain format
    return { error: "Invalid domain format" } unless domain.match?(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i)

    # Determine wordlist size based on scan depth
    wordlist_size = case scan_depth
                    when /Quick/ then 50
                    when /Deep/ then 500
                    else 200
                    end

    results = {
      domain: domain,
      scan_depth: scan_depth,
      subdomains_found: [],
      total_checked: 0,
      total_found: 0,
      dns_info: {},
      scan_duration: 0
    }

    start_time = Time.now

    # Get subdomains to check
    subdomains_to_check = COMMON_SUBDOMAINS.first(wordlist_size)

    results[:total_checked] = subdomains_to_check.length

    # Check each subdomain
    subdomains_to_check.each do |subdomain|
      full_domain = "#{subdomain}.#{domain}"

      dns_result = check_subdomain(full_domain)

      if dns_result[:exists]
        results[:subdomains_found] << dns_result
        results[:total_found] += 1
      end
    end

    # Check for wildcard DNS
    wildcard_test = check_subdomain("#{SecureRandom.hex(16)}.#{domain}")
    results[:wildcard_dns] = wildcard_test[:exists]

    # Get domain's main DNS info
    results[:dns_info] = get_domain_info(domain)

    results[:scan_duration] = (Time.now - start_time).round(2)

    # Sort results by subdomain name
    results[:subdomains_found].sort_by! { |s| s[:subdomain] }

    results
  rescue StandardError => e
    { error: "Error during subdomain enumeration: #{e.message}" }
  end

  private

  def check_subdomain(full_domain)
    result = {
      subdomain: full_domain,
      exists: false,
      ip_addresses: [],
      cname: nil,
      response_time: 0
    }

    start_time = Time.now

    begin
      # Perform DNS lookup with timeout
      Timeout.timeout(3) do
        resolver = Resolv::DNS.new

        # Try to get A records
        begin
          ips = resolver.getaddresses(full_domain)
          if ips.any?
            result[:exists] = true
            result[:ip_addresses] = ips.map(&:to_s)
          end
        rescue Resolv::ResolvError
          # No A record, try CNAME
        end

        # Try to get CNAME record
        begin
          resources = resolver.getresources(full_domain, Resolv::DNS::Resource::IN::CNAME)
          if resources.any?
            result[:exists] = true
            result[:cname] = resources.first.name.to_s
          end
        rescue Resolv::ResolvError
          # No CNAME
        end

        resolver.close
      end

      result[:response_time] = ((Time.now - start_time) * 1000).round(2)
    rescue Timeout::Error
      result[:error] = "DNS lookup timeout"
    rescue StandardError => e
      result[:error] = "DNS error: #{e.message}"
    end

    result
  end

  def get_domain_info(domain)
    info = {
      name_servers: [],
      mx_records: [],
      txt_records: [],
      a_records: [],
      soa: nil
    }

    begin
      resolver = Resolv::DNS.new

      # Get NS records
      begin
        ns_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::NS)
        info[:name_servers] = ns_records.map { |ns| ns.name.to_s }
      rescue Resolv::ResolvError
        # No NS records
      end

      # Get MX records
      begin
        mx_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::MX)
        info[:mx_records] = mx_records.map { |mx| "#{mx.preference} #{mx.exchange}" }
      rescue Resolv::ResolvError
        # No MX records
      end

      # Get A records
      begin
        a_records = resolver.getaddresses(domain)
        info[:a_records] = a_records.map(&:to_s)
      rescue Resolv::ResolvError
        # No A records
      end

      # Get TXT records
      begin
        txt_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::TXT)
        info[:txt_records] = txt_records.map { |txt| txt.strings.join }
      rescue Resolv::ResolvError
        # No TXT records
      end

      # Get SOA record
      begin
        soa_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::SOA)
        if soa_records.any?
          soa = soa_records.first
          info[:soa] = {
            mname: soa.mname.to_s,
            rname: soa.rname.to_s,
            serial: soa.serial
          }
        end
      rescue Resolv::ResolvError
        # No SOA record
      end

      resolver.close
    rescue StandardError => e
      info[:error] = "Error fetching DNS info: #{e.message}"
    end

    info
  end
end

SubdomainEnumerationTool.register!
