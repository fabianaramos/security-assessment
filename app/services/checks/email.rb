require "open3"
require "resolv"

module Checks
  module Email
    GROUP = "E-mail".freeze
    DKIM_SELECTORS = %w[google selector1 selector2 default k1 s1 s2 mail dkim hostinger zoho mx].freeze
    SPF_TITLE = "SPF (quem pode enviar e-mail pelo domínio)".freeze
    DMARC_TITLE = "DMARC (política contra e-mails falsificados)".freeze

    # Valid mechanisms and modifiers (RFC 7208): [qualifier]mechanism[:value] or name=value.
    SPF_VALUE = "[^\\s,;]+".freeze
    SPF_TERM = /
      \A[+\-~?]?(all|include:#{SPF_VALUE}|a(:#{SPF_VALUE})?|mx(:#{SPF_VALUE})?|ip4:#{SPF_VALUE}|
                 ip6:#{SPF_VALUE}|exists:#{SPF_VALUE}|ptr(:#{SPF_VALUE})?)\z
      | \A[a-z][\w.-]*=[^\s,;]*\z
    /ix

    module_function

    def item(...) = Checks.item(GROUP, ...)

    # ------------------------------------------------------------ analysis (pure functions)

    def analyze_spf(txt_records)
      records = txt_records.select { _1.downcase.start_with?("v=spf1") }
      if records.empty?
        return item("spf", SPF_TITLE, "fail", "Nenhum registro SPF encontrado.",
                    "Criar um registro TXT SPF listando os serviços que enviam e-mail pelo domínio " \
                    "(ex.: v=spf1 include:_spf.google.com ~all).", weight: 3)
      end
      if records.size > 1
        return item("spf", SPF_TITLE, "fail",
                    "Há #{records.size} registros SPF; o padrão exige apenas um, então todos são ignorados.",
                    "Unificar os registros SPF em um único TXT.", weight: 3)
      end

      spf = records.first
      if (problem = spf_syntax_error(spf))
        return item("spf", SPF_TITLE, "fail",
                    "Registro SPF inválido (#{problem}): #{spf}. Os provedores tratam como se não houvesse SPF.",
                    "Reescrever o SPF como um único registro, com todos os serviços antes do final, " \
                    "ex.: v=spf1 include:_spf.google.com include:sendgrid.net ~all.", weight: 3)
      end

      last_term = spf.split.last.downcase
      if %w[+all all].include?(last_term)
        item("spf", SPF_TITLE, "fail",
             "O SPF termina em '#{last_term}', permitindo que qualquer servidor envie em nome do domínio.",
             "Trocar o final do SPF por ~all ou -all.", weight: 3)
      elsif last_term == "?all" || !last_term.end_with?("all")
        item("spf", SPF_TITLE, "warn", "SPF presente, mas neutro: #{spf}",
             "Terminar o SPF com ~all (ou -all quando todos os remetentes estiverem listados).", weight: 3)
      else
        item("spf", SPF_TITLE, "pass", spf, weight: 3)
      end
    end

    # Returns a description of the problem (shown to users) or nil when the syntax is valid.
    def spf_syntax_error(spf)
      return "duas definições 'v=spf1' no mesmo registro" if spf.scan(/v=spf1/i).size > 1

      terms = spf.split.drop(1)
      invalid = terms.find { !_1.match?(SPF_TERM) }
      return "termo inválido '#{invalid}'" if invalid

      all_index = terms.index { _1.match?(/\A[+\-~?]?all\z/i) }
      return "há regras depois do 'all', que são ignoradas" if all_index && all_index < terms.size - 1

      nil
    end

    def analyze_dmarc(txt_records)
      dmarc = txt_records.find { _1.downcase.start_with?("v=dmarc1") }
      if dmarc.nil?
        return item("dmarc", DMARC_TITLE, "fail", "Nenhum registro DMARC em _dmarc.",
                    "Criar o TXT _dmarc com 'v=DMARC1; p=none; rua=mailto:...' para monitorar e, depois de " \
                    "algumas semanas, evoluir para p=quarantine.", weight: 3)
      end

      tags = dmarc.split(";").filter_map do |part|
        key, value = part.split("=", 2)
        [ key.strip.downcase, value.strip.downcase ] if value
      end.to_h
      policy = tags.fetch("p", "none")

      if %w[quarantine reject].include?(policy)
        detail = "Política p=#{policy}."
        detail += " Subdomínios sem proteção (sp=none)." if tags["sp"] == "none"
        item("dmarc", DMARC_TITLE, "pass", detail, weight: 3)
      else
        item("dmarc", DMARC_TITLE, "warn", "O DMARC só monitora (p=#{policy}): e-mails falsificados ainda são entregues.",
             "Depois de conferir os relatórios, mudar a política para p=quarantine.", weight: 3)
      end
    end

    def analyze_dkim(selectors_found)
      if selectors_found.any?
        item("dkim", "DKIM (assinatura dos e-mails)", "pass",
             "Chave encontrada no(s) seletor(es): #{selectors_found.join(', ')}.", weight: 2)
      else
        item("dkim", "DKIM (assinatura dos e-mails)", "info",
             "Não encontrado nos seletores mais comuns. Pode existir com outro nome; confirme no painel do provedor de e-mail.",
             "Ativar a assinatura DKIM no provedor de e-mail (Google Workspace, Microsoft 365 etc.).", weight: 2)
      end
    end

    def analyze_mx(mx_hosts)
      return item("mx", "Servidor de e-mail (MX)", "info", "O domínio não recebe e-mail (sem MX).") if mx_hosts.empty?

      text = mx_hosts.join(" ").downcase
      provider = { "google" => "Google Workspace", "outlook" => "Microsoft 365", "zoho" => "Zoho",
                   "hostinger" => "Hostinger", "locaweb" => "Locaweb" }.find { |key, _| text.include?(key) }&.last
      detail = provider ? "Provedor identificado: #{provider}." : "MX: #{mx_hosts.first(3).join(', ')}"
      item("mx", "Servidor de e-mail (MX)", "info", detail)
    end

    # ------------------------------------------------------------ DNS

    # Lookup with one retry and, if Ruby's resolver keeps failing (e.g. a flaky
    # IPv6 DNS server on the router), falls back to the system `dig` command.
    def lookup(dns, name, type)
      resource = { "TXT" => Resolv::DNS::Resource::IN::TXT, "MX" => Resolv::DNS::Resource::IN::MX }.fetch(type)
      attempts = 0
      begin
        records = dns.getresources(name, resource)
        type == "TXT" ? records.map { _1.strings.join } : records.map { _1.exchange.to_s }
      rescue Resolv::ResolvError, Resolv::DNS::Requester::RequestError, Timeout::Error
        retry if (attempts += 1) < 2
        lookup_with_dig(name, type)
      end
    end

    def lookup_with_dig(name, type)
      output, status = Open3.capture2("dig", "+short", "+time=5", "+tries=2", type, name)
      raise Resolv::ResolvError, "dig failed" unless status.success?

      lines = output.lines.map(&:strip).reject { _1.empty? || _1.start_with?(";") }
      return lines.map { _1.split.last } if type == "MX"

      lines.map { |line| line.scan(/"((?:[^"\\]|\\.)*)"/).flatten.join } # joins "abc" "def" chunks
    end

    def run(domain)
      Resolv::DNS.open do |dns|
        dns.timeouts = [ 3, 5 ]
        mx_hosts = lookup(dns, domain, "MX")
        items = [
          analyze_mx(mx_hosts),
          analyze_spf(lookup(dns, domain, "TXT")),
          analyze_dmarc(lookup(dns, "_dmarc.#{domain}", "TXT"))
        ]
        if mx_hosts.any?
          found = DKIM_SELECTORS.select do |selector|
            lookup(dns, "#{selector}._domainkey.#{domain}", "TXT").any? { _1.include?("p=") }
          rescue StandardError
            false # one failing selector must not break the others
          end
          items << analyze_dkim(found)
        end
        items
      end
    rescue StandardError => e
      [ item("dns", "Consulta DNS", "error", "Falha ao consultar o DNS (#{e.class.name}).") ]
    end
  end
end
