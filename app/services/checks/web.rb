require "net/http"
require "json"

module Checks
  # Website: HTTPS, redirect, security headers and exposed versions.
  module Web
    GROUP = "Site".freeze
    SIX_MONTHS = 15_552_000
    MAX_BODY = 512 * 1024
    REDIRECTS = [ 301, 302, 303, 307, 308 ].freeze

    Response = Data.define(:url, :status, :headers, :body, :chain)

    module_function

    def item(...) = Checks.item(GROUP, ...)

    # ------------------------------------------------------------ analysis (pure functions)

    def analyze_redirect(chain)
      if chain.last.to_s.start_with?("https://")
        item("redirect_https", "HTTP redireciona para HTTPS", "pass",
             "Quem digita o endereço sem https é levado à versão segura.", weight: 2)
      else
        item("redirect_https", "HTTP redireciona para HTTPS", "fail",
             "A versão sem criptografia (http://) continua acessível sem redirecionar.",
             "Configurar redirecionamento 301 de http:// para https:// na hospedagem ou no CMS.", weight: 2)
      end
    end

    # headers: hash with lowercase keys
    def analyze_headers(headers)
      items = []

      hsts = headers["strict-transport-security"].to_s
      max_age = hsts[/max-age=(\d+)/, 1].to_i
      items <<
        if hsts.empty?
          item("hsts", "HSTS (forçar HTTPS no navegador)", "fail", "Cabeçalho Strict-Transport-Security ausente.",
               "Ativar o cabeçalho Strict-Transport-Security com max-age de pelo menos 6 meses.", weight: 2)
        elsif max_age < SIX_MONTHS
          item("hsts", "HSTS (forçar HTTPS no navegador)", "warn", "HSTS com validade curta: #{hsts}",
               "Aumentar o max-age do HSTS para pelo menos 15552000 (6 meses).", weight: 2)
        else
          item("hsts", "HSTS (forçar HTTPS no navegador)", "pass", hsts, weight: 2)
        end

      csp = headers["content-security-policy"].to_s
      xfo = headers["x-frame-options"].to_s
      items <<
        if xfo.present? || csp.include?("frame-ancestors")
          item("clickjacking", "Proteção contra clickjacking", "pass",
               xfo.present? ? "X-Frame-Options: #{xfo}" : "CSP com frame-ancestors.")
        else
          item("clickjacking", "Proteção contra clickjacking", "fail",
               "O site pode ser embutido em páginas de terceiros (iframe).",
               "Adicionar o cabeçalho X-Frame-Options: SAMEORIGIN ou CSP frame-ancestors 'self'.")
        end

      items <<
        if headers["x-content-type-options"].to_s.casecmp?("nosniff")
          item("nosniff", "X-Content-Type-Options", "pass", "nosniff")
        else
          item("nosniff", "X-Content-Type-Options", "fail",
               "Cabeçalho ausente: o navegador pode interpretar arquivos com o tipo errado.",
               "Adicionar o cabeçalho X-Content-Type-Options: nosniff.")
        end

      items <<
        if csp.present?
          item("csp", "Content-Security-Policy", "pass", "Política de conteúdo definida.")
        else
          item("csp", "Content-Security-Policy", "warn",
               "Sem política de conteúdo: menos proteção contra scripts injetados (XSS).",
               "Definir uma Content-Security-Policy, começando em modo Report-Only para não quebrar o site.")
        end

      items <<
        if headers["referrer-policy"].present?
          item("referrer", "Referrer-Policy", "pass", headers["referrer-policy"])
        else
          item("referrer", "Referrer-Policy", "warn",
               "Sem Referrer-Policy: endereços completos podem vazar para outros sites.",
               "Adicionar Referrer-Policy: strict-origin-when-cross-origin.")
        end

      leaks = []
      leaks << "Server: #{headers['server']}" if headers["server"].to_s.match?(/\d/)
      leaks << "X-Powered-By: #{headers['x-powered-by']}" if headers["x-powered-by"].present?
      items <<
        if leaks.any?
          item("server_version", "Versão do servidor exposta", "warn", leaks.join("; "),
               "Ocultar a versão do servidor e do PHP nos cabeçalhos (ex.: expose_php = Off).")
        else
          item("server_version", "Versão do servidor exposta", "pass", "Os cabeçalhos não revelam versões de software.")
        end

      items
    end

    def analyze_cms(html, latest_wordpress = nil)
      generator = html[/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i, 1].to_s
      wordpress = generator.downcase.include?("wordpress") || html.include?("/wp-content/") || html.include?("/wp-includes/")

      unless wordpress
        detail = generator.present? ? "Gerador identificado: #{generator}" : "Nenhum CMS conhecido identificado."
        return [ item("cms", "CMS identificado", "info", detail) ]
      end

      items = [ item("cms", "CMS identificado", "info", "WordPress detectado.") ]
      version = generator[/wordpress\s+([\d.]+)/i, 1]

      items <<
        if version.nil?
          item("wp_version", "Versão do WordPress exposta", "pass", "A versão do WordPress não aparece no código da página.")
        elsif latest_wordpress && Gem::Version.new(version) < Gem::Version.new(latest_wordpress)
          item("wp_version", "WordPress desatualizado", "fail",
               "Versão #{version} em uso; a mais recente é #{latest_wordpress}.",
               "Atualizar o WordPress (com backup antes) e remover a meta tag 'generator'.", weight: 3)
        else
          item("wp_version", "Versão do WordPress exposta", "warn",
               "A página revela a versão #{version} na meta tag 'generator'.",
               "Remover a meta tag 'generator' para não facilitar ataques direcionados à versão.")
        end
      items
    end

    # ------------------------------------------------------------ network

    def fetch(url)
      uri = URI(url)
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                      open_timeout: TIMEOUT, read_timeout: TIMEOUT, ssl_timeout: TIMEOUT) do |http|
        request = Net::HTTP::Get.new(uri.request_uri, "User-Agent" => USER_AGENT, "Accept" => "text/html,*/*")
        http.request(request) do |response|
          body = +""
          response.read_body do |chunk|
            body << chunk
            break if body.bytesize > MAX_BODY
          end
          headers = response.each_header.to_h # Net::HTTP already lowercases the keys
          return [ response.code.to_i, headers, body.force_encoding("UTF-8").scrub ]
        end
      end
    end

    def follow(url, limit: 5)
      chain = [ url ]
      (limit + 1).times do
        status, headers, body = fetch(url)
        if REDIRECTS.include?(status) && headers["location"].present?
          url = URI.join(url, headers["location"]).to_s
          chain << url
          next
        end
        return Response.new(url, status, headers, body, chain)
      end
      raise "Too many redirects"
    end

    def latest_wordpress_version
      uri = URI("https://api.wordpress.org/core/version-check/1.7/")
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: TIMEOUT, read_timeout: TIMEOUT) do |http|
        http.get(uri.request_uri, "User-Agent" => USER_AGENT)
      end
      JSON.parse(response.body).dig("offers", 0, "current")
    rescue StandardError
      nil
    end

    # ------------------------------------------------------------ orchestration

    def run(host)
      items = []
      begin
        response = follow("https://#{host}/")
        items << item("https", "Site acessível por HTTPS", "pass",
                      "Respondeu com status #{response.status} em #{response.url}", weight: 3)
      rescue OpenSSL::SSL::SSLError => e
        return [ item("https", "Site acessível por HTTPS", "fail", "Erro de certificado/TLS: #{e.message.truncate(120)}",
                      "Instalar um certificado válido (ex.: Let's Encrypt, gratuito) com renovação automática.", weight: 3) ]
      rescue StandardError => e
        return [ item("https", "Site acessível por HTTPS", "error", "Não foi possível acessar https://#{host}/ (#{e.class.name}).") ]
      end

      begin
        items << analyze_redirect(follow("http://#{host}/").chain)
      rescue StandardError => e
        items << item("redirect_https", "HTTP redireciona para HTTPS", "info",
                      "A porta 80 (http) não respondeu (#{e.class.name}).")
      end

      items.concat(analyze_headers(response.headers)) if response.url.start_with?("https://")
      wordpress = response.body.include?("wp-content") || response.body.match?(/wordpress/i)
      items.concat(analyze_cms(response.body, wordpress ? latest_wordpress_version : nil))
    end
  end
end
