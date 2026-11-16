require "ipaddr"
require "resolv"
require "uri"

module Checks
  # Validates the domain entered by the user and blocks internal addresses
  # (localhost, private networks) so the server cannot be misused (SSRF).
  module Domain
    HOST_RE = /\A(?=.{1,253}\z)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/

    # Common two-level suffixes (company.com.br -> root company.com.br).
    DOUBLE_SUFFIXES = %w[
      com.br net.br org.br eng.br arq.br art.br adv.br ind.br inf.br imb.br
      srv.br tec.br blog.br app.br dev.br ong.br co.uk com.ar com.pt
    ].freeze

    BLOCKED_NETWORKS = %w[
      0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
      192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 ::/128 ::1/128 fc00::/7 fe80::/10 ff00::/8
    ].map { IPAddr.new(_1) }.freeze

    module_function

    # Accepts "company.com.br", "https://www.company.com.br/contact" etc.
    def normalize(input)
      text = input.to_s.strip.downcase
      raise InvalidDomain, "Informe um domínio." if text.empty?

      text = "http://#{text}" unless text.include?("://")
      host = URI.parse(text).host.to_s.delete_suffix(".")
      raise InvalidDomain, "Domínio inválido. Exemplo: minhaagencia.com.br" unless host.match?(HOST_RE)

      host
    rescue URI::InvalidURIError
      raise InvalidDomain, "Domínio inválido. Exemplo: minhaagencia.com.br"
    end

    # www.company.com.br -> company.com.br (used for SPF/DMARC/DKIM)
    def root(host)
      labels = host.split(".")
      size = labels.size >= 3 && DOUBLE_SUFFIXES.include?(labels.last(2).join(".")) ? 3 : 2
      labels.last(size).join(".")
    end

    def public?(ip)
      address = IPAddr.new(ip)
      address = address.native if address.ipv4_mapped?
      BLOCKED_NETWORKS.none? { _1.family == address.family && _1.include?(address) }
    end

    def ensure_public!(host)
      ips = Resolv.getaddresses(host)
      raise InvalidDomain, "Não foi possível encontrar esse domínio (o DNS não resolve)." if ips.empty?
      return if ips.all? { public?(_1) }

      raise InvalidDomain, "O domínio aponta para um endereço interno; verificação bloqueada."
    end
  end
end
