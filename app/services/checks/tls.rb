require "openssl"
require "socket"

module Checks
  # TLS certificate: trust, expiry and protocol version.
  module Tls
    GROUP = "Certificado".freeze

    module_function

    def item(...) = Checks.item(GROUP, ...)

    def analyze_expiry(expires_at, now = Time.now)
      days = ((expires_at - now) / 86_400).floor
      date = expires_at.strftime("%d/%m/%Y")
      if days.negative?
        item("cert_expiry", "Validade do certificado", "fail", "Certificado vencido em #{date}.",
             "Renovar o certificado imediatamente e ativar a renovação automática.", weight: 3)
      elsif days < 14
        item("cert_expiry", "Validade do certificado", "warn", "Vence em #{days} dias (#{date}).",
             "Confirmar que a renovação automática do certificado está funcionando.", weight: 3)
      else
        item("cert_expiry", "Validade do certificado", "pass", "Válido até #{date} (#{days} dias).", weight: 3)
      end
    end

    def analyze_protocol(version)
      if %w[TLSv1.2 TLSv1.3].include?(version)
        item("tls_version", "Versão do protocolo TLS", "pass", "Conexão negociada com #{version}.")
      else
        item("tls_version", "Versão do protocolo TLS", "fail", "Conexão negociada com #{version}, considerado inseguro.",
             "Desativar TLS 1.0/1.1 na hospedagem e manter apenas TLS 1.2 e 1.3.")
      end
    end

    def run(host)
      context = OpenSSL::SSL::SSLContext.new
      context.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER)

      tcp = Socket.tcp(host, 443, connect_timeout: TIMEOUT)
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, context)
      ssl.hostname = host
      ssl.sync_close = true
      ssl.connect
      ssl.post_connection_check(host)
      cert = ssl.peer_cert
      version = ssl.ssl_version
      ssl.close

      issuer = cert.issuer.to_a.find { _1[0] == "O" }&.dig(1) || "autoridade reconhecida"
      [
        item("cert_trusted", "Certificado confiável", "pass", "Emitido por #{issuer}.", weight: 3),
        analyze_expiry(cert.not_after),
        analyze_protocol(version)
      ]
    rescue OpenSSL::SSL::SSLError => e
      [ item("cert_trusted", "Certificado confiável", "fail",
             "O navegador não confia no certificado: #{e.message.truncate(140)}",
             "Instalar um certificado de autoridade reconhecida (ex.: Let's Encrypt) que cubra este domínio.", weight: 3) ]
    rescue StandardError => e
      [ item("cert_trusted", "Certificado confiável", "error", "Não foi possível conectar na porta 443 (#{e.class.name}).") ]
    end
  end
end
