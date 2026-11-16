require "test_helper"

class ChecksTest < ActiveSupport::TestCase
  # ---------- domain

  test "normalizes URLs and domains" do
    assert_equal "www.acme.com.br", Checks::Domain.normalize(" HTTPS://www.Acme.com.br/contato?x=1 ")
    assert_equal "acme.com.br", Checks::Domain.normalize("acme.com.br")
  end

  test "rejects input that is not a domain" do
    [ "", "localhost", "192.168.0.1", "não é domínio", "javascript:alert(1)" ].each do |input|
      assert_raises(Checks::InvalidDomain, input) { Checks::Domain.normalize(input) }
    end
  end

  test "root domain handles .com.br suffixes" do
    assert_equal "acme.com.br", Checks::Domain.root("www.acme.com.br")
    assert_equal "example.com", Checks::Domain.root("site.example.com")
  end

  test "blocks internal addresses" do
    %w[127.0.0.1 10.1.2.3 192.168.1.10 172.20.0.1 169.254.169.254 ::1 fd00::1 ::ffff:127.0.0.1].each do |ip|
      refute Checks::Domain.public?(ip), ip
    end
    assert Checks::Domain.public?("8.8.8.8")
  end

  # ---------- website

  def status_of(items, id) = items.find { _1["id"] == id }["status"]

  test "missing headers fail" do
    items = Checks::Web.analyze_headers({})
    assert_equal "fail", status_of(items, "hsts")
    assert_equal "fail", status_of(items, "clickjacking")
    assert_equal "fail", status_of(items, "nosniff")
    assert_equal "warn", status_of(items, "csp")
  end

  test "well-configured headers pass" do
    items = Checks::Web.analyze_headers(
      "strict-transport-security" => "max-age=31536000; includeSubDomains",
      "content-security-policy" => "default-src 'self'; frame-ancestors 'self'",
      "x-content-type-options" => "nosniff",
      "referrer-policy" => "strict-origin-when-cross-origin",
      "server" => "nginx"
    )
    assert items.all? { _1["status"] == "pass" }, items.inspect
  end

  test "short HSTS and exposed PHP version warn" do
    items = Checks::Web.analyze_headers("strict-transport-security" => "max-age=300", "x-powered-by" => "PHP/7.4.3")
    assert_equal "warn", status_of(items, "hsts")
    assert_equal "warn", status_of(items, "server_version")
  end

  test "redirect to https" do
    assert_equal "pass", Checks::Web.analyze_redirect([ "http://a.com/", "https://a.com/" ])["status"]
    assert_equal "fail", Checks::Web.analyze_redirect([ "http://a.com/" ])["status"]
  end

  test "detects outdated WordPress" do
    html = '<meta name="generator" content="WordPress 6.1.1" />'
    assert_equal "fail", status_of(Checks::Web.analyze_cms(html, "6.8.2"), "wp_version")
    assert_equal "warn", status_of(Checks::Web.analyze_cms(html, "6.1.1"), "wp_version")
    assert_equal "pass", status_of(Checks::Web.analyze_cms('<link href="/wp-content/x.css">'), "wp_version")
    assert_equal [ "cms" ], Checks::Web.analyze_cms("<html></html>").map { _1["id"] }
  end

  # ---------- certificate

  test "certificate expiry and protocol" do
    now = Time.utc(2026, 11, 15)
    assert_equal "pass", Checks::Tls.analyze_expiry(now + 60.days, now)["status"]
    assert_equal "warn", Checks::Tls.analyze_expiry(now + 5.days, now)["status"]
    assert_equal "fail", Checks::Tls.analyze_expiry(now - 1.day, now)["status"]
    assert_equal "fail", Checks::Tls.analyze_protocol("TLSv1")["status"]
  end

  # ---------- e-mail

  test "SPF" do
    email = Checks::Email
    assert_equal "fail", email.analyze_spf([])["status"]
    assert_equal "fail", email.analyze_spf([ "v=spf1 +all" ])["status"]
    assert_equal "fail", email.analyze_spf([ "v=spf1 ~all", "v=spf1 -all" ])["status"]
    assert_equal "warn", email.analyze_spf([ "v=spf1 include:x ?all" ])["status"]
    assert_equal "pass", email.analyze_spf([ "google-site-verification=abc", "v=spf1 include:_spf.google.com ~all" ])["status"]
    assert_equal "pass", email.analyze_spf([ "v=spf1 ip4:192.0.2.0/24 mx a:mail.x.com ip6:2001:db8::/32 include:x.com -all" ])["status"]
    assert_equal "warn", email.analyze_spf([ "v=spf1 include:x.com redirect=_spf.x.com" ])["status"]
  end

  test "malformed SPF fails" do
    email = Checks::Email
    # real-world case: two definitions glued together with a comma
    glued = "v=spf1 include:_spf.google.com ~all, v=spf1 include:sendgrid.net ~all include:_spf.rdstation.com.br ~all"
    result = email.analyze_spf([ glued ])
    assert_equal "fail", result["status"]
    assert_includes result["detail"], "duas definições"

    assert_includes email.analyze_spf([ "v=spf1 include:a.com ~all include:b.com" ])["detail"], "depois do 'all'"
    assert_includes email.analyze_spf([ "v=spf1 include:a.com, ~all" ])["detail"], "termo inválido"
  end

  test "DMARC" do
    email = Checks::Email
    assert_equal "fail", email.analyze_dmarc([])["status"]
    assert_equal "warn", email.analyze_dmarc([ "v=DMARC1; p=none; rua=mailto:a@b.com" ])["status"]
    assert_equal "pass", email.analyze_dmarc([ "v=DMARC1; p=quarantine" ])["status"]
  end

  test "DMARC flags unprotected subdomains" do
    assert_includes Checks::Email.analyze_dmarc([ "v=DMARC1;p=quarantine;sp=none" ])["detail"], "sp=none"
  end

  test "identifies the e-mail provider" do
    assert_includes Checks::Email.analyze_mx([ "aspmx.l.google.com." ])["detail"], "Google Workspace"
  end
end
