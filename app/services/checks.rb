# PASSIVE technical checks.
#
# They only read what the domain already exposes publicly: the home page (one
# GET, like any visitor), the TLS certificate and DNS records. No port scanning,
# brute force or intrusion testing. Even so, only run them against domains whose
# owner is aware of it.
module Checks
  class InvalidDomain < StandardError; end

  USER_AGENT = "SecurityAssessment/1.0 (academic project; passive checks)".freeze
  TIMEOUT = 10

  module_function

  # Returns [normalized_host, list_of_check_items].
  def run(input)
    host = Domain.normalize(input)
    Domain.ensure_public!(host)

    threads = [
      Thread.new { Web.run(host) },
      Thread.new { Tls.run(host) },
      Thread.new { Email.run(Domain.root(host)) }
    ]
    [ host, threads.flat_map(&:value) ]
  end

  # status: "pass" | "warn" | "fail" (scored) | "info" | "error" (not scored)
  # group, title, detail and recommendation are shown to users (Portuguese).
  def item(group, id, title, status, detail, recommendation = "", weight: 1)
    { "group" => group, "id" => id, "title" => title, "status" => status,
      "detail" => detail, "recommendation" => recommendation, "weight" => weight }
  end
end
