module ApplicationHelper
  # status => [label shown to users, CSS modifier]
  STATUS_BADGES = {
    "pass" => [ "OK", "pass" ],
    "warn" => [ "Atenção", "warn" ],
    "fail" => [ "Falha", "fail" ],
    "info" => [ "Info", "info" ],
    "error" => [ "Não verificado", "info" ],
    # survey answers, which also appear in the action plan
    "yes" => [ "Sim", "pass" ],
    "partial" => [ "Em parte", "warn" ],
    "no" => [ "Não", "fail" ],
    "unknown" => [ "Não sei", "info" ]
  }.freeze

  PRIORITY_LABELS = { "high" => "Prioridade alta", "medium" => "Prioridade média", "low" => "Prioridade baixa" }.freeze

  def status_badge(status)
    label, modifier = STATUS_BADGES.fetch(status, [ status.to_s, "info" ])
    tag.span(label, class: "badge badge--#{modifier}")
  end

  def format_datetime(time)
    time.in_time_zone.strftime("%d/%m/%Y às %H:%M")
  end

  def score_class(score)
    return "score--empty" if score.nil?

    case score
    when 80.. then "score--advanced"
    when 60...80 then "score--intermediate"
    when 40...60 then "score--basic"
    else "score--critical"
    end
  end

  def score_delta(current, previous)
    return if current.nil? || previous.nil?

    diff = current - previous
    text = diff.zero? ? "sem variação" : format("%+d", diff)
    tag.span(text, class: [ "delta", ("delta--up" if diff.positive?), ("delta--down" if diff.negative?) ])
  end
end
