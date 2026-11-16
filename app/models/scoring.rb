# Computes the maturity score (0 to 100) and the prioritized action plan.
#
# Overall score = 60% survey + 40% technical checks (when both are present).
# Each item is worth: yes/pass = 100%, partial/warn = 50%, no/fail = 0%, scaled by its weight.
# Checks with status "info" or "error" do not count towards the score.
module Scoring
  SURVEY_WEIGHT = 0.6
  CHECKS_WEIGHT = 0.4

  STATUS_VALUES = { "pass" => 1.0, "warn" => 0.5, "fail" => 0.0 }.freeze

  # Level names and descriptions are shown to users, so they stay in Portuguese.
  LEVELS = [
    [ 80, "Avançado", "Boas práticas consolidadas; manter a rotina de revisão." ],
    [ 60, "Intermediário", "Base boa, mas com lacunas que ainda expõem a agência." ],
    [ 40, "Básico", "Algumas proteções existem, mas há riscos importantes em aberto." ],
    [ 0, "Crítico", "A agência está muito exposta; priorizar as ações de alto impacto." ]
  ].freeze

  module_function

  def level(score)
    return nil if score.nil?

    _, name, description = LEVELS.find { |minimum, *| score >= minimum }
    { "name" => name, "description" => description }
  end

  def priority(impact)
    if impact >= 2 then "high"
    elsif impact >= 1 then "medium"
    else "low"
    end
  end

  def calculate(answers, checks = [])
    survey = survey_score(answers || {})
    technical = checks_score(checks || [])

    overall =
      if survey[:score] && technical[:score]
        (SURVEY_WEIGHT * survey[:score] + CHECKS_WEIGHT * technical[:score]).round
      else
        survey[:score] || technical[:score]
      end

    actions = (survey[:actions] + technical[:actions])
      .each { |a| a["priority"] = priority(a["impact"]) }
      .each_with_index.sort_by { |a, i| [ -a["impact"], i ] }.map(&:first) # stable: ties keep survey order

    {
      "overall" => overall,
      "level" => level(overall),
      "survey" => survey.except(:actions).transform_keys(&:to_s),
      "checks" => { "score" => technical[:score] },
      "action_plan" => actions
    }
  end

  def survey_score(answers)
    totals = Survey::CATEGORIES.keys.index_with { { earned: 0.0, possible: 0.0 } }
    actions = []
    answered = unknown = 0

    Survey::QUESTIONS.each do |q|
      answer = answers[q.id]
      next unless Survey::ANSWER_VALUES.key?(answer) # unanswered questions are left out of the score

      answered += 1
      unknown += 1 if answer == "unknown"
      value = Survey::ANSWER_VALUES[answer]
      totals[q.category][:earned] += value * q.weight
      totals[q.category][:possible] += q.weight
      next if value >= 1

      actions << {
        "source" => "survey", "id" => q.id, "category" => Survey::CATEGORIES[q.category],
        "title" => q.text, "status" => answer, "recommendation" => q.recommendation,
        "impact" => (q.weight * (1 - value)).round(2)
      }
    end

    categories = Survey::CATEGORIES.map do |id, name|
      { "id" => id, "name" => name, "score" => percent(totals[id][:earned], totals[id][:possible]) }
    end

    {
      score: percent(totals.values.sum { _1[:earned] }, totals.values.sum { _1[:possible] }),
      categories: categories,
      answered: answered,
      total_questions: Survey::QUESTIONS.size,
      unknown_count: unknown,
      actions: actions
    }
  end

  def checks_score(checks)
    earned = possible = 0.0
    actions = []

    checks.each do |check|
      value = STATUS_VALUES[check["status"]]
      next if value.nil?

      weight = check.fetch("weight", 1)
      earned += value * weight
      possible += weight
      next if value >= 1

      actions << {
        "source" => "checks", "id" => check["id"], "category" => "Verificação técnica · #{check['group']}",
        "title" => check["title"], "status" => check["status"], "recommendation" => check["recommendation"],
        "impact" => (weight * (1 - value)).round(2)
      }
    end

    { score: percent(earned, possible), actions: actions }
  end

  def percent(earned, possible)
    possible.positive? ? (100 * earned / possible).round : nil
  end
end
