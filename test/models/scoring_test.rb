require "test_helper"

class ScoringTest < ActiveSupport::TestCase
  def all_answers(value) = Survey.ids.index_with { value }

  test "all yes without technical checks scores 100" do
    result = Scoring.calculate(all_answers("yes"))
    assert_equal 100, result["overall"]
    assert_equal "Avançado", result["level"]["name"]
    assert_empty result["action_plan"]
  end

  test "all no scores 0 and creates one action per question" do
    result = Scoring.calculate(all_answers("no"))
    assert_equal 0, result["overall"]
    assert_equal "Crítico", result["level"]["name"]
    assert_equal Survey::QUESTIONS.size, result["action_plan"].size
  end

  test "partial is worth half" do
    assert_equal 50, Scoring.calculate(all_answers("partial"))["overall"]
  end

  test "unknown counts as zero but is reported separately" do
    result = Scoring.calculate(all_answers("unknown"))
    assert_equal 0, result["overall"]
    assert_equal Survey::QUESTIONS.size, result["survey"]["unknown_count"]
  end

  test "overall score combines 60% survey and 40% checks" do
    checks = [
      { "id" => "a", "group" => "Site", "title" => "A", "status" => "pass", "weight" => 1 },
      { "id" => "b", "group" => "Site", "title" => "B", "status" => "fail", "weight" => 1 },
      { "id" => "c", "group" => "Site", "title" => "C", "status" => "info", "weight" => 1 } # not scored
    ]
    result = Scoring.calculate(all_answers("yes"), checks)
    assert_equal 50, result["checks"]["score"]
    assert_equal 80, result["overall"] # 0.6 * 100 + 0.4 * 50
    assert_equal [ "b" ], result["action_plan"].map { _1["id"] }
  end

  test "action plan starts with the highest-impact actions" do
    # impacts: 2FA e-mail (weight 3, no) = 3; access inventory (weight 2, partial) = 1; VPN (weight 1, partial) = 0.5
    answers = all_answers("yes").merge("q_2fa_email" => "no", "q_vpn" => "partial", "q_access_inventory" => "partial")
    plan = Scoring.calculate(answers)["action_plan"]
    assert_equal %w[q_2fa_email q_access_inventory q_vpn], plan.map { _1["id"] }
    assert_equal %w[high medium low], plan.map { _1["priority"] }
  end

  test "ties keep the survey order" do
    ids = Survey.ids.first(5)
    plan = Scoring.calculate(all_answers("yes").merge(ids.index_with { "no" }))["action_plan"]
    plan.group_by { _1["impact"] }.each_value { |group| assert_equal ids & group.map { _1["id"] }, group.map { _1["id"] } }
  end

  test "score per category" do
    answers = all_answers("yes").merge(Survey.by_category["accounts"].to_h { [ _1.id, "no" ] })
    accounts = Scoring.calculate(answers)["survey"]["categories"].find { _1["id"] == "accounts" }
    assert_equal 0, accounts["score"]
  end
end
