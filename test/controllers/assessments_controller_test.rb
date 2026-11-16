require "test_helper"

class AssessmentsControllerTest < ActionDispatch::IntegrationTest
  FAKE_CHECKER = lambda do |domain|
    raise Checks::InvalidDomain, "Domínio inválido." if domain == "invalid"

    [ "acme.com.br", [ { "id" => "hsts", "group" => "Site", "title" => "HSTS", "status" => "fail",
                         "detail" => "ausente", "recommendation" => "Ativar HSTS", "weight" => 2 } ] ]
  end

  setup do
    @original_checker = Assessment.checker
    Assessment.checker = FAKE_CHECKER
  end

  teardown { Assessment.checker = @original_checker }

  def answers(value = "yes") = Survey.ids.index_with { value }

  test "lists assessments and renders the form" do
    get root_path
    assert_response :success
    assert_select "td", text: "Acme Agency"

    get new_assessment_path
    assert_response :success
    assert_select ".question", Survey::QUESTIONS.size
  end

  test "creates an assessment with the survey only" do
    assert_difference("Assessment.count") do
      post assessments_path, params: { assessment: { organization: "Acme Agency", participants: 3 }, answers: answers }
    end
    assessment = Assessment.last
    assert_redirected_to assessment_path(assessment)
    assert_equal 100, assessment.overall_score

    follow_redirect!
    assert_select ".scorecard__value", /100/
    assert_select ".comparison", /40 → 100/ # compares with the earlier assessment (fixture)
  end

  test "creates an assessment with authorized technical checks" do
    post assessments_path, params: {
      assessment: { organization: "Acme Agency", domain: "https://acme.com.br", authorized: "1" }, answers: answers
    }
    assessment = Assessment.last
    assert_equal "acme.com.br", assessment.domain
    assert_equal 0, assessment.checks_score
    assert_equal 60, assessment.overall_score
  end

  test "requires authorization to check a domain" do
    assert_no_difference("Assessment.count") do
      post assessments_path, params: { assessment: { organization: "Acme Agency", domain: "acme.com.br" }, answers: answers }
    end
    assert_response :unprocessable_entity
    assert_select ".errors", /autorização/
  end

  test "shows invalid domain and incomplete survey errors" do
    post assessments_path, params: {
      assessment: { organization: "Acme Agency", domain: "invalid", authorized: "1" }, answers: answers
    }
    assert_response :unprocessable_entity
    assert_select ".errors", /Domínio inválido/

    post assessments_path, params: { assessment: { organization: "Acme Agency" }, answers: { "q_vpn" => "yes" } }
    assert_select ".errors", /faltam #{Survey::QUESTIONS.size - 1}/
  end

  test "deletes an assessment" do
    assert_difference("Assessment.count", -1) { delete assessment_path(assessments(:earlier)) }
    assert_redirected_to assessments_path
  end
end
