class Assessment < ApplicationRecord
  # Lets tests swap the network checks for a fake implementation.
  cattr_accessor :checker, default: ->(domain) { Checks.run(domain) }

  attribute :authorized, :boolean, default: false

  validates :organization, presence: { message: "Informe o nome da empresa." }
  validates :participants, numericality: { only_integer: true, greater_than: 0, allow_nil: true,
                                           message: "Informe um número inteiro maior que zero." }
  validates :authorized, acceptance: { accept: true,
                                       message: "Confirme que há autorização por escrito para verificar o domínio." },
                         if: -> { domain.present? && checks.blank? }
  validate :survey_complete

  before_save :compute_result

  scope :recent, -> { order(created_at: :desc) }

  # Runs the technical checks (when a domain was given). Returns false and
  # records the error when the domain is invalid.
  def run_checks
    return true if domain.blank?

    self.domain, self.checks = checker.call(domain)
    true
  rescue Checks::InvalidDomain => e
    errors.add(:domain, e.message)
    false
  end

  # Previous assessment of the same organization, used to show progress.
  def previous
    return if new_record?

    @previous ||= Assessment.where("lower(organization) = ?", organization.downcase)
                            .where("created_at < ?", created_at)
                            .recent.first
  end

  def level = result["level"]
  def action_plan = result.fetch("action_plan", [])
  def categories = result.dig("survey", "categories") || []
  def survey_score = result.dig("survey", "score")
  def checks_score = result.dig("checks", "score")

  def category_score(id)
    categories.find { _1["id"] == id }&.dig("score")
  end

  private

  def survey_complete
    valid = answers.to_h.select { |id, value| Survey.ids.include?(id) && Survey::ANSWER_VALUES.key?(value) }
    self.answers = valid
    missing = Survey::QUESTIONS.size - valid.size
    errors.add(:answers, "Responda todas as perguntas (faltam #{missing}).") if missing.positive?
  end

  def compute_result
    self.result = Scoring.calculate(answers, checks)
    self.overall_score = result["overall"]
  end
end
