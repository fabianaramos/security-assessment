class AssessmentsController < ApplicationController
  def index
    @assessments = Assessment.recent
  end

  def new
    base = Assessment.find_by(id: params[:repeat])
    @assessment = Assessment.new(organization: base&.organization, domain: base&.domain)
  end

  def create
    @assessment = Assessment.new(assessment_params)
    @assessment.answers = params.fetch(:answers, {}).permit(*Survey.ids).to_h

    # Validate the form before touching the network; only then run the checks.
    if @assessment.valid? && @assessment.run_checks && @assessment.save
      redirect_to @assessment, notice: "Diagnóstico concluído."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def show
    @assessment = Assessment.find(params[:id])
  end

  def destroy
    Assessment.find(params[:id]).destroy!
    redirect_to assessments_path, notice: "Avaliação excluída.", status: :see_other
  end

  private

  def assessment_params
    params.require(:assessment).permit(:organization, :domain, :participants, :notes, :authorized)
  end
end
