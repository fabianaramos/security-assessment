import { Controller } from "@hotwired/stimulus"

// Shows how many questions have been answered so far.
export default class extends Controller {
  static targets = ["progress"]

  connect() {
    this.count()
  }

  count() {
    const total = Number(this.progressTarget.dataset.total)
    const answered = new Set(
      [...this.element.querySelectorAll('input[type="radio"]:checked')].map((input) => input.name)
    ).size
    this.progressTarget.textContent = `${answered} de ${total} perguntas respondidas`
  }
}
