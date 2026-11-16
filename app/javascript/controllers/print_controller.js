import { Controller } from "@hotwired/stimulus"

// Opens the print dialog (browsers offer "Save as PDF").
export default class extends Controller {
  print() {
    window.print()
  }
}
