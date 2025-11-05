import { Controller } from "@hotwired/stimulus"

// Connects to data-controller="theme"
export default class extends Controller {
  static targets = ["selector"]
  static values = {
    default: { type: String, default: "hacker" }
  }

  // Theme registry for extensibility
  themes = {
    hacker: {
      name: "Hacker Mode",
      description: "Dark theme with terminal aesthetics"
    },
    professional: {
      name: "Professional Mode",
      description: "Light, clean, and business-friendly"
    }
  }

  connect() {
    // Apply theme before first paint to prevent flash
    this.applyTheme(this.getCurrentTheme())

    // Set the selector to the current theme if it exists
    if (this.hasSelectorTarget) {
      this.selectorTarget.value = this.getCurrentTheme()
    }
  }

  // Get current theme from localStorage or default
  getCurrentTheme() {
    const stored = localStorage.getItem('sectools-theme-preference')
    return stored && this.themes[stored] ? stored : this.defaultValue
  }

  // Handle theme selection change
  change(event) {
    const newTheme = event.target.value
    this.setTheme(newTheme)
  }

  // Set and persist theme
  setTheme(themeName) {
    if (!this.themes[themeName]) {
      console.warn(`Theme "${themeName}" not found, using default`)
      themeName = this.defaultValue
    }

    // Persist to localStorage
    localStorage.setItem('sectools-theme-preference', themeName)

    // Apply theme
    this.applyTheme(themeName)
  }

  // Apply theme to HTML element
  applyTheme(themeName) {
    document.documentElement.setAttribute('data-theme', themeName)

    // Dispatch custom event for other components to react to theme changes
    this.dispatch('changed', { detail: { theme: themeName } })
  }

  // Public method to get available themes
  getThemes() {
    return this.themes
  }
}
