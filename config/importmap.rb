# Pin npm packages by running ./bin/importmap

pin "application"
pin "@hotwired/turbo-rails", to: "turbo.min.js"
pin "@hotwired/stimulus", to: "stimulus.min.js"
pin "@hotwired/stimulus-loading", to: "stimulus-loading.js"
pin_all_from "app/javascript/controllers", under: "controllers"

# Markdown rendering and sanitization
pin "markdown-it", to: "https://cdn.jsdelivr.net/npm/markdown-it@14.1.0/dist/markdown-it.min.js"
pin "dompurify", to: "https://cdn.jsdelivr.net/npm/dompurify@3.0.8/dist/purify.min.js"
