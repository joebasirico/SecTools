# Styling Changes - Hacker Theme

## Overview
Transformed SecTools from a clean, modern UI to an edgy hacker aesthetic with dark grey backgrounds and green terminal-style text.

## Color Scheme

### Primary Colors
- **Background**: Dark grey (`bg-gray-900`, `bg-gray-800`)
- **Primary Text**: Green shades (`text-green-400`, `text-green-500`, `text-green-300`)
- **Accents**: Bright green (`border-green-500`, `border-green-600`)
- **Typography**: Monospace/Courier New font

### Severity Colors
- **Critical**: Red (`text-red-400`)
- **High**: Dark red (`text-red-500`)
- **Medium**: Yellow (`text-yellow-500`)
- **Low**: Light yellow (`text-yellow-400`)
- **Success**: Green (`text-green-300`)

## Key Visual Elements

### 1. ASCII Art Header
```
╔═══════════════════════════════════════════════════════╗
║  ███████╗███████╗ ██████╗████████╗ ██████╗  ██████╗  ║
║  ██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔═══██╗ ║
║  ███████╗█████╗  ██║        ██║   ██║   ██║██║   ██║ ║
║  ╚════██║██╔══╝  ██║        ██║   ██║   ██║██║   ██║ ║
║  ███████║███████╗╚██████╗   ██║   ╚██████╔╝╚██████╔╝ ║
║  ╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝  ║
╚═══════════════════════════════════════════════════════╝
```

### 2. Hacker Cards
- Dark grey background with green borders
- Glowing shadow effect on hover
- Pulsing animation (scan-line effect)
- Terminal-style indicators (▶, >, •)

### 3. Typography
- All text in monospace font (Courier New)
- Terminal-style prompts (>, [, ])
- Uppercase category labels
- Tracking and spacing adjustments

### 4. Interactive Elements
- Green buttons with dark text
- Glowing borders on focus
- Animated cursor (█)
- Hover effects with color transitions

## CSS Components

### Custom Classes

#### `.hacker-card`
```css
bg-gray-800
border-2 border-green-500
rounded-lg
p-6
shadow-lg shadow-green-500/20
hover:shadow-green-500/40
transition-all duration-300
hover:border-green-400
```

#### `.hacker-button`
```css
bg-green-600
text-gray-900
font-bold
px-6 py-3
rounded
hover:bg-green-500
transition-colors
border border-green-400
```

#### `.terminal-header`
```css
font-mono
text-green-400
tracking-wider
```

#### `.glitch`
```css
text-shadow: 0 0 10px rgba(34, 197, 94, 0.8)
```

#### `.scan-line`
Animated glow effect that pulses every 2 seconds

## Animations

### Scan Animation
```css
@keyframes scan {
  0% { box-shadow: 0 0 10px rgba(34, 197, 94, 0.3); }
  50% { box-shadow: 0 0 20px rgba(34, 197, 94, 0.6); }
  100% { box-shadow: 0 0 10px rgba(34, 197, 94, 0.3); }
}
```

### Pulse (built-in Tailwind)
Used for cursor animations and status indicators

## Layout Changes

### Homepage
- Full-screen dark background
- ASCII art logo
- System status bar with tool count
- Grid layout for tool cards
- Horizontal divider lines for categories
- Each tool in distinct glowing card

### Tool Page
- Dark theme maintained
- Form inputs with green borders
- Terminal-style labels with > prefix
- Results displayed in hacker-card format
- Monospace code display
- Color-coded severity warnings

## Responsive Design
All hacker theme elements are responsive:
- Cards stack on mobile (grid-cols-1)
- 2 columns on tablets (md:grid-cols-2)
- 3 columns on desktop (lg:grid-cols-3)
- ASCII art scales appropriately

## Browser Compatibility
- Modern browsers (Chrome, Firefox, Safari, Edge)
- CSS Grid and Flexbox
- Tailwind CSS utilities
- Custom CSS animations
- Web-safe fonts (Courier New fallback)

## Performance
- Minimal custom CSS
- Tailwind JIT compilation
- Optimized animations (GPU-accelerated)
- No external font loading
- Small asset footprint

## Accessibility Considerations
- Sufficient color contrast ratios
- Focus states on interactive elements
- Semantic HTML maintained
- Screen reader compatible
- Keyboard navigation support

## Future Enhancements
Potential additions to enhance the theme:
- Matrix-style falling characters background
- Terminal typing animation
- Sound effects on button clicks
- More elaborate glitch effects
- Scanline overlay effect
- CRT monitor simulation
- Custom cursor (terminal block)
- Loading animations with progress bars

## Files Modified

1. **app/assets/tailwind/application.css**
   - Added custom hacker theme components
   - Scan animation keyframes
   - Base body styling

2. **app/views/home/index.html.erb**
   - Complete redesign with ASCII art
   - Hacker-themed cards
   - Terminal-style navigation

3. **app/views/tools/show.html.erb**
   - Dark theme form inputs
   - Terminal-style labels
   - Hacker-themed result display
   - Updated helper methods

4. **app/views/layouts/application.html.erb**
   - Removed restrictive container
   - Full-height body support
   - Updated page title

## Testing
To test the new theme:
1. Start the dev server: `bin/dev`
2. Visit http://localhost:3000
3. Navigate through different tools
4. Test form submissions
5. Verify responsive behavior

## Reverting Changes
If you need to revert to the original theme:
1. Check out previous versions of modified files
2. Rebuild Tailwind: `rails tailwindcss:build`
3. Restart the server
