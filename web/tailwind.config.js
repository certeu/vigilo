/** @type {import('tailwindcss').Config} */
// Design language: Stripe-minimalism, cool near-white, one cobalt
// accent, a desaturated severity ramp used ONLY on severity markers. Space Grotesk
// for display/numerals, IBM Plex Sans for body, IBM Plex Mono for evidence.
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#FBFBFD",
        surface: "#FFFFFF",
        ink: "#12161F",
        slate: "#606A7B",
        line: "#E7E9EE",
        accent: "#3B5BDB",
        severity: {
          critical: "#B4232C",
          high: "#C2410C",
          medium: "#B45309",
          low: "#4B5563",
          info: "#677082",
        },
        // Analyst hints (grey-box steering): the only use of this hue.
        hint: {
          DEFAULT: "#6D28D9",
          soft: "#F5F3FF",
          line: "#C4B5FD",
          ink: "#5B21B6",
        },
      },
      fontFamily: {
        display: ['"Space Grotesk"', "system-ui", "sans-serif"],
        body: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(18,22,31,0.04), 0 1px 3px rgba(18,22,31,0.06)",
      },
    },
  },
  plugins: [],
};
