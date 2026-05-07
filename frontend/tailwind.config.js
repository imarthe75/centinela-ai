/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: "#0F172A",
        secondary: "#334155",
        accent: "#06B6D4",
        danger: "#EF4444",
        warning: "#F59E0B",
        success: "#10B981",
        card: "#1E293B",
        border: "#334155"
      },
      fontFamily: {
        heading: ['Montserrat', 'sans-serif'],
        sans: ['Open Sans', 'sans-serif'],
      },
      boxShadow: {
        'neon': '0 0 15px rgba(6, 182, 212, 0.2)',
      },
      animation: {
        'spin-slow': 'spin 8s linear infinite',
      }
    },
  },
  plugins: [],
}
