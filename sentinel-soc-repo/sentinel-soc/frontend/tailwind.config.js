/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#070b14',
          panel: '#0f172a',
          card: '#131d31',
          border: '#1e293b',
          cyan: '#06b6d4',
          blue: '#3b82f6'
        }
      }
    }
  },
  plugins: []
};
