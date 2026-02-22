/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],
	darkMode: 'class',
	theme: {
		extend: {
			colors: {
				kryon: {
					50: '#e8f5e9',
					100: '#c8e6c9',
					200: '#a5d6a7',
					300: '#81c784',
					400: '#66bb6a',
					500: '#00e676',
					600: '#00c853',
					700: '#009624',
					800: '#1b2a1b',
					900: '#0d1a0d',
					950: '#060e06'
				}
			}
		}
	},
	plugins: []
};
