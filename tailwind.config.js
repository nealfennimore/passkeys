/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ['./src/client/**/*.{html,js}'],
    theme: {
        extend: {},
    },
    plugins: [require('@tailwindcss/forms')],
};
