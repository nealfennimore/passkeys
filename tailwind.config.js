/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ['./src/client/assets/*.{html,js}'],
    theme: {
        extend: {},
    },
    plugins: [require('@tailwindcss/forms')],
};
