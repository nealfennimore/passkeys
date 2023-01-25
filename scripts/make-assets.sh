#! /usr/bin/env bash

npx tailwindcss -i ./src/client/assets/tailwind.css -o ./src/client/assets/app.css 

cp src/client/assets/* build/

HASH=$(sha256sum build/index.js | awk '{print $1}')
mv build/index.js build/$HASH.bundle.js

sed -i "s/{{bundle.js}}/\/$HASH.bundle.js/g" build/index.html

HASH=$(sha256sum build/app.css | awk '{print $1}')
mv build/app.css build/$HASH.app.css

sed -i "s/app.css/\/$HASH.app.css/g" build/index.html