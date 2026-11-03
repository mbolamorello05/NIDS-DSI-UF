# Bibliothèques locales du dashboard

Ces fichiers sont servis par le dashboard lui-même : il fonctionne **sans accès
Internet** (réseau isolé, démo hors ligne). Ne pas les éditer à la main.

| Fichier | Origine |
|---|---|
| `daisyui.min.css` | daisyUI 4.12.10 (`dist/full.css`, minifié) |
| `chart.umd.js` | Chart.js 4.4.1 (`dist/chart.umd.js`) |
| `lucide.min.js` | Lucide 0.460.0 (`dist/umd/lucide.min.js`) |
| `tailwind.css` | Tailwind CSS 3.4.17, compilé **uniquement** pour les classes utilisées dans `index.html`, `login.html` et `script.js` |

## Si tu ajoutes une classe Tailwind dans index.html, login.html ou script.js

`tailwind.css` ne contient que les classes déjà utilisées : il faut le régénérer
(Node.js requis, une machine avec Internet suffit, une seule fois) :

```bash
cd dashboard/static
mkdir /tmp/tw && cd /tmp/tw && npm i --no-save tailwindcss@3.4.17 && cd -
echo '@tailwind base; @tailwind components; @tailwind utilities;' > /tmp/tw/in.css
/tmp/tw/node_modules/.bin/tailwindcss -i /tmp/tw/in.css -o vendor/tailwind.css --minify \
  --content "./index.html,./login.html,./script.js"
```

Les classes daisyUI (`btn`, `badge`, `card`...) n'ont pas besoin de ça.
