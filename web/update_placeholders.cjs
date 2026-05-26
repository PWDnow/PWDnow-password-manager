const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const updates = {
  ar: { "emailPlaceholder": "الاسم@مثال.com" },
  hi: { "emailPlaceholder": "नाम@उदाहरण.com" },
  id: { "emailPlaceholder": "nama@contoh.com" },
  ja: { "emailPlaceholder": "名前@example.com" },
  ko: { "emailPlaceholder": "이름@example.com" },
  ru: { "emailPlaceholder": "имя@пример.com" },
  zh: { "emailPlaceholder": "名字@example.com" }
};

for (const [lang, translations] of Object.entries(updates)) {
  const filePath = path.join(localesDir, `${lang}.json`);
  if (fs.existsSync(filePath)) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (data.assetHolder) {
      Object.assign(data.assetHolder, translations);
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
      console.log(`Updated ${lang}.json placeholder`);
    }
  }
}
