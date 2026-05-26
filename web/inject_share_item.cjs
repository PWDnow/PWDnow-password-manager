const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json') && f !== 'en.json');

const shareItemTranslations = {
  ar: { "shareItem": "مشاركة العنصر" },
  de: { "shareItem": "Element teilen" },
  es: { "shareItem": "Compartir elemento" },
  fr: { "shareItem": "Partager l'élément" },
  hi: { "shareItem": "आइटम साझा करें" },
  id: { "shareItem": "Bagikan Item" },
  it: { "shareItem": "Condividi elemento" },
  ja: { "shareItem": "アイテムを共有" },
  ko: { "shareItem": "항목 공유" },
  pt: { "shareItem": "Compartilhar item" },
  ru: { "shareItem": "Поделиться элементом" },
  zh: { "shareItem": "共享项目" }
};

for (const file of files) {
  const lang = file.replace('.json', '');
  const filePath = path.join(localesDir, file);
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  if (data.vault && shareItemTranslations[lang]) {
    data.vault.shareItem = shareItemTranslations[lang].shareItem;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated shareItem for ${lang}`);
  }
}
