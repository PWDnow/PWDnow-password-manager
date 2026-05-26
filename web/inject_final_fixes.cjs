const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json'));

const updates = {
  en: {
    addCredential: { tagsLabel: "Tags" },
    vault: { card: "Card", secureNote: "Secure Note" }
  },
  fr: {
    addCredential: { tagsLabel: "Tags" },
    vault: { card: "Carte", secureNote: "Note Sécurisée" }
  },
  ja: {
    addCredential: { tagsLabel: "タグ" },
    vault: { card: "カード", secureNote: "安全なメモ" }
  },
  es: {
    addCredential: { tagsLabel: "Etiquetas" },
    vault: { card: "Tarjeta", secureNote: "Nota Segura" }
  },
  de: {
    addCredential: { tagsLabel: "Tags" },
    vault: { card: "Karte", secureNote: "Sichere Notiz" }
  },
  it: {
    addCredential: { tagsLabel: "Tag" },
    vault: { card: "Carta", secureNote: "Nota Sicura" }
  },
  pt: {
    addCredential: { tagsLabel: "Tags" },
    vault: { card: "Cartão", secureNote: "Nota Segura" }
  },
  ru: {
    addCredential: { tagsLabel: "Теги" },
    vault: { card: "Карта", secureNote: "Защищенная заметка" }
  },
  zh: {
    addCredential: { tagsLabel: "标签" },
    vault: { card: "卡片", secureNote: "安全备注" }
  },
  ar: {
    addCredential: { tagsLabel: "الوسوم" },
    vault: { card: "بطاقة", secureNote: "ملاحظة آمنة" }
  },
  hi: {
    addCredential: { tagsLabel: "टैग" },
    vault: { card: "कार्ड", secureNote: "सुरक्षित नोट" }
  },
  id: {
    addCredential: { tagsLabel: "Tag" },
    vault: { card: "Kartu", secureNote: "Catatan Aman" }
  },
  ko: {
    addCredential: { tagsLabel: "태그" },
    vault: { card: "카드", secureNote: "보안 메모" }
  }
};

for (const file of files) {
  const lang = file.replace('.json', '');
  const filePath = path.join(localesDir, file);
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  const trans = updates[lang] || updates.en;
  
  if (!data.addCredential) data.addCredential = {};
  if (!data.vault) data.vault = {};
  
  Object.assign(data.addCredential, trans.addCredential);
  Object.assign(data.vault, trans.vault);
  
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
  console.log(`Updated translations for ${lang}`);
}
