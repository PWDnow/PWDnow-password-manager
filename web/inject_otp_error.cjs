const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json') && f !== 'en.json');

const otpErrorTranslations = {
  ar: { "otpError": "خطأ" },
  de: { "otpError": "Fehler" },
  es: { "otpError": "Error" },
  fr: { "otpError": "Erreur" },
  hi: { "otpError": "त्रुटि" },
  id: { "otpError": "Kesalahan" },
  it: { "otpError": "Errore" },
  ja: { "otpError": "エラー" },
  ko: { "otpError": "오류" },
  pt: { "otpError": "Erro" },
  ru: { "otpError": "Ошибка" },
  zh: { "otpError": "错误" }
};

for (const file of files) {
  const lang = file.replace('.json', '');
  const filePath = path.join(localesDir, file);
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  if (data.vault && otpErrorTranslations[lang]) {
    data.vault.otpError = otpErrorTranslations[lang].otpError;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated otpError for ${lang}`);
  }
}
