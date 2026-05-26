const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json') && f !== 'en.json');

const invalidOtpSecretTranslations = {
  ar: { "invalidOtpSecret": "مفتاح سر OTP غير صالح" },
  de: { "invalidOtpSecret": "Ungültiger OTP-Geheimschlüssel" },
  es: { "invalidOtpSecret": "Clave secreta OTP no válida" },
  fr: { "invalidOtpSecret": "Clé secrète OTP invalide" },
  hi: { "invalidOtpSecret": "अमान्य OTP गुप्त कुंजी" },
  id: { "invalidOtpSecret": "Kunci rahasia OTP tidak valid" },
  it: { "invalidOtpSecret": "Chiave segreta OTP non valida" },
  ja: { "invalidOtpSecret": "無効なOTP秘密キー" },
  ko: { "invalidOtpSecret": "잘못된 OTP 비밀 키" },
  pt: { "invalidOtpSecret": "Chave secreta OTP inválida" },
  ru: { "invalidOtpSecret": "Неверный секретный ключ OTP" },
  zh: { "invalidOtpSecret": "无效的OTP密钥" }
};

for (const file of files) {
  const lang = file.replace('.json', '');
  const filePath = path.join(localesDir, file);
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  if (data.vault && invalidOtpSecretTranslations[lang]) {
    data.vault.invalidOtpSecret = invalidOtpSecretTranslations[lang].invalidOtpSecret;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated invalidOtpSecret for ${lang}`);
  }
}
