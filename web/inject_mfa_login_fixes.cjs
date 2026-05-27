const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json'));

const updates = {
  en: {
    login: { emailPlaceholder: "name@company.com" },
    mfa: {
      defaultKeyName: "My Security Key",
      defaultDeviceName: "My Device",
      defaultThisDevice: "This Device"
    }
  },
  fr: {
    login: { emailPlaceholder: "nom@entreprise.com" },
    mfa: {
      defaultKeyName: "Ma clé de sécurité",
      defaultDeviceName: "Mon appareil",
      defaultThisDevice: "Cet appareil"
    }
  },
  es: {
    login: { emailPlaceholder: "nombre@empresa.com" },
    mfa: {
      defaultKeyName: "Mi llave de seguridad",
      defaultDeviceName: "Mi dispositivo",
      defaultThisDevice: "Este dispositivo"
    }
  },
  de: {
    login: { emailPlaceholder: "name@unternehmen.com" },
    mfa: {
      defaultKeyName: "Mein Sicherheitsschlüssel",
      defaultDeviceName: "Mein Gerät",
      defaultThisDevice: "Dieses Gerät"
    }
  },
  ja: {
    login: { emailPlaceholder: "名前@会社.com" },
    mfa: {
      defaultKeyName: "マイセキュリティキー",
      defaultDeviceName: "マイデバイス",
      defaultThisDevice: "このデバイス"
    }
  },
  it: {
    login: { emailPlaceholder: "nome@azienda.com" },
    mfa: {
      defaultKeyName: "Mia chiave di sicurezza",
      defaultDeviceName: "Mio dispositivo",
      defaultThisDevice: "Questo dispositivo"
    }
  },
  pt: {
    login: { emailPlaceholder: "nome@empresa.com" },
    mfa: {
      defaultKeyName: "Minha chave de segurança",
      defaultDeviceName: "Meu dispositivo",
      defaultThisDevice: "Este dispositivo"
    }
  },
  ru: {
    login: { emailPlaceholder: "имя@компания.com" },
    mfa: {
      defaultKeyName: "Мой ключ безопасности",
      defaultDeviceName: "Мое устройство",
      defaultThisDevice: "Это устройство"
    }
  },
  zh: {
    login: { emailPlaceholder: "名字@公司.com" },
    mfa: {
      defaultKeyName: "我的安全密钥",
      defaultDeviceName: "我的设备",
      defaultThisDevice: "此设备"
    }
  },
  ar: {
    login: { emailPlaceholder: "الاسم@الشركة.com" },
    mfa: {
      defaultKeyName: "مفتاح الأمان الخاص بي",
      defaultDeviceName: "جهازي",
      defaultThisDevice: "هذا الجهاز"
    }
  },
  hi: {
    login: { emailPlaceholder: "नाम@कंपनी.com" },
    mfa: {
      defaultKeyName: "मेरी सुरक्षा कुंजी",
      defaultDeviceName: "मेरा डिवाइस",
      defaultThisDevice: "यह डिवाइस"
    }
  },
  id: {
    login: { emailPlaceholder: "nama@perusahaan.com" },
    mfa: {
      defaultKeyName: "Kunci Keamanan Saya",
      defaultDeviceName: "Perangkat Saya",
      defaultThisDevice: "Perangkat Ini"
    }
  },
  ko: {
    login: { emailPlaceholder: "이름@회사.com" },
    mfa: {
      defaultKeyName: "내 보안 키",
      defaultDeviceName: "내 장치",
      defaultThisDevice: "이 장치"
    }
  }
};

for (const file of files) {
  const lang = file.replace('.json', '');
  const filePath = path.join(localesDir, file);
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  const trans = updates[lang] || updates.en;
  
  if (!data.login) data.login = {};
  if (!data.mfa) data.mfa = {};
  
  Object.assign(data.login, trans.login);
  Object.assign(data.mfa, trans.mfa);
  
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
  console.log(`Updated login/mfa translations for ${lang}`);
}
