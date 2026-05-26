const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json'));

const translations = {
  en: {
    addCredential: {
      tags: {
        "2fa": "Two-Factor Auth",
        "2faDesc": "Phone number for SMS / app verification",
        "otp": "One-Time Password",
        "otpDesc": "TOTP secret for authenticator apps",
        "kba": "Security Questions",
        "kbaDesc": "Knowledge-based security answers",
        "u2f": "Hardware Key",
        "u2fDesc": "Physical security key (YubiKey etc.)"
      },
      otpTitle: "One-Time Password (OTP)",
      otpDesc: "TOTP secret for authenticator apps",
      mfaTitle: "Two-Factor Auth",
      mfaDesc: "Phone number for SMS / app verification",
      phoneNumberN: "Phone Number {{n}}",
      removePhoneNumber: "Remove Phone Number",
      addPhoneNumber: "Add Another Phone Number",
      kbaTitle: "Security Questions (KBA)",
      kbaDesc: "Knowledge-based security answers",
      questionN: "Question {{n}}",
      kbaQuestionPlaceholder: "What was the name of your first pet?",
      kbaAnswerPlaceholder: "Your answer",
      addQuestion: "Add Another Question",
      u2fTitle: "Hardware Key (U2F)",
      u2fDesc: "Physical security key (YubiKey etc.)",
      u2fKeyN: "Security Key {{n}}",
      removeU2fKey: "Remove Security Key",
      addU2fKey: "Add Another Security Key",
      toolbar: {
        bold: "Bold - toggle **text**",
        italic: "Italic - toggle *text*",
        underline: "Underline - toggle __text__",
        bulletList: "Bullet list",
        clear: "Remove formatting from selection"
      }
    }
  },
  fr: {
    addCredential: {
      tags: {
        "2fa": "Authentification à deux facteurs",
        "2faDesc": "Numéro de téléphone pour vérification SMS / application",
        "otp": "Mot de passe à usage unique",
        "otpDesc": "Secret TOTP pour les applications d'authentification",
        "kba": "Questions de sécurité",
        "kbaDesc": "Réponses de sécurité basées sur les connaissances",
        "u2f": "Clé matérielle",
        "u2fDesc": "Clé de sécurité physique (YubiKey etc.)"
      },
      otpTitle: "Mot de passe à usage unique (OTP)",
      otpDesc: "Secret TOTP pour les applications d'authentification",
      mfaTitle: "Authentification à deux facteurs",
      mfaDesc: "Numéro de téléphone pour vérification SMS / application",
      phoneNumberN: "Numéro de téléphone {{n}}",
      removePhoneNumber: "Supprimer le numéro de téléphone",
      addPhoneNumber: "Ajouter un autre numéro de téléphone",
      kbaTitle: "Questions de sécurité (KBA)",
      kbaDesc: "Réponses de sécurité basées sur les connaissances",
      questionN: "Question {{n}}",
      kbaQuestionPlaceholder: "Quel était le nom de votre premier animal de compagnie ?",
      kbaAnswerPlaceholder: "Votre réponse",
      addQuestion: "Ajouter une autre question",
      u2fTitle: "Clé matérielle (U2F)",
      u2fDesc: "Clé de sécurité physique (YubiKey etc.)",
      u2fKeyN: "Clé de sécurité {{n}}",
      removeU2fKey: "Supprimer la clé de sécurité",
      addU2fKey: "Ajouter une autre clé de sécurité",
      toolbar: {
        bold: "Gras - basculer le **texte**",
        italic: "Italique - basculer le *texte*",
        underline: "Souligné - basculer le __texte__",
        bulletList: "Liste à puces",
        clear: "Supprimer la mise en forme de la sélection"
      }
    }
  },
  ja: {
    addCredential: {
      tags: {
        "2fa": "2要素認証",
        "2faDesc": "SMS / アプリ認証用の電話番号",
        "otp": "ワンタイムパスワード",
        "otpDesc": "認証アプリ用のTOTPシークレット",
        "kba": "セキュリティ質問",
        "kbaDesc": "知識ベースのセキュリティ回答",
        "u2f": "ハードウェアキー",
        "u2fDesc": "物理セキュリティキー（YubiKeyなど）"
      },
      otpTitle: "ワンタイムパスワード（OTP）",
      otpDesc: "認証アプリ用のTOTPシークレット",
      mfaTitle: "2要素認証",
      mfaDesc: "SMS / アプリ認証用の電話番号",
      phoneNumberN: "電話番号 {{n}}",
      removePhoneNumber: "電話番号を削除",
      addPhoneNumber: "別の電話番号を追加",
      kbaTitle: "セキュリティ質問（KBA）",
      kbaDesc: "知識ベースのセキュリティ回答",
      questionN: "質問 {{n}}",
      kbaQuestionPlaceholder: "最初に飼ったペットの名前は？",
      kbaAnswerPlaceholder: "あなたの回答",
      addQuestion: "別の質問を追加",
      u2fTitle: "ハードウェアキー（U2F）",
      u2fDesc: "物理セキュリティキー（YubiKeyなど）",
      u2fKeyN: "セキュリティキー {{n}}",
      removeU2fKey: "セキュリティキーを削除",
      addU2fKey: "別のセキュリティキーを追加",
      toolbar: {
        bold: "太字 - **テキスト**を切り替え",
        italic: "斜体 - *テキスト*を切り替え",
        underline: "下線 - __テキスト__を切り替え",
        bulletList: "箇条書きリスト",
        clear: "選択範囲から書式を削除"
      }
    }
  }
};

for (const file of files) {
  const lang = file.replace('.json', '');
  const filePath = path.join(localesDir, file);
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  if (!data.addCredential) data.addCredential = {};
  
  const trans = translations[lang] || translations.en;
  
  // Merge recursively or just assign top-level keys
  data.addCredential = { ...data.addCredential, ...trans.addCredential };
  
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
  console.log(`Updated addCredential translations for ${lang}`);
}
