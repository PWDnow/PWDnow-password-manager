const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json'));

const extraTranslations = {
  es: {
    addCredential: {
      tags: { "2fa": "Doble factor", "2faDesc": "Teléfono para SMS / app", "otp": "OTP", "otpDesc": "Secreto TOTP", "kba": "Preguntas", "kbaDesc": "Respuestas de seguridad", "u2f": "Llave hardware", "u2fDesc": "Llave física (YubiKey)" },
      otpTitle: "Contraseña de un solo uso (OTP)",
      otpDesc: "Secreto TOTP para apps de autenticación",
      mfaTitle: "Doble Factor",
      mfaDesc: "Teléfono para verificación SMS / app",
      phoneNumberN: "Teléfono {{n}}",
      removePhoneNumber: "Eliminar teléfono",
      addPhoneNumber: "Añadir otro teléfono",
      kbaTitle: "Preguntas de seguridad (KBA)",
      kbaDesc: "Respuestas de seguridad",
      questionN: "Pregunta {{n}}",
      kbaQuestionPlaceholder: "¿Cuál era el nombre de su primera mascota?",
      kbaAnswerPlaceholder: "Su respuesta",
      addQuestion: "Añadir otra pregunta",
      u2fTitle: "Llave hardware (U2F)",
      u2fDesc: "Llave de seguridad física (YubiKey etc.)",
      u2fKeyN: "Llave de seguridad {{n}}",
      removeU2fKey: "Eliminar llave",
      addU2fKey: "Añadir otra llave",
      toolbar: { bold: "Negrita", italic: "Cursiva", underline: "Subrayado", bulletList: "Lista", clear: "Borrar formato" }
    }
  },
  de: {
    addCredential: {
      tags: { "2fa": "2FA", "2faDesc": "Telefon für SMS / App", "otp": "OTP", "otpDesc": "TOTP Geheimnis", "kba": "Sicherheitsfragen", "kbaDesc": "Wissensbasierte Antworten", "u2f": "Hardware-Key", "u2fDesc": "Physischer Key (YubiKey)" },
      otpTitle: "Einmalpasswort (OTP)",
      otpDesc: "TOTP-Geheimnis für Authentifikator-Apps",
      mfaTitle: "Zwei-Faktor-Auth",
      mfaDesc: "Telefonnummer für SMS / App-Verifizierung",
      phoneNumberN: "Telefonnummer {{n}}",
      removePhoneNumber: "Nummer entfernen",
      addPhoneNumber: "Weitere Nummer hinzufügen",
      kbaTitle: "Sicherheitsfragen (KBA)",
      kbaDesc: "Wissensbasierte Sicherheitsantworten",
      questionN: "Frage {{n}}",
      kbaQuestionPlaceholder: "Wie hieß Ihr erstes Haustier?",
      kbaAnswerPlaceholder: "Ihre Antwort",
      addQuestion: "Weitere Frage hinzufügen",
      u2fTitle: "Hardware-Schlüssel (U2F)",
      u2fDesc: "Physischer Sicherheitsschlüssel (YubiKey etc.)",
      u2fKeyN: "Sicherheitsschlüssel {{n}}",
      removeU2fKey: "Schlüssel entfernen",
      addU2fKey: "Weiteren Schlüssel hinzufügen",
      toolbar: { bold: "Fett", italic: "Kursiv", underline: "Unterstrichen", bulletList: "Liste", clear: "Formatierung löschen" }
    }
  },
  it: {
    addCredential: {
      tags: { "2fa": "2FA", "2faDesc": "Telefono per SMS / app", "otp": "OTP", "otpDesc": "Segreto TOTP", "kba": "Domande", "kbaDesc": "Risposte di sicurezza", "u2f": "Chiave hardware", "u2fDesc": "Chiave fisica (YubiKey)" },
      otpTitle: "Password monouso (OTP)",
      otpDesc: "Segreto TOTP per app di autenticazione",
      mfaTitle: "Autenticazione a due fattori",
      mfaDesc: "Telefono per verifica SMS / app",
      phoneNumberN: "Telefono {{n}}",
      removePhoneNumber: "Rimuovi telefono",
      addPhoneNumber: "Aggiungi altro telefono",
      kbaTitle: "Domande di sicurezza (KBA)",
      kbaDesc: "Risposte di sicurezza",
      questionN: "Domanda {{n}}",
      kbaQuestionPlaceholder: "Qual era il nome del tuo primo animale domestico?",
      kbaAnswerPlaceholder: "La tua risposta",
      addQuestion: "Aggiungi un'altra domanda",
      u2fTitle: "Chiave hardware (U2F)",
      u2fDesc: "Chiave di sicurezza fisica (YubiKey etc.)",
      u2fKeyN: "Chiave di sicurezza {{n}}",
      removeU2fKey: "Rimuovi chiave",
      addU2fKey: "Aggiungi un'altra chiave",
      toolbar: { bold: "Grassetto", italic: "Corsivo", underline: "Sottolineato", bulletList: "Elenco", clear: "Cancella formattazione" }
    }
  }
};

for (const [lang, trans] of Object.entries(extraTranslations)) {
  const filePath = path.join(localesDir, `${lang}.json`);
  if (fs.existsSync(filePath)) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!data.addCredential) data.addCredential = {};
    data.addCredential = { ...data.addCredential, ...trans.addCredential };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated extra addCredential translations for ${lang}`);
  }
}
