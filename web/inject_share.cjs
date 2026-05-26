const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, 'src', 'locales');
const files = fs.readdirSync(localesDir).filter(f => f.endsWith('.json') && f !== 'en.json');

const shareTranslations = {
  fr: {
    shareCredential: "Partager l'identifiant",
    securityNotice: "Les identifiants sont chiffrés dans votre navigateur avant l'envoi. La clé de déchiffrement vit uniquement dans le fragment de l'URL — le serveur ne la voit jamais.",
    linkExpiresIn: "Le lien expire dans",
    ttl1h: "1 heure",
    ttl24h: "24 heures",
    ttl7d: "7 jours",
    singleView: "Vue unique",
    singleViewDesc: "Le lien s'autodétruit après la première vue",
    generateShareLink: "Générer le lien de partage",
    linkCreated: "Lien de partage créé !",
    shareLink: "Lien de partage",
    expiresNote: "Expire : {{ttl}}",
    selfDestructNote: "S'autodétruit après la première vue",
    keyNote: "La clé de déchiffrement est dans le fragment de l'URL — jamais transmise au serveur",
    createAnother: "Créer un autre partage"
  },
  es: {
    shareCredential: "Compartir credencial",
    securityNotice: "Las credenciales se cifran en su navegador antes de enviarse. La clave de descifrado solo vive en el fragmento de la URL — el servidor nunca la ve.",
    linkExpiresIn: "El enlace expira en",
    ttl1h: "1 hora",
    ttl24h: "24 horas",
    ttl7d: "7 días",
    singleView: "Vista única",
    singleViewDesc: "El enlace se autodestruye tras la primera vista",
    generateShareLink: "Generar enlace de compartir",
    linkCreated: "¡Enlace de compartir creado!",
    shareLink: "Enlace de compartir",
    expiresNote: "Expira: {{ttl}}",
    selfDestructNote: "Se autodestruye tras la primera vista",
    keyNote: "La clave de descifrado está en el fragmento de la URL — nunca se transmite al servidor",
    createAnother: "Crear otro enlace"
  },
  de: {
    shareCredential: "Anmeldedaten teilen",
    securityNotice: "Die Anmeldedaten werden vor dem Hochladen in Ihrem Browser verschlüsselt. Der Entschlüsselungscode befindet sich nur im URL-Fragment — der Server sieht ihn nie.",
    linkExpiresIn: "Link läuft ab in",
    ttl1h: "1 Stunde",
    ttl24h: "24 Stunden",
    ttl7d: "7 Tage",
    singleView: "Einmalige Ansicht",
    singleViewDesc: "Link zerstört sich nach der ersten Ansicht selbst",
    generateShareLink: "Teilen-Link generieren",
    linkCreated: "Teilen-Link erstellt!",
    shareLink: "Teilen-Link",
    expiresNote: "Läuft ab: {{ttl}}",
    selfDestructNote: "Zerstört sich nach der ersten Ansicht selbst",
    keyNote: "Der Entschlüsselungscode ist im URL-Fragment — wird nie an den Server übertragen",
    createAnother: "Weiteren Teilen-Link erstellen"
  },
  it: {
    shareCredential: "Condividi credenziale",
    securityNotice: "Le credenziali vengono crittografate nel tuo browser prima del caricamento. La chiave di decrittografia risiede solo nel frammento dell'URL: il server non la vede mai.",
    linkExpiresIn: "Il link scade tra",
    ttl1h: "1 ora",
    ttl24h: "24 ore",
    ttl7d: "7 giorni",
    singleView: "Visualizzazione singola",
    singleViewDesc: "Il link si autodistrugge dopo la prima visualizzazione",
    generateShareLink: "Genera link di condivisione",
    linkCreated: "Link di condivisione creato!",
    shareLink: "Link di condivisione",
    expiresNote: "Scade: {{ttl}}",
    selfDestructNote: "Si autodistrugge dopo la prima visualizzazione",
    keyNote: "La chiave di decrittografia è nel frammento dell'URL: mai trasmessa al server",
    createAnother: "Crea un'altra condivisione"
  },
  pt: {
    shareCredential: "Compartilhar credencial",
    securityNotice: "As credenciais são criptografadas no seu navegador antes do envio. A chave de descriptografia vive apenas no fragmento da URL — o servidor nunca a vê.",
    linkExpiresIn: "O link expira em",
    ttl1h: "1 hora",
    ttl24h: "24 horas",
    ttl7d: "7 dias",
    singleView: "Visualização única",
    singleViewDesc: "O link se autodestrói após a primeira visualização",
    generateShareLink: "Gerar link de compartilhamento",
    linkCreated: "Link de compartilhamento criado!",
    shareLink: "Link de compartilhamento",
    expiresNote: "Expira: {{ttl}}",
    selfDestructNote: "Autodestrói após a primeira visualização",
    keyNote: "A chave de descriptografia está no fragmento da URL — nunca é transmitida ao servidor",
    createAnother: "Criar outro compartilhamento"
  },
  ja: {
    shareCredential: "クレデンシャルを共有",
    securityNotice: "クレデンシャルはアップロード前にブラウザで暗号化されます。復号キーはURLフラグメントにのみ存在し、サーバーには送信されません。",
    linkExpiresIn: "リンクの有効期限",
    ttl1h: "1時間",
    ttl24h: "24時間",
    ttl7d: "7日",
    singleView: "1回限り表示",
    singleViewDesc: "リンクは最初の表示後に自己破棄されます",
    generateShareLink: "共有リンクを生成",
    linkCreated: "共有リンクが作成されました！",
    shareLink: "共有リンク",
    expiresNote: "有効期限: {{ttl}}",
    selfDestructNote: "最初の表示後に自己破棄されます",
    keyNote: "復号キーはURLフラグメントにあり、サーバーには送信されません",
    createAnother: "別の共有を作成"
  },
  ko: {
    shareCredential: "자격 증명 공유",
    securityNotice: "자격 증명은 업로드 전 브라우저에서 암호화됩니다. 복호화 키는 URL 프래그먼트에만 존재하며 서버는 이를 절대 볼 수 없습니다.",
    linkExpiresIn: "링크 만료 기한",
    ttl1h: "1시간",
    ttl24h: "24시간",
    ttl7d: "7일",
    singleView: "1회 보기",
    singleViewDesc: "링크는 처음 본 후 자동 파기됩니다",
    generateShareLink: "공유 링크 생성",
    linkCreated: "공유 링크가 생성되었습니다!",
    shareLink: "공유 링크",
    expiresNote: "만료: {{ttl}}",
    selfDestructNote: "처음 본 후 자동 파기됨",
    keyNote: "복호화 키는 URL 프래그먼트에 있으며 서버로 전송되지 않습니다",
    createAnother: "다른 공유 생성"
  },
  zh: {
    shareCredential: "共享凭据",
    securityNotice: "凭据在上传前会在您的浏览器中加密。解密密钥仅存在于URL片段中 —— 服务器永远看不到它。",
    linkExpiresIn: "链接过期时间",
    ttl1h: "1小时",
    ttl24h: "24小时",
    ttl7d: "7天",
    singleView: "阅后即焚",
    singleViewDesc: "链接在首次查看后将自动销毁",
    generateShareLink: "生成共享链接",
    linkCreated: "共享链接已创建！",
    shareLink: "共享链接",
    expiresNote: "过期时间: {{ttl}}",
    selfDestructNote: "首次查看后自动销毁",
    keyNote: "解密密钥位于URL片段中 —— 永远不会传输到服务器",
    createAnother: "创建另一个共享"
  },
  ru: {
    shareCredential: "Поделиться учетными данными",
    securityNotice: "Учетные данные шифруются в вашем браузере перед отправкой. Ключ расшифровки находится только во фрагменте URL — сервер его никогда не видит.",
    linkExpiresIn: "Ссылка истекает через",
    ttl1h: "1 час",
    ttl24h: "24 часа",
    ttl7d: "7 дней",
    singleView: "Один просмотр",
    singleViewDesc: "Ссылка самоуничтожается после первого просмотра",
    generateShareLink: "Создать ссылку",
    linkCreated: "Ссылка создана!",
    shareLink: "Ссылка для обмена",
    expiresNote: "Истекает: {{ttl}}",
    selfDestructNote: "Самоуничтожается после первого просмотра",
    keyNote: "Ключ расшифровки находится во фрагменте URL — никогда не передается на сервер",
    createAnother: "Создать еще одну ссылку"
  },
  hi: {
    shareCredential: "क्रेडेंशियल साझा करें",
    securityNotice: "अपलोड करने से पहले क्रेडेंशियल आपके ब्राउज़र में एन्क्रिप्ट किए जाते हैं। डिक्रिप्शन कुंजी केवल URL फ़्रैगमेंट में रहती है — सर्वर इसे कभी नहीं देखता।",
    linkExpiresIn: "लिंक समाप्त होता है",
    ttl1h: "1 घंटा",
    ttl24h: "24 घंटे",
    ttl7d: "7 दिन",
    singleView: "एक बार देखें",
    singleViewDesc: "लिंक पहली बार देखने के बाद स्वतः नष्ट हो जाता है",
    generateShareLink: "साझा लिंक बनाएं",
    linkCreated: "साझा लिंक बन गया!",
    shareLink: "साझा लिंक",
    expiresNote: "समाप्त होता है: {{ttl}}",
    selfDestructNote: "पहली बार देखने के बाद स्वतः नष्ट हो जाता है",
    keyNote: "डिक्रिप्शन कुंजी URL फ़्रैगमेंट में है — सर्वर को कभी प्रेषित नहीं की जाती",
    createAnother: "एक और लिंक बनाएं"
  },
  ar: {
    shareCredential: "مشاركة بيانات الاعتماد",
    securityNotice: "يتم تشفير بيانات الاعتماد في متصفحك قبل التحميل. يوجد مفتاح فك التشفير فقط في جزء عنوان URL - ولا يراه الخادم أبدًا.",
    linkExpiresIn: "تنتهي صلاحية الرابط في",
    ttl1h: "ساعة واحدة",
    ttl24h: "24 ساعة",
    ttl7d: "7 أيام",
    singleView: "عرض لمرة واحدة",
    singleViewDesc: "يدمر الرابط نفسه بعد المشاهدة الأولى",
    generateShareLink: "إنشاء رابط مشاركة",
    linkCreated: "تم إنشاء رابط المشاركة!",
    shareLink: "رابط المشاركة",
    expiresNote: "ينتهي: {{ttl}}",
    selfDestructNote: "يدمر نفسه بعد المشاهدة الأولى",
    keyNote: "مفتاح فك التشفير موجود في جزء عنوان URL - ولا يتم نقله أبدًا إلى الخادم",
    createAnother: "إنشاء مشاركة أخرى"
  },
  id: {
    shareCredential: "Bagikan Kredensial",
    securityNotice: "Kredensial dienkripsi di peramban Anda sebelum diunggah. Kunci dekripsi hanya ada di fragmen URL — server tidak pernah melihatnya.",
    linkExpiresIn: "Tautan kedaluwarsa dalam",
    ttl1h: "1 jam",
    ttl24h: "24 jam",
    ttl7d: "7 hari",
    singleView: "Satu Kali Lihat",
    singleViewDesc: "Tautan hancur dengan sendirinya setelah dilihat pertama kali",
    generateShareLink: "Buat Tautan Bagikan",
    linkCreated: "Tautan bagikan dibuat!",
    shareLink: "Tautan Bagikan",
    expiresNote: "Kedaluwarsa: {{ttl}}",
    selfDestructNote: "Hancur dengan sendirinya setelah dilihat pertama kali",
    keyNote: "Kunci dekripsi ada di fragmen URL — tidak pernah dikirim ke server",
    createAnother: "Buat Tautan Lainnya"
  }
};

for (const file of files) {
  const lang = file.replace('.json', '');
  const filePath = path.join(localesDir, file);
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  if (!data.share) {
    data.share = {};
  }
  
  const translations = shareTranslations[lang] || shareTranslations.en; // Will fall back to whatever is there or undefined
  if (translations) {
    Object.assign(data.share, translations);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated share module for ${lang}`);
  }
}
