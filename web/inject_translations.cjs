const fs = require('fs');
const path = require('path');

const locales = ['ar', 'de', 'en', 'es', 'fr', 'hi', 'id', 'it', 'ja', 'ko', 'pt', 'ru', 'zh'];

const translations = {
  en: {
    health: {
      title: "Vault Health",
      subtitle: "A real-time audit of your vault passwords - weak, reused, and known-compromised passwords.",
      basedOn: "Based on {{count}} credentials with passwords",
      excellent: "Excellent",
      good: "Good",
      fair: "Fair",
      poor: "Poor",
      compromised: "Compromised",
      compromisedDesc: "Found in known breach lists",
      weak: "Weak",
      weakDesc: "Short or simple passwords",
      reused: "Reused",
      reusedDesc: "Same password across accounts",
      healthy: "Healthy",
      healthyDesc: "No issues detected",
      issuesFound: "Issues Found ({{count}})",
      goToVault: "Go to Vault",
      allClear: "All Clear",
      allClearDesc: "No weak, reused, or compromised passwords detected.",
      noCredentials: "No credentials with passwords found.",
      compromisedCheck: "Compromised Check",
      compromisedCheckDesc: "Matches against 500+ passwords from the rockyou.txt top entries and HIBP research. Run the Breach Monitor for a deeper scan using the full 900M+ HIBP dataset.",
      strengthAnalysis: "Strength Analysis",
      strengthAnalysisDesc: "Evaluates length, character diversity (uppercase, lowercase, numbers, symbols). Passwords scoring ≤ 1/5 are flagged as weak.",
      reuseDetection: "Reuse Detection",
      reuseDetectionDesc: "Identifies passwords shared across multiple accounts. All comparisons happen locally - your passwords never leave this page."
    },
    assetHolder: {
      configureTemplates: "Configure template values for credentials.",
      emailAddresses: "Email Addresses",
      phoneNumbers: "Phone Numbers",
      securityKeys: "Security Keys (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "Security Key Name",
      invalidEmail: "Invalid email format",
      saveTemplates: "Save Templates"
    }
  },
  fr: {
    health: {
      title: "Santé du Coffre",
      subtitle: "Un audit en temps réel de vos mots de passe - faibles, réutilisés et compromis.",
      basedOn: "Basé sur {{count}} identifiants avec mots de passe",
      excellent: "Excellent",
      good: "Bon",
      fair: "Moyen",
      poor: "Faible",
      compromised: "Compromis",
      compromisedDesc: "Trouvé dans des listes de fuites connues",
      weak: "Faible",
      weakDesc: "Mots de passe courts ou simples",
      reused: "Réutilisé",
      reusedDesc: "Même mot de passe sur plusieurs comptes",
      healthy: "Sain",
      healthyDesc: "Aucun problème détecté",
      issuesFound: "Problèmes trouvés ({{count}})",
      goToVault: "Aller au Coffre",
      allClear: "Tout est bon",
      allClearDesc: "Aucun mot de passe faible, réutilisé ou compromis détecté.",
      noCredentials: "Aucun identifiant avec mot de passe trouvé.",
      compromisedCheck: "Vérification de compromission",
      compromisedCheckDesc: "Correspondances avec plus de 500 mots de passe du top rockyou.txt et HIBP. Utilisez le Breach Monitor pour une analyse plus approfondie.",
      strengthAnalysis: "Analyse de force",
      strengthAnalysisDesc: "Évalue la longueur, la diversité (majuscules, minuscules, chiffres, symboles). Les mots de passe avec un score ≤ 1/5 sont marqués comme faibles.",
      reuseDetection: "Détection de réutilisation",
      reuseDetectionDesc: "Identifie les mots de passe partagés entre plusieurs comptes. Toutes les comparaisons sont locales - vos mots de passe ne quittent jamais cette page."
    },
    assetHolder: {
      configureTemplates: "Configurer les valeurs modèles pour les identifiants.",
      emailAddresses: "Adresses E-mail",
      phoneNumbers: "Numéros de Téléphone",
      securityKeys: "Clés de Sécurité (U2F)",
      emailPlaceholder: "nom@exemple.com",
      securityKeyName: "Nom de la Clé de Sécurité",
      invalidEmail: "Format d'e-mail invalide",
      saveTemplates: "Enregistrer les Modèles"
    }
  },
  es: {
    health: {
      title: "Salud de la Bóveda",
      subtitle: "Una auditoría en tiempo real de sus contraseñas - débiles, reutilizadas y comprometidas.",
      basedOn: "Basado en {{count}} credenciales con contraseñas",
      excellent: "Excelente",
      good: "Bueno",
      fair: "Regular",
      poor: "Pobre",
      compromised: "Comprometida",
      compromisedDesc: "Encontrada en listas de brechas conocidas",
      weak: "Débil",
      weakDesc: "Contraseñas cortas o simples",
      reused: "Reutilizada",
      reusedDesc: "Misma contraseña en varias cuentas",
      healthy: "Saludable",
      healthyDesc: "No se detectaron problemas",
      issuesFound: "Problemas encontrados ({{count}})",
      goToVault: "Ir a la Bóveda",
      allClear: "Todo en orden",
      allClearDesc: "No se detectaron contraseñas débiles, reutilizadas o comprometidas.",
      noCredentials: "No se encontraron credenciales con contraseñas.",
      compromisedCheck: "Comprobación de compromiso",
      compromisedCheckDesc: "Coincidencias con más de 500 contraseñas principales de rockyou.txt y HIBP. Ejecute el Breach Monitor para un análisis profundo.",
      strengthAnalysis: "Análisis de fuerza",
      strengthAnalysisDesc: "Evalúa la longitud, la diversidad de caracteres. Las contraseñas con puntuación ≤ 1/5 se marcan como débiles.",
      reuseDetection: "Detección de reutilización",
      reuseDetectionDesc: "Identifica contraseñas compartidas en varias cuentas. Las comparaciones son locales."
    },
    assetHolder: {
      configureTemplates: "Configurar valores de plantilla para credenciales.",
      emailAddresses: "Direcciones de Correo",
      phoneNumbers: "Números de Teléfono",
      securityKeys: "Llaves de Seguridad (U2F)",
      emailPlaceholder: "nombre@ejemplo.com",
      securityKeyName: "Nombre de la Llave de Seguridad",
      invalidEmail: "Formato de correo inválido",
      saveTemplates: "Guardar Plantillas"
    }
  },
  de: {
    health: {
      title: "Tresor-Gesundheit",
      subtitle: "Ein Echtzeit-Audit Ihrer Tresor-Passwörter - schwach, wiederverwendet und kompromittiert.",
      basedOn: "Basierend auf {{count}} Anmeldedaten mit Passwörtern",
      excellent: "Ausgezeichnet",
      good: "Gut",
      fair: "Befriedigend",
      poor: "Schlecht",
      compromised: "Kompromittiert",
      compromisedDesc: "In bekannten Datenlecks gefunden",
      weak: "Schwach",
      weakDesc: "Kurze oder einfache Passwörter",
      reused: "Wiederverwendet",
      reusedDesc: "Gleiches Passwort für mehrere Konten",
      healthy: "Gesund",
      healthyDesc: "Keine Probleme erkannt",
      issuesFound: "Gefundene Probleme ({{count}})",
      goToVault: "Zum Tresor",
      allClear: "Alles in Ordnung",
      allClearDesc: "Keine schwachen, wiederverwendeten oder kompromittierten Passwörter erkannt.",
      noCredentials: "Keine Anmeldedaten mit Passwörtern gefunden.",
      compromisedCheck: "Kompromittierungsprüfung",
      compromisedCheckDesc: "Abgleich mit über 500 Passwörtern aus rockyou.txt und HIBP. Führen Sie den Breach Monitor für einen tieferen Scan aus.",
      strengthAnalysis: "Stärkeanalyse",
      strengthAnalysisDesc: "Bewertet Länge und Zeichenvielfalt. Passwörter mit einer Punktzahl ≤ 1/5 werden als schwach markiert.",
      reuseDetection: "Wiederverwendungserkennung",
      reuseDetectionDesc: "Identifiziert Passwörter, die über mehrere Konten hinweg geteilt werden. Alle Vergleiche finden lokal statt."
    },
    assetHolder: {
      configureTemplates: "Vorlagenwerte für Anmeldedaten konfigurieren.",
      emailAddresses: "E-Mail-Adressen",
      phoneNumbers: "Telefonnummern",
      securityKeys: "Sicherheitsschlüssel (U2F)",
      emailPlaceholder: "name@beispiel.com",
      securityKeyName: "Name des Sicherheitsschlüssels",
      invalidEmail: "Ungültiges E-Mail-Format",
      saveTemplates: "Vorlagen speichern"
    }
  },
  pt: {
    health: {
      title: "Saúde do Cofre",
      subtitle: "Uma auditoria em tempo real das senhas do seu cofre - fracas, reutilizadas e comprometidas.",
      basedOn: "Com base em {{count}} credenciais com senhas",
      excellent: "Excelente",
      good: "Bom",
      fair: "Razoável",
      poor: "Fraco",
      compromised: "Comprometida",
      compromisedDesc: "Encontrada em listas de vazamentos conhecidas",
      weak: "Fraca",
      weakDesc: "Senhas curtas ou simples",
      reused: "Reutilizada",
      reusedDesc: "Mesma senha em várias contas",
      healthy: "Saudável",
      healthyDesc: "Nenhum problema detectado",
      issuesFound: "Problemas Encontrados ({{count}})",
      goToVault: "Ir para o Cofre",
      allClear: "Tudo Certo",
      allClearDesc: "Nenhuma senha fraca, reutilizada ou comprometida detectada.",
      noCredentials: "Nenhuma credencial com senha encontrada.",
      compromisedCheck: "Verificação de Comprometimento",
      compromisedCheckDesc: "Compara com mais de 500 senhas principais do rockyou.txt e HIBP. Execute o Breach Monitor para uma análise mais profunda.",
      strengthAnalysis: "Análise de Força",
      strengthAnalysisDesc: "Avalia o comprimento e a diversidade de caracteres. Senhas com pontuação ≤ 1/5 são marcadas como fracas.",
      reuseDetection: "Detecção de Reutilização",
      reuseDetectionDesc: "Identifica senhas compartilhadas em várias contas. Todas as comparações acontecem localmente."
    },
    assetHolder: {
      configureTemplates: "Configurar valores de modelo para credenciais.",
      emailAddresses: "Endereços de E-mail",
      phoneNumbers: "Números de Telefone",
      securityKeys: "Chaves de Segurança (U2F)",
      emailPlaceholder: "nome@exemplo.com",
      securityKeyName: "Nome da Chave de Segurança",
      invalidEmail: "Formato de e-mail inválido",
      saveTemplates: "Salvar Modelos"
    }
  },
  it: {
    health: {
      title: "Salute della Cassaforte",
      subtitle: "Un controllo in tempo reale delle password della tua cassaforte: deboli, riutilizzate e compromesse.",
      basedOn: "Basato su {{count}} credenziali con password",
      excellent: "Eccellente",
      good: "Buono",
      fair: "Sufficiente",
      poor: "Scarso",
      compromised: "Compromessa",
      compromisedDesc: "Trovata in liste di violazioni note",
      weak: "Debole",
      weakDesc: "Password corte o semplici",
      reused: "Riutilizzata",
      reusedDesc: "Stessa password su più account",
      healthy: "Sana",
      healthyDesc: "Nessun problema rilevato",
      issuesFound: "Problemi trovati ({{count}})",
      goToVault: "Vai alla Cassaforte",
      allClear: "Tutto a posto",
      allClearDesc: "Nessuna password debole, riutilizzata o compromessa rilevata.",
      noCredentials: "Nessuna credenziale con password trovata.",
      compromisedCheck: "Controllo Compromissione",
      compromisedCheckDesc: "Confronta con oltre 500 password di rockyou.txt e HIBP. Esegui il Breach Monitor per una scansione più approfondita.",
      strengthAnalysis: "Analisi di Forza",
      strengthAnalysisDesc: "Valuta lunghezza e diversità dei caratteri. Le password con punteggio ≤ 1/5 sono classificate come deboli.",
      reuseDetection: "Rilevamento Riutilizzo",
      reuseDetectionDesc: "Identifica le password condivise tra più account. Tutti i confronti avvengono localmente."
    },
    assetHolder: {
      configureTemplates: "Configura i valori dei modelli per le credenziali.",
      emailAddresses: "Indirizzi Email",
      phoneNumbers: "Numeri di Telefono",
      securityKeys: "Chiavi di Sicurezza (U2F)",
      emailPlaceholder: "nome@esempio.com",
      securityKeyName: "Nome della Chiave di Sicurezza",
      invalidEmail: "Formato email non valido",
      saveTemplates: "Salva Modelli"
    }
  },
  ja: {
    health: {
      title: "ボルトの健康状態",
      subtitle: "ボルトのパスワードのリアルタイム監査 - 脆弱、使い回し、漏洩したパスワード。",
      basedOn: "{{count}}件のパスワード付きクレデンシャルに基づく",
      excellent: "優秀",
      good: "良好",
      fair: "普通",
      poor: "脆弱",
      compromised: "漏洩",
      compromisedDesc: "既知の漏洩リストで発見",
      weak: "脆弱",
      weakDesc: "短すぎる、または単純なパスワード",
      reused: "使い回し",
      reusedDesc: "複数のアカウントで同じパスワードを使用",
      healthy: "健康",
      healthyDesc: "問題は検出されませんでした",
      issuesFound: "問題が見つかりました ({{count}})",
      goToVault: "ボルトへ移動",
      allClear: "すべてクリア",
      allClearDesc: "脆弱、使い回し、または漏洩したパスワードは検出されませんでした。",
      noCredentials: "パスワード付きのクレデンシャルが見つかりません。",
      compromisedCheck: "漏洩チェック",
      compromisedCheckDesc: "rockyou.txtとHIBPから500以上のパスワードと照合。詳細なスキャンにはBreach Monitorを実行してください。",
      strengthAnalysis: "強度分析",
      strengthAnalysisDesc: "長さと文字の多様性を評価します。スコアが1/5以下のパスワードは脆弱と判定されます。",
      reuseDetection: "使い回し検出",
      reuseDetectionDesc: "複数のアカウントで共有されているパスワードを特定します。すべての比較はローカルで行われます。"
    },
    assetHolder: {
      configureTemplates: "クレデンシャルのテンプレート値を設定します。",
      emailAddresses: "メールアドレス",
      phoneNumbers: "電話番号",
      securityKeys: "セキュリティキー (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "セキュリティキー名",
      invalidEmail: "無効なメール形式",
      saveTemplates: "テンプレートを保存"
    }
  },
  ko: {
    health: {
      title: "볼트 건강 상태",
      subtitle: "볼트 비밀번호 실시간 감사 - 취약, 재사용 및 유출된 비밀번호.",
      basedOn: "비밀번호가 있는 자격 증명 {{count}}개 기준",
      excellent: "우수",
      good: "양호",
      fair: "보통",
      poor: "취약",
      compromised: "유출됨",
      compromisedDesc: "알려진 유출 목록에서 발견됨",
      weak: "취약",
      weakDesc: "짧거나 단순한 비밀번호",
      reused: "재사용됨",
      reusedDesc: "여러 계정에서 같은 비밀번호 사용",
      healthy: "건강함",
      healthyDesc: "발견된 문제 없음",
      issuesFound: "발견된 문제 ({{count}})",
      goToVault: "볼트로 이동",
      allClear: "모두 정상",
      allClearDesc: "취약, 재사용 또는 유출된 비밀번호가 감지되지 않았습니다.",
      noCredentials: "비밀번호가 있는 자격 증명을 찾을 수 없습니다.",
      compromisedCheck: "유출 검사",
      compromisedCheckDesc: "rockyou.txt 및 HIBP의 500개 이상 비밀번호와 대조. 더 깊은 스캔을 위해 Breach Monitor를 실행하세요.",
      strengthAnalysis: "강도 분석",
      strengthAnalysisDesc: "길이와 문자 다양성을 평가합니다. 1/5 이하의 점수는 취약으로 표시됩니다.",
      reuseDetection: "재사용 감지",
      reuseDetectionDesc: "여러 계정에서 공유된 비밀번호를 식별합니다. 모든 비교는 로컬에서 발생합니다."
    },
    assetHolder: {
      configureTemplates: "자격 증명을 위한 템플릿 값을 구성합니다.",
      emailAddresses: "이메일 주소",
      phoneNumbers: "전화번호",
      securityKeys: "보안 키 (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "보안 키 이름",
      invalidEmail: "잘못된 이메일 형식",
      saveTemplates: "템플릿 저장"
    }
  },
  zh: {
    health: {
      title: "密码库健康",
      subtitle: "实时审计您的密码库密码 - 弱密码、重复使用和已泄露的密码。",
      basedOn: "基于 {{count}} 个带有密码的凭据",
      excellent: "优秀",
      good: "良好",
      fair: "一般",
      poor: "极差",
      compromised: "已泄露",
      compromisedDesc: "在已知泄露列表中发现",
      weak: "较弱",
      weakDesc: "较短或简单的密码",
      reused: "重复使用",
      reusedDesc: "跨账户使用相同的密码",
      healthy: "健康",
      healthyDesc: "未检测到问题",
      issuesFound: "发现问题 ({{count}})",
      goToVault: "前往密码库",
      allClear: "一切正常",
      allClearDesc: "未检测到弱密码、重复使用或已泄露的密码。",
      noCredentials: "未找到带有密码的凭据。",
      compromisedCheck: "泄露检查",
      compromisedCheckDesc: "与rockyou.txt和HIBP中的500+密码进行匹配。运行数据泄露监视器进行深度扫描。",
      strengthAnalysis: "强度分析",
      strengthAnalysisDesc: "评估长度、字符多样性。得分 ≤ 1/5 的密码被标记为弱。",
      reuseDetection: "重复检测",
      reuseDetectionDesc: "识别跨多个账户共享的密码。所有比较都在本地进行。"
    },
    assetHolder: {
      configureTemplates: "配置凭据的模板值。",
      emailAddresses: "电子邮件地址",
      phoneNumbers: "电话号码",
      securityKeys: "安全密钥 (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "安全密钥名称",
      invalidEmail: "无效的电子邮件格式",
      saveTemplates: "保存模板"
    }
  },
  ru: {
    health: {
      title: "Здоровье Хранилища",
      subtitle: "Аудит ваших паролей в реальном времени - слабые, повторяющиеся и скомпрометированные.",
      basedOn: "На основе {{count}} учетных данных с паролями",
      excellent: "Отлично",
      good: "Хорошо",
      fair: "Удовлетворительно",
      poor: "Слабо",
      compromised: "Скомпрометирован",
      compromisedDesc: "Найден в известных списках утечек",
      weak: "Слабый",
      weakDesc: "Короткие или простые пароли",
      reused: "Повторяющийся",
      reusedDesc: "Одинаковый пароль для нескольких аккаунтов",
      healthy: "Здоров",
      healthyDesc: "Проблем не обнаружено",
      issuesFound: "Найдено проблем ({{count}})",
      goToVault: "Перейти в Хранилище",
      allClear: "Всё чисто",
      allClearDesc: "Не обнаружено слабых, повторяющихся или скомпрометированных паролей.",
      noCredentials: "Не найдено учетных данных с паролями.",
      compromisedCheck: "Проверка на компрометацию",
      compromisedCheckDesc: "Проверка по 500+ паролям из rockyou.txt и HIBP. Запустите Монитор утечек для глубокого сканирования.",
      strengthAnalysis: "Анализ надежности",
      strengthAnalysisDesc: "Оценивает длину, разнообразие символов. Пароли с оценкой ≤ 1/5 отмечаются как слабые.",
      reuseDetection: "Обнаружение повторов",
      reuseDetectionDesc: "Выявляет пароли, используемые в нескольких аккаунтах. Все сравнения происходят локально."
    },
    assetHolder: {
      configureTemplates: "Настройте значения шаблонов для учетных данных.",
      emailAddresses: "Адреса электронной почты",
      phoneNumbers: "Номера телефонов",
      securityKeys: "Ключи безопасности (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "Имя ключа безопасности",
      invalidEmail: "Неверный формат почты",
      saveTemplates: "Сохранить шаблоны"
    }
  },
  ar: {
    health: {
      title: "صحة الخزنة",
      subtitle: "تدقيق في الوقت الفعلي لكلمات مرور الخزنة - الضعيفة والمكررة والمخترقة.",
      basedOn: "بناءً على {{count}} بيانات اعتماد بكلمات مرور",
      excellent: "ممتاز",
      good: "جيد",
      fair: "مقبول",
      poor: "ضعيف",
      compromised: "مخترق",
      compromisedDesc: "موجود في قوائم الاختراق المعروفة",
      weak: "ضعيف",
      weakDesc: "كلمات مرور قصيرة أو بسيطة",
      reused: "مكرر",
      reusedDesc: "نفس كلمة المرور عبر حسابات متعددة",
      healthy: "سليم",
      healthyDesc: "لم يتم اكتشاف أي مشاكل",
      issuesFound: "المشاكل التي تم العثور عليها ({{count}})",
      goToVault: "الذهاب إلى الخزنة",
      allClear: "كل شيء سليم",
      allClearDesc: "لم يتم اكتشاف كلمات مرور ضعيفة أو مكررة أو مخترقة.",
      noCredentials: "لم يتم العثور على بيانات اعتماد بكلمات مرور.",
      compromisedCheck: "فحص الاختراق",
      compromisedCheckDesc: "يتطابق مع أكثر من 500 كلمة مرور من rockyou.txt و HIBP. قم بتشغيل Breach Monitor لإجراء فحص أعمق.",
      strengthAnalysis: "تحليل القوة",
      strengthAnalysisDesc: "يقيم الطول وتنوع الأحرف. كلمات المرور التي تقل نتيجتها عن 1/5 يتم وضع علامة عليها كضعيفة.",
      reuseDetection: "اكتشاف التكرار",
      reuseDetectionDesc: "يحدد كلمات المرور المشتركة عبر حسابات متعددة. تتم جميع المقارنات محليًا."
    },
    assetHolder: {
      configureTemplates: "تكوين قيم القوالب لبيانات الاعتماد.",
      emailAddresses: "عناوين البريد الإلكتروني",
      phoneNumbers: "أرقام الهواتف",
      securityKeys: "مفاتيح الأمان (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "اسم مفتاح الأمان",
      invalidEmail: "تنسيق بريد إلكتروني غير صالح",
      saveTemplates: "حفظ القوالب"
    }
  },
  id: {
    health: {
      title: "Kesehatan Brankas",
      subtitle: "Audit waktu nyata kata sandi brankas Anda - lemah, digunakan kembali, dan bocor.",
      basedOn: "Berdasarkan {{count}} kredensial dengan kata sandi",
      excellent: "Sangat Baik",
      good: "Baik",
      fair: "Cukup",
      poor: "Buruk",
      compromised: "Bocor",
      compromisedDesc: "Ditemukan dalam daftar kebocoran yang diketahui",
      weak: "Lemah",
      weakDesc: "Kata sandi pendek atau sederhana",
      reused: "Digunakan Kembali",
      reusedDesc: "Kata sandi yang sama di beberapa akun",
      healthy: "Sehat",
      healthyDesc: "Tidak ada masalah yang terdeteksi",
      issuesFound: "Masalah Ditemukan ({{count}})",
      goToVault: "Pergi ke Brankas",
      allClear: "Semua Aman",
      allClearDesc: "Tidak ada kata sandi yang lemah, digunakan kembali, atau bocor yang terdeteksi.",
      noCredentials: "Tidak ada kredensial dengan kata sandi yang ditemukan.",
      compromisedCheck: "Pemeriksaan Kebocoran",
      compromisedCheckDesc: "Pencocokan terhadap 500+ kata sandi dari rockyou.txt dan HIBP. Jalankan Breach Monitor untuk pemindaian lebih dalam.",
      strengthAnalysis: "Analisis Kekuatan",
      strengthAnalysisDesc: "Mengevaluasi panjang, keragaman karakter. Kata sandi dengan skor ≤ 1/5 ditandai sebagai lemah.",
      reuseDetection: "Deteksi Penggunaan Kembali",
      reuseDetectionDesc: "Mengidentifikasi kata sandi yang dibagikan di beberapa akun. Semua perbandingan terjadi secara lokal."
    },
    assetHolder: {
      configureTemplates: "Konfigurasi nilai templat untuk kredensial.",
      emailAddresses: "Alamat Email",
      phoneNumbers: "Nomor Telepon",
      securityKeys: "Kunci Keamanan (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "Nama Kunci Keamanan",
      invalidEmail: "Format email tidak valid",
      saveTemplates: "Simpan Templat"
    }
  },
  hi: {
    health: {
      title: "वॉल्ट स्वास्थ्य",
      subtitle: "आपके वॉल्ट पासवर्ड का रीयल-टाइम ऑडिट - कमजोर, बार-बार उपयोग किए जाने वाले और समझौता किए गए पासवर्ड।",
      basedOn: "पासवर्ड वाले {{count}} क्रेडेंशियल्स के आधार पर",
      excellent: "उत्कृष्ट",
      good: "अच्छा",
      fair: "निष्पक्ष",
      poor: "खराब",
      compromised: "समझौता किया गया",
      compromisedDesc: "ज्ञात उल्लंघन सूचियों में पाया गया",
      weak: "कमजोर",
      weakDesc: "छोटे या सरल पासवर्ड",
      reused: "पुन: उपयोग किया गया",
      reusedDesc: "कई खातों में एक ही पासवर्ड",
      healthy: "स्वस्थ",
      healthyDesc: "कोई समस्या नहीं मिली",
      issuesFound: "समस्याएं मिलीं ({{count}})",
      goToVault: "वॉल्ट पर जाएं",
      allClear: "सब साफ",
      allClearDesc: "कोई कमजोर, बार-बार उपयोग किया जाने वाला या समझौता किया गया पासवर्ड नहीं मिला।",
      noCredentials: "पासवर्ड वाले कोई क्रेडेंशियल्स नहीं मिले।",
      compromisedCheck: "समझौता जाँच",
      compromisedCheckDesc: "rockyou.txt और HIBP से 500+ पासवर्ड के विरुद्ध मेल खाता है। गहरी स्कैनिंग के लिए ब्रीच मॉनिटर चलाएं।",
      strengthAnalysis: "शक्ति विश्लेषण",
      strengthAnalysisDesc: "लंबाई, चरित्र विविधता का मूल्यांकन करता है। ≤ 1/5 स्कोर करने वाले पासवर्ड को कमजोर के रूप में फ़्लैग किया जाता है।",
      reuseDetection: "पुन: उपयोग का पता लगाना",
      reuseDetectionDesc: "कई खातों में साझा किए गए पासवर्ड की पहचान करता है। सभी तुलनाएं स्थानीय रूप से होती हैं।"
    },
    assetHolder: {
      configureTemplates: "क्रेडेंशियल्स के लिए टेम्प्लेट मान कॉन्फ़िगर करें।",
      emailAddresses: "ईमेल पते",
      phoneNumbers: "फ़ोन नंबर",
      securityKeys: "सुरक्षा कुंजी (U2F)",
      emailPlaceholder: "name@example.com",
      securityKeyName: "सुरक्षा कुंजी का नाम",
      invalidEmail: "अमान्य ईमेल प्रारूप",
      saveTemplates: "टेम्प्लेट सहेजें"
    }
  }
};

const localesDir = path.join(__dirname, 'src', 'locales');

locales.forEach(lang => {
  const filePath = path.join(localesDir, `${lang}.json`);
  if (fs.existsSync(filePath)) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    
    // Inject English fallback if the language isn't fully in translations object
    // (though I provided all 13).
    const trans = translations[lang] || translations.en;
    
    // Merge health
    if (!data.health) {
        data.health = {};
    }
    data.health = { ...data.health, ...trans.health };
    
    // Merge assetHolder
    if (!data.assetHolder) {
        data.assetHolder = {};
    }
    data.assetHolder = { ...data.assetHolder, ...trans.assetHolder };
    
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
    console.log(`Updated ${lang}.json`);
  }
});
