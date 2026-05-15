import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import Backend from 'i18next-http-backend';
import enTranslations from './locales/en.json';

export const SUPPORTED_LANGUAGES = [
  { code: 'en', name: 'English',    nativeName: 'English'           },
  { code: 'fr', name: 'French',     nativeName: 'Français'          },
  { code: 'es', name: 'Spanish',    nativeName: 'Español'           },
  { code: 'de', name: 'German',     nativeName: 'Deutsch'           },
  { code: 'it', name: 'Italian',    nativeName: 'Italiano'          },
  { code: 'pt', name: 'Portuguese', nativeName: 'Português'         },
  { code: 'ru', name: 'Russian',    nativeName: 'Русский'           },
  { code: 'ar', name: 'Arabic',     nativeName: 'العربية'           },
  { code: 'hi', name: 'Hindi',      nativeName: 'हिन्दी'            },
  { code: 'zh', name: 'Chinese',    nativeName: '中文'               },
  { code: 'ja', name: 'Japanese',   nativeName: '日本語'             },
  { code: 'ko', name: 'Korean',     nativeName: '한국어'             },
  { code: 'id', name: 'Indonesian', nativeName: 'Bahasa Indonesia'  },
];

const RTL_LANGS = new Set(['ar']);

i18n
  .use(Backend)
  .use(initReactI18next)
  .init({
    lng: 'en',
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_LANGUAGES.map(l => l.code),
    // English is bundled inline (zero-RTT); all other locales load on demand.
    resources: { en: { translation: enTranslations } },
    partialBundledLanguages: true,
    backend: {
      loadPath: '/locales/{{lng}}/translation.json',
    },
    interpolation: {
      escapeValue: false,
    },
    // RouterProvider is not wrapped in Suspense - disable throwing promises.
    react: {
      useSuspense: false,
    },
  });

i18n.on('languageChanged', (lng) => {
  document.documentElement.dir = RTL_LANGS.has(lng) ? 'rtl' : 'ltr';
});

export default i18n;
