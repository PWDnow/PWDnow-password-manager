import i18n from 'i18next';
import HttpBackend from 'i18next-http-backend';
import { initReactI18next } from 'react-i18next';

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

// Translation JSON (~70-130 KB per language) is fetched on demand from
// /locales/{{lng}}.json instead of being statically imported, so the main
// bundle no longer ships all 13 languages (~1.1 MB) up front. The PWA
// workbox config already CacheFirst-caches /locales/* responses.
export const i18nReady = i18n
  .use(HttpBackend)
  .use(initReactI18next)
  .init({
    lng: localStorage.getItem('i18nextLng') || 'en',
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_LANGUAGES.map(l => l.code),
    backend: {
      loadPath: '/locales/{{lng}}.json',
    },
    interpolation: {
      escapeValue: false,
    },
    react: {
      useSuspense: false,
    },
  });

i18n.on('languageChanged', (lng) => {
  document.documentElement.dir = RTL_LANGS.has(lng) ? 'rtl' : 'ltr';
  document.documentElement.lang = lng;
  localStorage.setItem('i18nextLng', lng);
});

export default i18n;
