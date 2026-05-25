import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import enTranslations from './locales/en.json';
import frTranslations from './locales/fr.json';
import esTranslations from './locales/es.json';
import deTranslations from './locales/de.json';
import itTranslations from './locales/it.json';
import ptTranslations from './locales/pt.json';
import ruTranslations from './locales/ru.json';
import arTranslations from './locales/ar.json';
import hiTranslations from './locales/hi.json';
import zhTranslations from './locales/zh.json';
import jaTranslations from './locales/ja.json';
import koTranslations from './locales/ko.json';
import idTranslations from './locales/id.json';

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
  .use(initReactI18next)
  .init({
    lng: localStorage.getItem('i18nextLng') || 'en',
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_LANGUAGES.map(l => l.code),
    resources: {
      en: { translation: enTranslations },
      fr: { translation: frTranslations },
      es: { translation: esTranslations },
      de: { translation: deTranslations },
      it: { translation: itTranslations },
      pt: { translation: ptTranslations },
      ru: { translation: ruTranslations },
      ar: { translation: arTranslations },
      hi: { translation: hiTranslations },
      zh: { translation: zhTranslations },
      ja: { translation: jaTranslations },
      ko: { translation: koTranslations },
      id: { translation: idTranslations },
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
  localStorage.setItem('i18nextLng', lng);
});

export default i18n;
