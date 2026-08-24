import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import en from './locales/en.json';

// Internationalization (i18n) setup.
//
// All user-facing strings live in the locale resources under ./locales and are
// referenced through the `t()` function (or the <Trans> component for strings
// that contain inline markup). English is the only bundled language today;
// adding another locale is a matter of dropping a new JSON file next to en.json
// and registering it in `resources` below.
i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
    },
    lng: 'en',
    fallbackLng: 'en',
    interpolation: {
      // React already escapes values, so i18next does not need to.
      escapeValue: false,
    },
  });

export default i18n;
