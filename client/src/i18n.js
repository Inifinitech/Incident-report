import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Translations for English and Swahili
const resources = {
  en: {
    translation: {
      "App Settings": "App Settings",
      "Push Notifications": "Push Notifications",
      "Emergency Alerts": "Emergency Alerts",
      "Dark Mode": "Dark Mode",
      "Language": "Language",
      "Save Settings": "Save Settings",
      "English": "English",
      "Swahili": "Swahili",
      "Appearance": "Appearance",
      // Add other translations here
    }
  },
  sw: {
    translation: {
      "App Settings": "Mipangilio ya Programu",
      "Push Notifications": "Arifa za Push",
      "Emergency Alerts": "Arifa za Dharura",
      "Dark Mode": "Hali ya Giza",
      "Language": "Lugha",
      "Save Settings": "Hifadhi Mipangilio",
      "English": "Kiingereza",
      "Swahili": "Kiswahili",
      "Appearance": "Muonekano",
      // Add other translations here
    }
  }
};

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: 'en', // Default language
    fallbackLng: 'en', // Fallback language in case of missing translations
    interpolation: {
      escapeValue: false, // React already escapes values
    }
  });

export default i18n;
