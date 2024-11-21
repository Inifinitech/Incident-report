import React from 'react';
import { useTranslation } from 'react-i18next';
import { Bell, Globe, Moon, Shield } from 'lucide-react';  // Import the necessary icons
import { Formik, Form, Field } from 'formik';

export default function UserSettings() {
  const { t, i18n } = useTranslation();  // Use translation hook to get `t` function and `i18n` instance

  const handleLanguageChange = (e) => {
    const selectedLanguage = e.target.value;
    i18n.changeLanguage(selectedLanguage);  // Change the language in i18next
  };

  return (
    <div className="p-6 max-w-4xl mx-auto text-white">
      <h1 className="text-2xl font-bold mb-6">{t('App Settings')}</h1>

      <Formik
        initialValues={{
          pushNotifications: true,
          emergencyAlerts: true,
          darkMode: true,
          language: 'en',
        }}
        onSubmit={(values) => {
          console.log('Settings saved:', values);
        }}
      >
        {({ values }) => (
          <Form>
            <div className="space-y-6">
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-medium mb-4">{t('Notifications')}</h2>
                <div className="space-y-4">
                  <label className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Bell className="w-5 h-5 text-yellow-500" />
                      <span>{t('Push Notifications')}</span>
                    </div>
                    <Field
                      type="checkbox"
                      name="pushNotifications"
                      className="toggle"
                      checked={values.pushNotifications}
                    />
                  </label>
                  <label className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Shield className="w-5 h-5 text-yellow-500" />
                      <span>{t('Emergency Alerts')}</span>
                    </div>
                    <Field
                      type="checkbox"
                      name="emergencyAlerts"
                      className="toggle"
                      checked={values.emergencyAlerts}
                    />
                  </label>
                </div>
              </div>

              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-medium mb-4">{t('Appearance')}</h2>
                <div className="space-y-4">
                  <label className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Moon className="w-5 h-5 text-yellow-500" />
                      <span>{t('Dark Mode')}</span>
                    </div>
                    <Field
                      type="checkbox"
                      name="darkMode"
                      className="toggle"
                      checked={values.darkMode}
                    />
                  </label>
                </div>
              </div>

              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-medium mb-4">{t('Language')}</h2>
                <div className="flex items-center gap-3">
                  <Globe className="w-5 h-5 text-yellow-500" />
                  <Field
                    as="select"
                    name="language"
                    className="bg-gray-700 text-white px-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-yellow-500"
                    onChange={handleLanguageChange} // Update language when user selects
                    value={i18n.language}  // Ensure the current language is reflected in the select field
                  >
                    <option value="en">{t('English')}</option>
                    <option value="sw">{t('Swahili')}</option>
                  </Field>
                </div>
              </div>

              <button
                type="submit"
                className="px-6 py-2 bg-yellow-500 text-gray-900 font-medium rounded-lg hover:bg-yellow-600 transition-colors"
              >
                {t('Save Settings')}
              </button>
            </div>
          </Form>
        )}
      </Formik>
    </div>
  );
}
