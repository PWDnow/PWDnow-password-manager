import React, { useState, useRef, useMemo } from 'react';
import { Camera, ChevronDown, Check, RefreshCw, CheckCircle } from 'lucide-react';

const FbUserCircle = ({ size = 20, className = '' }: { size?: number; className?: string }) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="12" cy="12" r="10"/>
    <circle cx="12" cy="8.5" r="2.5"/>
    <path d="M6.5 19.8C7.2 17.1 9.4 15.5 12 15.5s4.8 1.6 5.5 4.3"/>
  </svg>
);
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { useProfileForm } from './hooks/useProfileForm';
import UserAvatar from '../../components/UserAvatar';
import COUNTRY_LIST from '../../data/country-list.json';
import type { UserProfile } from '../../context/UserContext';

const EUROPE_COUNTRIES = new Set([
  "Albania", "Andorra", "Austria", "Belarus", "Belgium", "Bosnia and Herzegovina", "Bulgaria", "Croatia", "Cyprus", "Czech Republic", "Denmark", "Estonia", "Faroe Islands", "Finland", "France", "Germany", "Gibraltar", "Greece", "Guernsey", "Hungary", "Iceland", "Ireland", "Isle of Man", "Italy", "Jersey", "Latvia", "Liechtenstein", "Lithuania", "Luxembourg", "Macedonia", "Malta", "Moldova", "Monaco", "Montenegro", "Netherlands", "Norway", "Poland", "Portugal", "Romania", "Russia", "San Marino", "Serbia", "Slovakia", "Slovenia", "Spain", "Svalbard and Jan Mayen", "Sweden", "Switzerland", "Ukraine", "United Kingdom", "Vatican City"
]);

const CUSTOM_ALIASES: Record<string, string[]> = {
  "United States": ["us", "usa", "america"],
  "United Kingdom": ["uk", "britain", "england", "great britain"],
  "United Arab Emirates": ["uae", "emirates"],
  "Myanmar (Burma)": ["birmanie", "myanmar", "burma"]
};

function getCountrySearchText(country: string, translated: string): string {
  let text = `${country} ${translated}`;
  if (EUROPE_COUNTRIES.has(country)) {
    text += " europe european europ";
  }
  if (CUSTOM_ALIASES[country]) {
    text += " " + CUSTOM_ALIASES[country].join(" ");
  }
  return text.toLowerCase();
}

interface Props {
  profile: UserProfile;
  updateProfile: (p: Partial<UserProfile>) => void;
  reloadProfile: () => Promise<void>;
}

export default function ProfileSection({ profile, updateProfile, reloadProfile }: Props) {
  const { t } = useTranslation();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const [isDragging, setIsDragging] = useState(false);
  const [isCountryDropdownOpen, setIsCountryDropdownOpen] = useState(false);
  const [countrySearch, setCountrySearch] = useState('');

  const {
    localProfile,
    isSaving,
    showSaveSuccess,
    hasChanges,
    handleLocalProfileChange,
    handleSaveProfile,
    handlePhotoUpload
  } = useProfileForm(profile, updateProfile, reloadProfile);

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = () => {
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handlePhotoUpload(file);
  };

  return (
    <section>
      <div className="mb-6">
        <h2 className="text-[15px] font-semibold text-neutral-900 dark:text-white leading-snug">{t('settings.userProfile', 'User Profile')}</h2>
        <p className="mt-1 text-[13px] text-neutral-600 dark:text-neutral-300">{t('settings.userProfileDesc', 'Your personal information and account preferences.')}</p>
        <div className="mt-4 h-px bg-neutral-200 dark:bg-white/8" />
      </div>
      <div className="bg-surface-container-low p-10 rounded-xl">
        <div className="grid grid-cols-12 gap-10">
          {/* Photo Upload */}
          <div className="col-span-12 md:col-span-4 lg:col-span-3">
            <div 
              className={`relative group aspect-square rounded-2xl overflow-hidden border-2 border-dashed transition-all ${
                isDragging ? 'border-black bg-black/5 scale-[1.02]' : 'border-outline-variant/30 hover:border-black/50'
              }`}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
              onDrop={onDrop}
            >
              <UserAvatar
                firstName={localProfile.firstName}
                lastName={localProfile.lastName}
                photoUrl={localProfile.photoUrl}
                className="w-full h-full object-cover transition-transform group-hover:scale-105"
              />
              <button type="button" aria-label={t('settings.changePhoto', 'Change Photo')} className="absolute inset-0 w-full h-full bg-[#000000]/40 opacity-0 group-hover:opacity-100 transition-opacity flex flex-col items-center justify-center text-white cursor-pointer" onClick={() => fileInputRef.current?.click()}>
                <Camera size={32} className="mb-2" aria-hidden="true" />
                <span className="text-[10px] font-black uppercase tracking-widest">{t('settings.changePhoto', 'Change Photo')}</span>
                <span className="text-[8px] opacity-70 mt-1 uppercase">{t('settings.dragAndDrop', 'Drag & Drop')}</span>
              </button>
              <input
                type="file"
                ref={fileInputRef}
                className="hidden"
                accept=".jpg,.jpeg,.png,.heic"
                aria-label={t('settings.changePhoto', 'Change Photo')}
                onChange={(e) => e.target.files?.[0] && handlePhotoUpload(e.target.files[0])}
              />
            </div>
            <p className="text-[10px] text-on-surface-variant uppercase tracking-widest mt-4 text-center font-bold">
              {t('settings.photoFormat', 'JPG, PNG, HEIC accepted')}
            </p>
          </div>

          {/* Profile Fields */}
          <div className="col-span-12 md:col-span-8 lg:col-span-9 grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label htmlFor="input-first-name" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                {t('settings.firstName', 'First Name')}
              </label>
<input id="input-first-name"
                type="text"
                aria-label={t('settings.firstName', 'First Name')}
                value={localProfile.firstName}
                onChange={(e) => handleLocalProfileChange('firstName', e.target.value)}
                className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="input-last-name" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                {t('settings.lastName', 'Last Name')}
              </label>
<input id="input-last-name"
                type="text"
                aria-label={t('settings.lastName', 'Last Name')}
                value={localProfile.lastName}
                onChange={(e) => handleLocalProfileChange('lastName', e.target.value)}
                className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="input-company-name" className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                {t('settings.company', 'Company Name (Optional)')}
              </label>
<input id="input-company-name"
                type="text"
                aria-label={t('settings.company', 'Company Name')}
                value={localProfile.company}
                onChange={(e) => handleLocalProfileChange('company', e.target.value)}
                placeholder={t('settings.companyPlaceholder', 'Enter company name...')}
                className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-black uppercase tracking-widest text-on-surface-variant ml-1">
                {t('settings.country', 'Country')}
              </label>
              <div className="relative" ref={dropdownRef}>
                <button
                  type="button"
                  aria-label={t('settings.country', 'Country')}
                  aria-haspopup="listbox"
                  aria-expanded={isCountryDropdownOpen}
                  onClick={() => setIsCountryDropdownOpen(!isCountryDropdownOpen)}
                  className="w-full px-5 py-3.5 bg-white dark:bg-surface-container-high rounded-xl border border-on-surface-variant/50 dark:border-outline-variant/10 text-black dark:text-white font-bold focus:ring-2 focus:ring-black/10 dark:focus:ring-white/10 outline-none transition-all flex items-center justify-between"
                >
                  <span>{localProfile.country ? t(`countries.${localProfile.country}`, localProfile.country) : ''}</span>
                  <ChevronDown size={18} aria-hidden="true" className={`transition-transform duration-300 ${isCountryDropdownOpen ? 'rotate-180' : ''}`} />
                </button>
                <AnimatePresence>
                  {isCountryDropdownOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: -10, scale: 0.95 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: -10, scale: 0.95 }}
                      className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-surface-container-low rounded-xl shadow-2xl border border-outline-variant/10 overflow-hidden z-50"
                    >
                      <div className="px-3 py-2 border-b border-outline-variant/10 sticky top-0 bg-white dark:bg-surface-container-low">
                        <input
                          autoFocus
                          type="text"
                          value={countrySearch}
                          onChange={e => setCountrySearch(e.target.value)}
                          placeholder={t('common.searchCountries', 'Search countries...')}
                          aria-label={t('common.searchCountries', 'Search countries')}
                          className="w-full px-3 py-1.5 text-sm bg-surface dark:bg-surface-container-high rounded-lg border border-on-surface-variant/50 dark:border-outline-variant/10 outline-none"
                        />
                      </div>
                      <ul role="listbox" aria-label={t('settings.country', 'Country')} className="max-h-52 overflow-y-auto custom-scrollbar">
                        {COUNTRY_LIST.entities
                          .filter(c => {
                            const searchStr = countrySearch.toLowerCase().trim();
                            if (!searchStr) return true;
                            return getCountrySearchText(c, t(`countries.${c}`, c)).includes(searchStr);
                          })
                          .map((country) => (
                            <li key={country} role="option" aria-selected={localProfile.country === country}>
                              <button
                                type="button"
                                onClick={() => {
                                  handleLocalProfileChange('country', country);
                                  setIsCountryDropdownOpen(false);
                                  setCountrySearch('');
                                }}
                                className={`w-full text-left px-5 py-3 text-sm font-bold hover:bg-surface-container-low transition-colors ${localProfile.country === country ? 'bg-black text-white' : 'text-black dark:text-white'}`}
                              >
                                {t(`countries.${country}`, country)}
                              </button>
                            </li>
                          ))}
                      </ul>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-10 pt-10 border-t border-outline-variant/10 flex items-center justify-end gap-4">
          <button
            type="button"
            onClick={() => updateProfile(profile)}
            disabled={!hasChanges || isSaving}
            className="px-6 py-3 text-sm font-bold text-on-surface-variant hover:text-black transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {t('common.cancel', 'Cancel')}
          </button>
          <button
            type="button"
            onClick={handleSaveProfile}
            disabled={!hasChanges || isSaving}
            className="px-10 py-3 bg-black text-white rounded-xl text-sm font-black uppercase tracking-widest hover:bg-black/90 transition-all flex items-center gap-2 shadow-lg shadow-black/10 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {isSaving ? (
              <RefreshCw size={16} className="animate-spin" />
            ) : (
              <Check size={16} />
            )}
            {t('common.save', 'Save Changes')}
          </button>
        </div>

        <AnimatePresence>
          {showSaveSuccess && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="mt-6 p-4 bg-green-50 border border-green-100 rounded-xl flex items-center gap-3 text-green-700"
            >
              <CheckCircle size={18} />
              <span className="text-sm font-bold">{t('settings.profileSuccessDesc', 'User profile successfully updated')}</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}
