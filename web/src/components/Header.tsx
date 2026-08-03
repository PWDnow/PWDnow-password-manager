import { getCsrfToken, apiFetch } from '../utils/api';
import React, { useState, useRef, useEffect } from 'react';
import { Search, Bell, Menu, Settings, LogOut, Lightbulb } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import LanguageModal from './LanguageModal';
import UserAvatar from './UserAvatar';
import NotificationDropdown from './NotificationDropdown';
import { useNotification } from '../context/NotificationContext';
import { useUser } from '../context/UserContext';
import { clearAllSessions } from '../utils/sessionTracker';
import { keyStore } from '../crypto/keystore';
import { clearMfaCache } from '../utils/mfa';

interface HeaderProps {
  activeTab: string;
  onMenuClick: () => void;
}

export default function Header({ activeTab, onMenuClick }: HeaderProps) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const { unreadCount } = useNotification();
  const { profile } = useUser();
  const [isLanguageModalOpen, setIsLanguageModalOpen] = useState(false);
  const [isNotificationOpen, setIsNotificationOpen] = useState(false);
  const [isProfileDropdownOpen, setIsProfileDropdownOpen] = useState(false);
  const [displayLang, setDisplayLang] = useState(
    (i18n.resolvedLanguage ?? i18n.language).slice(0, 2).toUpperCase()
  );

  useEffect(() => {
    const handleLangChange = (lng: string) => setDisplayLang(lng.slice(0, 2).toUpperCase());
    i18n.on('languageChanged', handleLangChange);
    return () => { i18n.off('languageChanged', handleLangChange); };
  }, [i18n]);
  const notificationRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notificationRef.current && !notificationRef.current.contains(event.target as Node)) {
        setIsNotificationOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setIsProfileDropdownOpen(false);
      }
    };

    if (isNotificationOpen || isProfileDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isNotificationOpen, isProfileDropdownOpen]);

  const handleLogout = async () => {
    keyStore.clear();
    clearMfaCache();
    // 2. Clear legacy auth state (if any)
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('currentUser');
    try { sessionStorage.removeItem('currentUser'); } catch { /* ignore */ }
    
    // Call offline API to clear JWE cookies
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch { /* ignore offline errors */ }
    
    navigate('/login');
  };

  const [globalSearch, setGlobalSearch] = useState('');

  const handleGlobalSearch = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Enter') return;
    const q = globalSearch.trim();
    if (!q) return;
    navigate(`/vault?q=${encodeURIComponent(q)}`);
    setGlobalSearch('');
  };

  return (
    <>
      <header className="fixed top-0 right-0 left-16 md:left-64 h-16 glass-nav border-b border-outline-variant/10 z-40 flex items-center justify-between px-2 sm:px-4 md:px-12 transition-all duration-300 gap-2">
        <div className="flex items-center gap-1 sm:gap-4 flex-1">
          <button
            onClick={onMenuClick}
            aria-label={t('header.menu', 'Menu')}
            className="md:hidden p-1 sm:p-2 hover:bg-surface-container-high rounded-lg transition-colors shrink-0 text-black dark:text-white"
          >
            <Menu size={20} aria-hidden="true" />
          </button>
          <div className="relative group flex-1">
            <Search className="absolute left-2 sm:left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" size={16} />
            <input
              type="text"
              id="global-search"
              name="global-search"
              autoComplete="off"
              value={globalSearch}
              onChange={e => setGlobalSearch(e.target.value)}
              onKeyDown={handleGlobalSearch}
              placeholder={t('header.searchPlaceholder', 'Search your sanctuary...')}
              aria-label="Global search — press Enter to search"
              className="w-full bg-surface-container-highest border-none rounded-lg py-1.5 sm:py-2 pl-8 sm:pl-10 pr-2 sm:pr-4 text-xs sm:text-sm text-black dark:text-white focus:ring-2 focus:ring-on-primary-container/20 transition-all outline-none"
            />
          </div>
        </div>

        <div className="flex items-center gap-1 sm:gap-4 md:gap-6 shrink-0">
          <div className="flex items-center gap-1 sm:gap-4 text-on-surface-variant">
            <button 
              onClick={() => setIsLanguageModalOpen(true)} 
              className="font-bold text-[10px] sm:text-xs uppercase tracking-widest text-on-surface-variant hover:text-black dark:hover:text-white transition-colors px-1 sm:px-2"
              aria-label={`${t('header.selectLanguage', 'Select Language')}: ${displayLang}`}
            >
              {displayLang}
            </button>
            <div 
              className={`relative p-1 rounded-2xl transition-all duration-500 ${
                isNotificationOpen ? 'bg-surface-container-high/80 backdrop-blur-md ring-1 ring-black/5 shadow-inner' : ''
              }`} 
              ref={notificationRef}
            >
              <button
                onClick={() => setIsNotificationOpen(!isNotificationOpen)}
                aria-label={t('header.notifications', 'Notifications')}
                className={`relative p-1.5 sm:p-2 rounded-xl transition-all duration-300 ${
                  isNotificationOpen
                    ? 'bg-black dark:bg-white text-white dark:text-black shadow-lg scale-110'
                    : 'text-on-surface-variant hover:text-black dark:hover:text-white hover:bg-surface-container-high'
                }`}
              >
                <Bell size={16} className={unreadCount > 0 ? 'animate-pulse' : ''} />
                {unreadCount > 0 && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-error rounded-full border-2 border-white dark:border-black shadow-sm animate-bounce"></span>
                )}
              </button>
              <NotificationDropdown 
                isOpen={isNotificationOpen} 
                onClose={() => setIsNotificationOpen(false)} 
              />
            </div>
          </div>

          <div className="hidden md:block h-8 w-px bg-outline-variant/20"></div>

          <div className="relative" ref={profileRef}>
            <div 
              className="flex items-center gap-2 sm:gap-3 cursor-pointer group"
              onClick={() => setIsProfileDropdownOpen(!isProfileDropdownOpen)}
            >
              <div className="text-right hidden sm:block">
                <p className="text-xs font-bold text-black dark:text-white leading-none">{profile.firstName} {profile.lastName}</p>
                <p className="text-[10px] text-on-surface-variant uppercase tracking-wider mt-1">{t('header.openSource', 'Open Source')}</p>
              </div>
              <div className="w-7 h-7 sm:w-8 sm:h-8 md:w-10 md:h-10 rounded-xl overflow-hidden ring-2 ring-surface-container-high transition-transform group-hover:scale-105 shrink-0">
                <UserAvatar
                  firstName={profile.firstName}
                  lastName={profile.lastName}
                  photoUrl={profile.photoUrl}
                  className="w-full h-full object-cover"
                />
              </div>
            </div>

            {isProfileDropdownOpen && (
              <div className="absolute right-0 mt-3 w-48 bg-white dark:bg-surface-container-low rounded-xl shadow-xl border border-outline-variant/10 overflow-hidden z-50">
                <div className="py-1">
                  <button
                    onClick={() => {
                      setIsProfileDropdownOpen(false);
                      navigate('/settings');
                    }}
                    className="w-full px-4 py-2.5 text-sm font-medium text-left text-black dark:text-white hover:bg-surface-container-high transition-colors flex items-center gap-3"
                  >
                    <Settings size={16} className="text-on-surface-variant" />
                    {t('sidebar.settings', 'Settings')}
                  </button>
                  <button
                    onClick={() => {
                      setIsProfileDropdownOpen(false);
                      window.open('https://github.com/PWDnow/PWDnow/issues/new?labels=enhancement&template=feature_request.md', '_blank', 'noopener,noreferrer');
                    }}
                    className="w-full px-4 py-2.5 text-sm font-medium text-left text-black dark:text-white hover:bg-surface-container-high transition-colors flex items-center gap-3"
                  >
                    <Lightbulb size={16} className="text-on-surface-variant" />
                    {t('header.suggestFeature', 'Suggest a Feature')}
                  </button>
                  <div className="h-px bg-outline-variant/10 my-1"></div>
                  <button
                    onClick={handleLogout}
                    className="w-full px-4 py-2.5 text-sm font-medium text-left text-red-900 hover:bg-red-900/5 transition-colors flex items-center gap-3"
                  >
                    <LogOut size={16} />
                    {t('common.logout', 'Logout')}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>
      
      <LanguageModal 
        isOpen={isLanguageModalOpen} 
        onClose={() => setIsLanguageModalOpen(false)} 
      />
    </>
  );
}
