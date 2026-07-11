import { getCsrfToken, apiFetch } from '../utils/api';
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { sanitizeSvg } from '../utils/sanitize';
import { useVault } from '../context/VaultContext';
import ConfirmModal from './ConfirmModal';
import {
  Shield,
  Lock,
  Key,
  Settings,
  HelpCircle,
  LogOut,
  Plus,
  Wallet,
  Globe,
  Briefcase,
  LayoutGrid,
  Gamepad2,
  Bitcoin,
  Dices,
  Folder as FolderIcon,
  CreditCard,
  Settings2,
  HeartPulse,
  Wand2,
  RefreshCw,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import { Folder } from '../types';
import { clearAllSessions } from '../utils/sessionTracker';
import { keyStore } from '../crypto/keystore';
import { ICON_MAP } from '../utils/folderIcons';
import { clearMfaCache } from '../utils/mfa';
import { SkeletonFolderRow } from './Skeleton';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isOpen: boolean;
  onClose: () => void;
  folders: Folder[];
  foldersLoading?: boolean;
  onCreateFolder: () => void;
  onManageFolders: () => void;
}



export default function Sidebar({ activeTab, setActiveTab, isOpen, onClose, folders, foldersLoading, onCreateFolder, onManageFolders }: SidebarProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { pendingSyncCount } = useVault();
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);

  const performLogout = async () => {
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

  // Logging out with unsynced offline changes still queued doesn't lose them
  // (they're encrypted with the deterministic key and will flush on next
  // login), but the user should knowingly choose that rather than be
  // surprised their edits vanished from view until they log back in.
  const handleLogout = () => {
    if (pendingSyncCount > 0) {
      setShowLogoutConfirm(true);
      return;
    }
    performLogout();
  };

  const mainNav = [
    { id: 'vault',       label: t('sidebar.vault'),                          icon: Lock },
    { id: 'security',    label: t('sidebar.security'),                       icon: Shield },
    { id: 'health',      label: t('sidebar.health', 'Vault Health'),         icon: HeartPulse },
    { id: 'generator',   label: t('sidebar.generator', 'Generator'),         icon: Wand2 },
    { id: 'assetHolder', label: t('sidebar.assetHolder', 'Asset holder'),    icon: Key },
  ];

  const renderFolderIcon = (folder: Folder) => {
    if (folder.customSvg) {
      return (
        <div
          className="w-5 h-5 shrink-0 flex items-center justify-center [&>svg]:w-full [&>svg]:h-full"
          dangerouslySetInnerHTML={{ __html: sanitizeSvg(folder.customSvg) }}
        />
      );
    }
    
    const IconComponent = (folder.iconName && ICON_MAP[folder.iconName]) ? ICON_MAP[folder.iconName] : FolderIcon;
    return <IconComponent size={20} className="shrink-0" />;
  };

  return (
    <>
      {/* Backdrop for mobile */}
      <AnimatePresence>
        {isOpen && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed fixed inset-0 bg-[#000000]/20 backdrop-blur-sm z-40 md:hidden"
          />
        )}
      </AnimatePresence>

      <aside aria-label={t('sidebar.label', 'Sidebar')} className={`fixed left-0 top-0 h-screen bg-surface-container-low border-r border-outline-variant/5 flex flex-col z-50 transition-all duration-300 overflow-hidden ${isOpen ? 'w-64' : 'w-16 md:w-64'}`}>
        <div className="py-8 overflow-y-auto no-scrollbar flex-1">
          <div className={`flex items-center justify-between mb-8 ${isOpen ? 'px-8' : 'px-0 justify-center md:px-8 md:justify-between'}`}>
            <div className={`flex items-center ${isOpen ? 'gap-3' : 'gap-0 md:gap-3'}`}>
              <div className="w-10 h-10 bg-black flex items-center justify-center rounded-lg shrink-0">
                <Shield className="text-white" size={20} fill="currentColor" />
              </div>
              <div className={`transition-all ${isOpen ? 'block' : 'hidden md:block'}`}>
                <div className="text-xl font-bold text-black dark:text-white brand-font tracking-tight leading-none">{t('sidebar.brand', 'PWDnow')}</div>
                <div className="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold mt-1">{t('sidebar.status', 'Digital Bastion Active')}</div>
              </div>
            </div>
            {isOpen && (
              <button onClick={onClose} aria-label={t('common.close', 'Close')} className="md:hidden p-2 hover:bg-surface-container-high rounded-lg shrink-0 text-black dark:text-white">
                <Plus size={20} className="rotate-45" aria-hidden="true" />
              </button>
            )}
          </div>

          <nav aria-label={t('sidebar.mainNav', 'Main navigation')} className="space-y-1">
            {mainNav.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                aria-label={item.label}
                className={`w-full flex items-center py-3 transition-colors text-left ${
                  isOpen ? 'px-4 gap-3 justify-start' : 'px-0 justify-center md:px-4 md:justify-start md:gap-3'
                } ${
                  activeTab === item.id
                    ? 'text-black dark:text-white font-bold border-r-2 border-black dark:border-white bg-surface-container-high/50'
                    : 'text-on-surface-variant font-medium hover:bg-surface-container-high hover:text-black dark:hover:text-white'
                }`}
              >
                <item.icon size={20} className="shrink-0" />
                <span className={`font-headline tracking-tight font-semibold truncate ${isOpen ? 'block' : 'hidden md:block'}`}>{item.label}</span>
              </button>
            ))}
          </nav>

          <div className="mt-12">
            <div className={`flex items-center justify-between mb-4 ${isOpen ? 'px-4' : 'px-0 justify-center md:px-4 md:justify-between'}`}>
              <div className={`text-[10px] uppercase tracking-widest text-on-surface-variant font-bold ${isOpen ? 'block' : 'hidden md:block'}`}>{t('sidebar.folders', 'Folders')}</div>
              <div className="flex items-center gap-1">
                <button
                  onClick={onCreateFolder}
                  className="text-on-surface-variant hover:text-black dark:hover:text-white transition-colors p-1"
                  aria-label={t('sidebar.newFolder', 'New Folder')}
                  title={t('sidebar.newFolder', 'New Folder')}
                >
                  <Plus size={14} />
                </button>
                <button
                  onClick={onManageFolders}
                  className="text-on-surface-variant hover:text-black dark:hover:text-white transition-colors p-1"
                  aria-label={t('sidebar.manageFolders')}
                >
                  <Settings2 size={14} />
                </button>
              </div>
            </div>
            <nav aria-label={t('sidebar.folderNav', 'Folder navigation')} className="space-y-1">
              {foldersLoading && folders.length === 0 ? (
                <div aria-label={t('sidebar.loadingFolders', 'Loading folders')} aria-busy="true">
                  {[...Array(4)].map((_, i) => <SkeletonFolderRow key={i} />)}
                </div>
              ) : folders.map((folder) => (
                <button
                  key={folder.id}
                  onClick={() => setActiveTab(folder.id)}
                  aria-label={folder.label}
                  className={`w-full flex items-center py-3 transition-colors text-left ${
                    isOpen ? 'px-4 gap-3 justify-start' : 'px-0 justify-center md:px-4 md:justify-start md:gap-3'
                  } ${
                    activeTab === folder.id 
                      ? 'text-black dark:text-white font-bold border-r-2 border-black dark:border-white bg-surface-container-high/50' 
                      : 'text-on-surface-variant font-medium hover:bg-surface-container-high hover:text-black dark:hover:text-white'
                  }`}
                >
                  {renderFolderIcon(folder)}
                  <span className={`font-headline tracking-tight font-semibold truncate ${isOpen ? 'block' : 'hidden md:block'}`}>{folder.label}</span>
                </button>
              ))}
            </nav>
            <button
              onClick={onManageFolders}
              aria-label={t('sidebar.manageFolders')}
              className={`w-full mt-4 flex items-center py-2 text-[10px] font-black uppercase tracking-widest text-on-surface-variant hover:text-black dark:hover:text-white transition-colors ${
                isOpen ? 'px-4 gap-2 justify-start' : 'px-0 justify-center md:px-4 md:justify-start md:gap-2'
              }`}
            >
              <Settings2 size={14} className="shrink-0" />
              <span className={isOpen ? 'block' : 'hidden md:block'}>{t('sidebar.manageFolders')}</span>
            </button>
          </div>
        </div>

        {pendingSyncCount > 0 && (
          <div
            className={`mb-2 flex items-center gap-2 rounded-lg bg-amber-100 dark:bg-amber-900/30 text-amber-900 dark:text-amber-200 text-[11px] font-bold py-2 ${
              isOpen ? 'mx-4 px-3 justify-start' : 'mx-2 px-2 justify-center md:mx-4 md:px-3 md:justify-start'
            }`}
            role="status"
          >
            <RefreshCw size={13} className="shrink-0" aria-hidden="true" />
            <span className={isOpen ? 'block' : 'hidden md:block'}>
              {t('sidebar.pendingSync', { count: pendingSyncCount, defaultValue: `${pendingSyncCount} change${pendingSyncCount === 1 ? '' : 's'} syncing...` })}
            </span>
          </div>
        )}

        <div className="py-6 border-t border-outline-variant/10 space-y-1">
          <button
            onClick={() => setActiveTab('settings')}
            aria-label={t('sidebar.settings')}
            className={`w-full flex items-center py-3 transition-colors text-left ${
              isOpen ? 'px-4 gap-3 justify-start' : 'px-0 justify-center md:px-4 md:justify-start md:gap-3'
            } ${
              activeTab === 'settings' 
                ? 'text-black dark:text-white font-bold border-r-2 border-black dark:border-white bg-surface-container-high/50' 
                : 'text-on-surface-variant font-medium hover:bg-surface-container-high hover:text-black dark:hover:text-white'
            }`}
          >
            <Settings size={20} className="shrink-0" />
            <span className={`font-headline tracking-tight font-semibold truncate ${isOpen ? 'block' : 'hidden md:block'}`}>{t('sidebar.settings')}</span>
          </button>
          <button
            onClick={handleLogout}
            aria-label={t('common.logout', 'Logout')}
            className={`w-full flex items-center py-3 text-red-900 dark:text-red-300 font-medium hover:bg-red-900/5 dark:hover:bg-red-300/10 transition-all rounded-md ${
            isOpen ? 'px-4 gap-3 justify-start' : 'px-0 justify-center md:px-4 md:justify-start md:gap-3'
          }`}>
            <LogOut size={20} className="shrink-0" />
            <span className={`font-headline tracking-tight font-semibold truncate ${isOpen ? 'block' : 'hidden md:block'}`}>{t('common.logout', 'Logout')}</span>
          </button>
        </div>
      </aside>

      <ConfirmModal
        isOpen={showLogoutConfirm}
        onClose={() => setShowLogoutConfirm(false)}
        onConfirm={() => { setShowLogoutConfirm(false); performLogout(); }}
        title={t('sidebar.unsyncedLogoutTitle', 'Unsynced changes')}
        message={t('sidebar.unsyncedLogoutMessage', {
          count: pendingSyncCount,
          defaultValue: `You have ${pendingSyncCount} change${pendingSyncCount === 1 ? '' : 's'} that hasn't synced to the server yet. They're saved encrypted on this device and will sync automatically next time you're online and logged in - but won't be visible on other devices until then. Log out anyway?`,
        })}
        confirmLabel={t('sidebar.logoutAnyway', 'Log out anyway')}
        variant="danger"
      />
    </>
  );
}
