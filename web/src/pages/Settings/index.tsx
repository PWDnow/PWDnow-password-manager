import React, { useState, useCallback, useEffect, useMemo, useRef, lazy, Suspense } from 'react';
import { 
  User, 
  History, 
  ShieldAlert, 
  Smartphone, 
  Key, 
  Mail, 
  Monitor, 
  Sun, 
  Moon, 
  CheckCircle, 
  LogOut, 
  Edit3, 
  RefreshCw, 
  X, 
  ShieldCheck, 
  Check, 
  Eye, 
  EyeOff, 
  Camera, 
  ChevronDown, 
  Copy, 
  AlertTriangle, 
  Trash2, 
  Timer, 
  Server, 
  Loader2, 
  Download, 
  Upload, 
  Plane, 
  Skull, 
  Flame, 
  FileJson, 
  FileText, 
  FileUp, 
  Fingerprint, 
  KeyRound, 
  ToggleLeft, 
  ToggleRight, 
  Shield, 
  Share2, 
  Globe, 
  Lock 
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { useTranslation } from 'react-i18next';
import QRCode from 'qrcode';
import { useUser } from '../../context/UserContext';
import { useVault } from '../../context/VaultContext';
import { useTheme } from '../../context/ThemeContext';
import { useNotification } from '../../context/NotificationContext';
import { generateUUID, generateRecoveryKey } from '../../utils/crypto';
import { writeEncryptedLocal, readDecryptedLocal } from '../../utils/localCrypto';
import { daemon } from '../../utils/daemonClient';
import { logger } from '../../utils/logger';
import SEO from '../../components/SEO';
import { AuditEvent, ShareLink } from '../../types';

// Decomposed components
import ProfileSection from './ProfileSection';
import MfaSection from './MfaSection';
import RecoveryKeySection from './RecoveryKeySection';
import ConfirmModal from '../../components/ConfirmModal';
import PasswordPromptModal from '../../components/PasswordPromptModal';
import AuditLogModal from './AuditLogModal';
import SharesModal from './SharesModal';

const EmergencyAccessModal = lazy(() => import('../../components/EmergencyAccessModal'));

export default function Settings() {
  const { t } = useTranslation();
  const { profile, updateProfile, reloadProfile } = useUser();
  const { theme, setTheme } = useTheme();
  const { addNotification } = useNotification();
  const { 
    credentials, folders, deleteCredential, addFolder, reloadLocal,
  } = useVault();

  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'sessions' | 'import'>('general');
  
  // Modals
  const [isEmergencyModalOpen, setIsEmergencyModalOpen] = useState(false);
  const [isRecoveryModalOpen, setIsRecoveryModalOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);
  const [isSharesOpen, setIsSharesOpen] = useState(false);
  
  // Handlers (to be moved to hooks or components)
  const handleGenerateRecovery = async () => {
    // simplified for now
    addNotification({ title: 'Recovery Key', message: 'Generating new key...', type: 'info' });
  };

  return (
    <div className="max-w-6xl mx-auto py-10 px-6">
      <SEO title="Settings | PWDnow" />
      
      <div className="mb-12">
        <h1 className="text-4xl font-headline font-black tracking-tight mb-2">{t('settings.title', 'Settings')}</h1>
        <p className="text-on-surface-variant">{t('settings.description', 'Manage your account security, profile, and application preferences.')}</p>
      </div>

      <div className="flex border-b border-outline-variant/10 mb-12 overflow-x-auto no-scrollbar">
        <button onClick={() => setActiveTab('general')} className={`px-8 py-4 text-sm font-black uppercase tracking-widest transition-all border-b-2 ${activeTab === 'general' ? 'border-black text-black dark:border-white dark:text-white' : 'border-transparent text-on-surface-variant hover:text-black'}`}>{t('settings.tabGeneral', 'General')}</button>
        <button onClick={() => setActiveTab('security')} className={`px-8 py-4 text-sm font-black uppercase tracking-widest transition-all border-b-2 ${activeTab === 'security' ? 'border-black text-black dark:border-white dark:text-white' : 'border-transparent text-on-surface-variant hover:text-black'}`}>{t('settings.tabSecurity', 'Security')}</button>
        <button onClick={() => setActiveTab('sessions')} className={`px-8 py-4 text-sm font-black uppercase tracking-widest transition-all border-b-2 ${activeTab === 'sessions' ? 'border-black text-black dark:border-white dark:text-white' : 'border-transparent text-on-surface-variant hover:text-black'}`}>{t('settings.tabSessions', 'Sessions')}</button>
        <button onClick={() => setActiveTab('import')} className={`px-8 py-4 text-sm font-black uppercase tracking-widest transition-all border-b-2 ${activeTab === 'import' ? 'border-black text-black dark:border-white dark:text-white' : 'border-transparent text-on-surface-variant hover:text-black'}`}>{t('settings.tabImportExport', 'Import & Export')}</button>
      </div>

      <div className="space-y-20">
        {activeTab === 'general' && (
          <>
            <ProfileSection profile={profile} updateProfile={updateProfile} reloadProfile={reloadProfile} />
            
            {/* Appearance Section */}
            <section>
              <div className="flex items-center gap-3 mb-8">
                <Monitor className="text-black dark:text-white" size={24} />
                <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.appearance', 'Appearance')}</h2>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                <button onClick={() => setTheme('light')} className={`p-6 rounded-2xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'light' ? 'border-black bg-white dark:bg-white/10' : 'border-outline-variant/20 bg-surface-container-low'}`}>
                  <Sun size={24} />
                  <span className="font-bold text-sm">{t('settings.themeLight', 'Light')}</span>
                </button>
                <button onClick={() => setTheme('dark')} className={`p-6 rounded-2xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'dark' ? 'border-white bg-black dark:bg-white/10' : 'border-outline-variant/20 bg-surface-container-low'}`}>
                  <Moon size={24} />
                  <span className="font-bold text-sm">{t('settings.themeDark', 'Dark')}</span>
                </button>
                <button onClick={() => setTheme('system')} className={`p-6 rounded-2xl border-2 transition-all flex flex-col items-center gap-4 ${theme === 'system' ? 'border-blue-600 bg-blue-50 dark:bg-blue-900/20' : 'border-outline-variant/20 bg-surface-container-low'}`}>
                  <Monitor size={24} />
                  <span className="font-bold text-sm">{t('settings.themeSystem', 'System')}</span>
                </button>
              </div>
            </section>
          </>
        )}

        {activeTab === 'security' && (
          <>
            <MfaSection profile={profile} />
            <RecoveryKeySection 
              profile={profile} 
              setIsRecoveryModalOpen={setIsRecoveryModalOpen} 
              isGeneratingRecovery={false} 
              handleGenerateRecovery={handleGenerateRecovery}
              recoveryAuthPassword=""
              setRecoveryAuthPassword={() => {}}
              recoveryAuthError=""
            />
            
            <section>
               <button onClick={() => setIsEmergencyModalOpen(true)} className="w-full p-8 bg-amber-50 dark:bg-amber-950/20 border-2 border-amber-200 dark:border-amber-900/30 rounded-2xl flex items-center justify-between group">
                  <div className="flex items-center gap-6 text-left">
                    <div className="w-14 h-14 rounded-2xl bg-amber-500 text-white flex items-center justify-center shadow-lg shadow-amber-900/20 transition-transform group-hover:scale-110">
                      <ShieldAlert size={28} />
                    </div>
                    <div>
                      <h3 className="text-xl font-bold text-amber-900 dark:text-amber-100 mb-1">{t('settings.emergencyAccess', 'Emergency Access')}</h3>
                      <p className="text-sm text-amber-800/70 dark:text-amber-400/70 leading-relaxed max-w-lg">{t('settings.emergencyAccessDesc', 'Designate trusted contacts who can request access to your vault in an emergency.')}</p>
                    </div>
                  </div>
                  <ChevronDown className="-rotate-90 text-amber-600" size={24} />
               </button>
            </section>
          </>
        )}

        {activeTab === 'sessions' && (
          <section>
             <div className="flex items-center gap-3 mb-8">
                <History className="text-black dark:text-white" size={24} />
                <h2 className="text-2xl font-headline font-extrabold tracking-tight">{t('settings.activeSessions', 'Active Sessions')}</h2>
              </div>
              <button onClick={() => setIsAuditLogOpen(true)} className="px-8 py-4 bg-black text-white rounded-xl font-bold">{t('settings.openAuditLog', 'Open Audit Log')}</button>
          </section>
        )}

        {activeTab === 'import' && (
          <section>
             <p>{t('settings.importExportPlaceholder', 'Import/Export implementation here...')}</p>
          </section>
        )}
      </div>

      {/* Modals */}
      <AnimatePresence>
        {isEmergencyModalOpen && (
          <Suspense fallback={<div className="fixed inset-0 z-[110] bg-black/60 flex items-center justify-center"><Loader2 className="animate-spin text-white" /></div>}>
            <EmergencyAccessModal onClose={() => setIsEmergencyModalOpen(false)} />
          </Suspense>
        )}
      </AnimatePresence>

      <AuditLogModal isOpen={isAuditLogOpen} onClose={() => setIsAuditLogOpen(false)} />
      <SharesModal isOpen={isSharesOpen} onClose={() => setIsSharesOpen(false)} />
    </div>
  );
}
