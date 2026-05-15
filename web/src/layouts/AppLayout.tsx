import React, { useState, useEffect } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import CreateFolderModal from '../components/CreateFolderModal';
import { useVault } from '../context/VaultContext';
import { motion, AnimatePresence } from 'motion/react';
import { keyStore } from '../crypto/keystore';
import { loadMfaConfigFromServer } from '../utils/mfa';

import { UserProvider } from '../context/UserContext';
import InstallPrompt from '../components/InstallPrompt';

export default function AppLayout() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isRestoringKeys, setIsRestoringKeys] = useState(true);
  const { folders, addFolder } = useVault();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    keyStore.restoreAsync().finally(() => {
      setIsRestoringKeys(false);
      window.dispatchEvent(new CustomEvent('demoKeyAvailable'));
    });
  }, []);

  useEffect(() => {
    if (isRestoringKeys) return;

    const hasServerSession = document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
    const hasLocalKeys = keyStore.getLocalKey(1) !== null || keyStore.getLocalKey(2) !== null;
    if (!keyStore.hasToken && (!hasServerSession || !hasLocalKeys)) {
      navigate('/login');
      return;
    }
    // After a page refresh in server-session mode the in-memory MFA cache is empty.
    // Re-load from the server so Settings shows the correct TOTP state without
    // requiring re-login. Also removes any legacy plaintext mfa_config_plain key.
    if (hasServerSession) {
      localStorage.removeItem('mfa_config_plain');
      loadMfaConfigFromServer().catch(() => {});
    }
  }, [navigate]);

  // ── Reactive session validation ─────────────────────────────────────────────
  // Detect stale sessions when cookies are cleared while the user is on the
  // dashboard (e.g. via browser settings, DevTools, or another tab).

  useEffect(() => {
    // 1. When the tab becomes visible again, check if the session cookie still
    //    exists. If not, the user cleared cookies while away - redirect to login.
    const handleVisibility = () => {
      if (document.visibilityState !== 'visible') return;
      const hasCsrf = document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
      // In daemon mode keyStore.hasToken is enough; in server mode the CSRF
      // cookie is the canonical session indicator.
      if (!hasCsrf && !keyStore.hasToken) {
        keyStore.clear();
        navigate('/login');
      }
    };

    // 2. VaultContext dispatches 'sessionInvalid' when any vault API call
    //    returns 401 (server rejected the session cookie).
    const handleSessionInvalid = () => {
      keyStore.clear();
      navigate('/login');
    };

    document.addEventListener('visibilitychange', handleVisibility);
    window.addEventListener('sessionInvalid', handleSessionInvalid);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibility);
      window.removeEventListener('sessionInvalid', handleSessionInvalid);
    };
  }, [navigate]);

  // Determine active tab based on path
  let activeTab = 'vault';
  if (location.pathname.startsWith('/vault/')) {
    activeTab = location.pathname.replace('/vault/', '');
  } else if (location.pathname === '/security') {
    activeTab = 'security';
  } else if (location.pathname === '/settings') {
    activeTab = 'settings';
  } else if (location.pathname === '/manage-folders') {
    activeTab = 'manage-folders';
  } else if (location.pathname === '/dashboard') {
    activeTab = 'dashboard';
  } else if (location.pathname === '/asset-holder') {
    activeTab = 'assetHolder';
  } else if (location.pathname === '/health') {
    activeTab = 'health';
  }

  const handleAddFolder = async (newFolder: any) => {
    try {
      // addFolder returns the *resolved* id (which may differ if the daemon
      // assigned its own UUID, or if the supplied id collided locally).
      const resolvedId = await addFolder(newFolder);
      navigate(`/vault/${resolvedId}`);
    } catch (err) {
      // VaultContext already pushed a "could not save" notification + rolled
      // back React state; nothing more to do here besides staying put.
      console.error('[AppLayout] folder create failed:', err);
    }
  };

  const handleTabChange = (tab: string) => {
    if (tab === 'security') navigate('/security');
    else if (tab === 'settings') navigate('/settings');
    else if (tab === 'manage-folders') navigate('/manage-folders');
    else if (tab === 'dashboard') navigate('/dashboard');
    else if (tab === 'assetHolder') navigate('/asset-holder');
    else if (tab === 'health') navigate('/health');
    else if (tab === 'vault') navigate('/vault');
    else navigate(`/vault/${tab}`);
    
    setIsSidebarOpen(false);
  };

  return (
    <UserProvider>
      <div className="min-h-screen bg-surface overflow-x-hidden">
        <CreateFolderModal 
          isOpen={isCreateModalOpen} 
          onClose={() => setIsCreateModalOpen(false)} 
          onAddFolder={handleAddFolder} 
        />

        <Sidebar 
          activeTab={activeTab} 
          setActiveTab={handleTabChange} 
          isOpen={isSidebarOpen}
          onClose={() => setIsSidebarOpen(false)}
          folders={folders}
          onCreateFolder={() => setIsCreateModalOpen(true)}
          onManageFolders={() => handleTabChange('manage-folders')}
        />
        <Header activeTab={activeTab} onMenuClick={() => setIsSidebarOpen(true)} />
        
        <main className="ml-16 md:ml-64 pt-24 pb-20 px-6 md:px-12 min-h-screen transition-all duration-300">
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
      <InstallPrompt />
    </UserProvider>
  );
}
