import React, { useState, useEffect } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import CreateFolderModal from '../components/CreateFolderModal';
import { useVault } from '../context/VaultContext';
import { motion, AnimatePresence } from 'motion/react';
import { keyStore } from '../crypto/keystore';

import { UserProvider } from '../context/UserContext';

export default function AppLayout() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const { folders, addFolder } = useVault();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (!keyStore.hasToken) {
      navigate('/login');
    }
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
  }

  const handleAddFolder = (newFolder: any) => {
    addFolder(newFolder);
    navigate(`/vault/${newFolder.id}`);
  };

  const handleTabChange = (tab: string) => {
    if (tab === 'security') navigate('/security');
    else if (tab === 'settings') navigate('/settings');
    else if (tab === 'manage-folders') navigate('/manage-folders');
    else if (tab === 'dashboard') navigate('/dashboard');
    else if (tab === 'assetHolder') navigate('/asset-holder');
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
    </UserProvider>
  );
}
