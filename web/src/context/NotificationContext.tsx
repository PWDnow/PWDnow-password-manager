import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Notification } from '../types';
import { generateUUID } from '../utils/crypto';
import { writeEncryptedLocal, readDecryptedLocal } from '../utils/localCrypto';

interface NotificationContextType {
  notifications: Notification[];
  unreadCount: number;
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  clearNotifications: () => void;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);
const NOTIF_KEY = 'vault_notifications';

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loaded, setLoaded] = useState(false);

  // Async load on mount — decryption requires keyStore local key to be set
  useEffect(() => {
    readDecryptedLocal(NOTIF_KEY)
      .then(s => {
        if (s) {
          try { setNotifications(JSON.parse(s) as Notification[]); } catch { /* corrupt — start empty */ }
        }
      })
      .catch(() => {})
      .finally(() => setLoaded(true));
  }, []);

  // Re-load after demo key becomes available (page reload, then re-login)
  useEffect(() => {
    const handler = () => {
      readDecryptedLocal(NOTIF_KEY)
        .then(s => {
          if (s) {
            try { setNotifications(JSON.parse(s) as Notification[]); } catch {}
          }
        })
        .catch(() => {});
    };
    window.addEventListener('demoKeyAvailable', handler);
    return () => window.removeEventListener('demoKeyAvailable', handler);
  }, []);

  // When daemon connects successfully, the notifications key becomes irrelevant —
  // clear it so nothing lingers in localStorage.
  useEffect(() => {
    const handler = () => {
      localStorage.removeItem(NOTIF_KEY);
    };
    window.addEventListener('daemonUnlocked', handler);
    return () => window.removeEventListener('daemonUnlocked', handler);
  }, []);

  // Persist (AES-GCM encrypted) on every change, but only after initial async load
  useEffect(() => {
    if (!loaded) return;
    writeEncryptedLocal(NOTIF_KEY, JSON.stringify(notifications)).catch(() => {});
  }, [notifications, loaded]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const addNotification = (n: Omit<Notification, 'id' | 'timestamp' | 'read'>) => {
    setNotifications(prev => [{
      ...n,
      id: generateUUID(),
      timestamp: Date.now(),
      read: false,
    }, ...prev]);
  };

  const markAsRead = (id: string) => {
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
  };

  const markAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const clearNotifications = () => setNotifications([]);

  return (
    <NotificationContext.Provider value={{
      notifications, unreadCount,
      addNotification, markAsRead, markAllAsRead, clearNotifications,
    }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotification() {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
}
