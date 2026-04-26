import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { daemon } from '../utils/daemonClient';

interface UserProfile {
  firstName: string;
  lastName: string;
  email: string;
  company: string;
  country: string;
  photoUrl: string;
  passwordChangedAt?: number;
}

interface UserContextType {
  profile: UserProfile;
  updateProfile: (updates: Partial<UserProfile>) => void;
  reloadProfile: () => Promise<void>;
}

const defaultProfile: UserProfile = {
  firstName: '',
  lastName: '',
  email: '',
  company: '',
  country: 'United States',
  photoUrl: '',
};

const UserContext = createContext<UserContextType | undefined>(undefined);

export function UserProvider({ children }: { children: ReactNode }) {
  const [profile, setProfile] = useState<UserProfile>(defaultProfile);

  const reloadProfile = async () => {
    try {
      const { firstName, lastName, email, passwordChangedAt } = await daemon.getProfile();
      setProfile(prev => ({ ...prev, firstName, lastName, email, passwordChangedAt }));
    } catch {
      // Daemon unavailable — fetch from offline API fallback
      try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
          const data = await res.json();
          if (data.authenticated && data.user) {
            setProfile(prev => ({ 
              ...prev, 
              firstName: data.user.firstName || '', 
              lastName: data.user.lastName || '', 
              email: data.user.email || '',
              passwordChangedAt: data.user.passwordChangedAt
            }));
          }
        }
      } catch {
        // Keep current profile
      }
    }
  };

  useEffect(() => {
    reloadProfile();
    const handler = () => { reloadProfile(); };
    window.addEventListener('daemonUnlocked', handler);
    return () => window.removeEventListener('daemonUnlocked', handler);
  }, []);

  const updateProfile = (updates: Partial<UserProfile>) => {
    setProfile(prev => ({ ...prev, ...updates }));
  };

  return (
    <UserContext.Provider value={{ profile, updateProfile, reloadProfile }}>
      {children}
    </UserContext.Provider>
  );
}

export function useUser() {
  const context = useContext(UserContext);
  if (context === undefined) throw new Error('useUser must be used within a UserProvider');
  return context;
}
