import { getCsrfToken, apiFetch, hasServerSession } from '../utils/api';
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { daemon } from '../utils/daemonClient';
import { keyStore } from '../crypto/keystore';

export interface UserProfile {
  firstName: string;
  lastName: string;
  email: string;
  company: string;
  country: string;
  photoUrl: string;
  passwordChangedAt?: number;
  recoveryKeyGeneratedAt?: number;
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

/**
 * Daemon stores the profile picture as raw PNG bytes (re-encoded server-side
 * by `upload_picture` in user_profile.rs). The CSP (`img-src 'self' blob:`,
 * MED-09) disallows `data:` URLs as an exfil-vector mitigation, so we wrap
 * the bytes in a Blob and hand the UI a `blob:` URL instead. The caller is
 * responsible for revoking the URL when the photo changes — see the
 * useEffect cleanup in UserProvider below.
 */
function pngBytesToBlobUrl(bytes: Uint8Array): string {
  return URL.createObjectURL(new Blob([bytes], { type: 'image/png' }));
}

export function UserProvider({ children }: { children: ReactNode }) {
  const [profile, setProfile] = useState<UserProfile>(defaultProfile);

  const reloadProfile = async () => {
    try {
      const { firstName, lastName, email, profilePic, passwordChangedAt } = await daemon.getProfile();
      const photoUrl = profilePic && profilePic.length > 0 ? pngBytesToBlobUrl(profilePic) : '';
      setProfile(prev => {
        // Free the previous blob URL so we don't leak object URLs on every reload.
        if (prev.photoUrl && prev.photoUrl.startsWith('blob:')) URL.revokeObjectURL(prev.photoUrl);
        return { ...prev, firstName, lastName, email, photoUrl, passwordChangedAt };
      });
    } catch (err: any) {
      // A daemon "session expired" error only means the whole app session is
      // dead when the daemon was our ONLY auth path. Server-mode users have
      // a valid `_pwd_sess` session while the local daemon is simply never
      // unlocked (session_token unset) — daemon.getProfile() fails the same
      // way whether the daemon session truly expired or never existed, so
      // treating it as globally fatal here logged every server-mode user out
      // on load. Fall through to the server-session fallback below instead.
      if (err?.message?.includes('Session expired') && !hasServerSession()) {
        keyStore.clear();
        window.dispatchEvent(new CustomEvent('sessionInvalid'));
        return;
      }
      // Daemon unavailable - fetch from offline API fallback
      try {
        const data = await apiFetch<any>('/api/auth/me').catch(() => null);
        if (data && data.authenticated && data.user) {
          setProfile(prev => ({ 
            ...prev, 
            firstName: data.user.firstName || '', 
            lastName: data.user.lastName || '', 
            email: data.user.email || '',
            passwordChangedAt: data.user.passwordChangedAt,
            recoveryKeyGeneratedAt: data.user.recoveryKeyGeneratedAt
          }));
        } else {
          keyStore.clear();
          window.dispatchEvent(new CustomEvent('sessionInvalid'));
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
