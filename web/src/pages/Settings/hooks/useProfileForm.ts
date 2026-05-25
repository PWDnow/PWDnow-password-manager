import { useState, useEffect, useMemo } from 'react';
import { daemon } from '../../../utils/daemonClient';
import { logger } from '../../../utils/logger';
import { useTranslation } from 'react-i18next';
import { useNotification } from '../../../context/NotificationContext';
import type { UserProfile } from '../../../context/UserContext';

export function useProfileForm(profile: UserProfile, updateProfile: (p: Partial<UserProfile>) => void, reloadProfile: () => Promise<void>) {
  const { t } = useTranslation();
  const { addNotification } = useNotification();
  const [localProfile, setLocalProfile] = useState(profile);
  const [isSaving, setIsSaving] = useState(false);
  const [showSaveSuccess, setShowSaveSuccess] = useState(false);

  useEffect(() => {
    setLocalProfile(profile);
  }, [profile]);

  const hasChanges = useMemo(() => {
    const fields = ['firstName', 'lastName', 'email', 'photoUrl', 'company', 'country'];
    return fields.some(k => localProfile[k] !== profile[k]);
  }, [localProfile, profile]);

  const handleLocalProfileChange = (field: keyof UserProfile, value: string) => {
    setLocalProfile(prev => ({ ...prev, [field]: value }));
  };

  const handleSaveProfile = async () => {
    setIsSaving(true);
    try {
      if (daemon.isConnected) {
        await daemon.updateProfile(
          localProfile.firstName ?? '',
          localProfile.lastName ?? '',
          localProfile.email ?? '',
        );

        const oldPhoto = profile.photoUrl;
        const newPhoto = localProfile.photoUrl;
        if (newPhoto && newPhoto !== oldPhoto && (newPhoto.startsWith('blob:') || newPhoto.startsWith('data:'))) {
          const res = await fetch(newPhoto);
          const blob = await res.blob();
          const arrayBuffer = await blob.arrayBuffer();
          const bytes = new Uint8Array(arrayBuffer);
          await daemon.uploadProfilePicture(bytes);
        } else if (!newPhoto && oldPhoto) {
          await daemon.removeProfilePicture();
        }

        await reloadProfile();
        setShowSaveSuccess(true);
        addNotification({ title: t('settings.profile', 'Profile'), message: t('settings.profileSaved', 'Profile updated successfully'), type: 'success' });
        setTimeout(() => setShowSaveSuccess(false), 3000);
      } else {
        updateProfile(localProfile);
        setShowSaveSuccess(true);
        addNotification({ title: t('settings.profile', 'Profile'), message: t('settings.profileSaved', 'Profile updated successfully'), type: 'success' });
        setTimeout(() => setShowSaveSuccess(false), 3000);
      }
    } catch (e: any) {
      logger.error('Failed to save profile:', e);
      addNotification({ title: t('common.error', 'Error'), message: e.message || 'Failed to save profile', type: 'error' });
    } finally {
      setIsSaving(false);
    }
  };

  const handlePhotoUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const result = e.target?.result as string;
      handleLocalProfileChange('photoUrl', result);
    };
    reader.readAsDataURL(file);
  };

  return {
    localProfile,
    isSaving,
    showSaveSuccess,
    hasChanges,
    handleLocalProfileChange,
    handleSaveProfile,
    handlePhotoUpload
  };
}
