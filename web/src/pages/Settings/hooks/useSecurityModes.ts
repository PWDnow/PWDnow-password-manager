import { useState, useEffect } from 'react';
import {
  getDuressModeConfig,
  getDuressModeConfigFull,
  getTravelModeConfig,
  getTravelModeConfigAsync,
  armDuressMode,
  disarmDuressMode,
  enableTravelMode,
  disableTravelMode
} from '../../../utils/securityModes';
import { readDecryptedLocal, writeEncryptedLocal } from '../../../utils/localCrypto';
import type { EmailServerConfig } from '../../../types';

export function useSecurityModes() {
  const [sessionLockTimeout, setSessionLockTimeout] = useState('300000');
  const [emailServerConfig, setEmailServerConfig] = useState<EmailServerConfig | null>(null);
  const [duressConfig, setDuressConfig] = useState(getDuressModeConfig());
  const [travelConfig, setTravelConfig] = useState(getTravelModeConfig());
  
  const [duressMaxAttempts, setDuressMaxAttempts] = useState(duressConfig.maxAttempts);

  useEffect(() => {
    const lock = localStorage.getItem('session_lock_timeout') || '300000';
    setSessionLockTimeout(lock);
    
    readDecryptedLocal('email_server_config').then(raw => {
      if (raw) setEmailServerConfig(JSON.parse(raw));
    });

    // Refresh configurations from server if session is active
    getDuressModeConfigFull().then(setDuressConfig);
    getTravelModeConfigAsync().then(setTravelConfig);
  }, []);

  const handleSessionLockChange = (val: string) => {
    setSessionLockTimeout(val);
    localStorage.setItem('session_lock_timeout', val);
    window.dispatchEvent(new CustomEvent('sessionLockChanged', { detail: val }));
  };

  const refreshDuress = () => setDuressConfig(getDuressModeConfig());
  const refreshTravel = () => setTravelConfig(getTravelModeConfig());

  return {
    sessionLockTimeout,
    handleSessionLockChange,
    emailServerConfig,
    setEmailServerConfig,
    duressConfig,
    refreshDuress,
    travelConfig,
    refreshTravel,
    duressMaxAttempts,
    setDuressMaxAttempts
  };
}
