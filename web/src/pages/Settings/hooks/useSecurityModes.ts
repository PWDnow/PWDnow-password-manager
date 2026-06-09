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
import { apiFetch } from '../../../utils/api';
import type { EmailServerConfig } from '../../../types';

type ServerSmtpConfig = {
  host?: string;
  port?: number;
  protocol?: 'none' | 'ssl_tls' | 'starttls';
  username?: string;
  fromName?: string;
} | null;

export function useSecurityModes() {
  const [sessionLockTimeout, setSessionLockTimeout] = useState('300000');
  const [emailServerConfig, setEmailServerConfig] = useState<EmailServerConfig | null>(null);
  const [duressConfig, setDuressConfig] = useState(getDuressModeConfig());
  const [travelConfig, setTravelConfig] = useState(getTravelModeConfig());
  
  const [duressMaxAttempts, setDuressMaxAttempts] = useState(duressConfig.maxAttempts);

  useEffect(() => {
    const lock = localStorage.getItem('session_lock_timeout') || '300000';
    setSessionLockTimeout(lock);
    
    // Local copy first (it retains the password for editing in daemon/local mode).
    readDecryptedLocal('email_server_config').then(raw => {
      if (raw) setEmailServerConfig(JSON.parse(raw));
    });

    // The server is the source of truth for SMTP (it sends the OTP emails), so load
    // it on mount. This makes the "Configured" badge survive page reloads and
    // cleared local data, even when there is no in-memory local key. The password
    // is never returned by the server, so we preserve any locally-known password.
    apiFetch<ServerSmtpConfig>('/api/vault/smtp-config')
      .then(cfg => {
        if (cfg?.host) {
          setEmailServerConfig(prev => ({
            host: cfg.host as string,
            port: cfg.port ?? prev?.port ?? 465,
            user: cfg.username ?? prev?.user ?? '',
            pass: prev?.pass ?? '',
            protocol: cfg.protocol ?? prev?.protocol,
            secure: cfg.protocol === 'ssl_tls',
            fromName: cfg.fromName ?? prev?.fromName,
          }));
        }
      })
      .catch(() => { /* no server session (daemon/local mode) or not configured */ });

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
