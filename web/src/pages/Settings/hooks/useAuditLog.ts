import { useState, useEffect } from 'react';
import { apiFetch } from '../../../utils/api';
import { getSessions, clearOtherSessions, formatSessionTime, type LoginSession } from '../../../utils/sessionTracker';
import type { AuditEvent, ShareLink } from '../../../types';

export function useAuditLog() {
  const [auditTab, setAuditTab] = useState<'sessions' | 'events'>('sessions');
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditEventsTotal, setAuditEventsTotal] = useState(0);
  const [auditEventsLoading, setAuditEventsLoading] = useState(false);
  
  const [sessions, setSessions] = useState<LoginSession[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);
  const [revokeSuccess, setRevokeSuccess] = useState(false);

  const [shares, setShares] = useState<ShareLink[]>([]);
  const [sharesLoading, setSharesLoading] = useState(false);

  const refreshSessions = async () => {
    setSessionsLoading(true);
    try {
      const s = await getSessions();
      setSessions(s);
    } finally {
      setSessionsLoading(false);
    }
  };

  const refreshAuditEvents = async () => {
    setAuditEventsLoading(true);
    try {
      const data = await apiFetch<any>('/api/audit/events?limit=50');
      if (data.ok) {
        setAuditEvents(data.events);
        setAuditEventsTotal(data.total);
      }
    } finally {
      setAuditEventsLoading(false);
    }
  };

  const refreshShares = async () => {
    setSharesLoading(true);
    try {
      const data = await apiFetch<any>('/api/vault/shares');
      if (data.ok) setShares(data.shares);
    } finally {
      setSharesLoading(false);
    }
  };

  const handleRevokeAll = async () => {
    setIsRevoking(true);
    try {
      await clearOtherSessions();
      await refreshSessions();
      setRevokeSuccess(true);
      setTimeout(() => setRevokeSuccess(false), 3000);
    } finally {
      setIsRevoking(false);
    }
  };

  return {
    auditTab,
    setAuditTab,
    auditEvents,
    setAuditEvents,
    auditEventsTotal,
    setAuditEventsTotal,
    auditEventsLoading,
    sessions,
    sessionsLoading,
    isRevoking,
    setIsRevoking,
    revokeSuccess,
    refreshSessions,
    refreshAuditEvents,
    handleRevokeAll,
    shares,
    setShares,
    sharesLoading,
    refreshShares
  };
}
