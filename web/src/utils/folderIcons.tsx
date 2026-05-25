import React from 'react';
import {
  Wallet, Globe, Briefcase, Gamepad2, Bitcoin, Dices,
  Folder as FolderIcon, Shield, CreditCard, Key,
  Home, Landmark, Building2, Server, Cloud, Database,
  Code, Terminal, Music, Headphones, Film, Tv, Camera,
  ShoppingCart, ShoppingBag, Heart, HeartPulse, Package,
  Plane, Car, GraduationCap, BookOpen,
  Smartphone, Wifi, Lock, Mail, Phone,
  Users, User, Star, Zap, Cpu, Newspaper, Rss,
  Fingerprint, AtSign,
} from 'lucide-react';

type IconProps = { size?: number; className?: string };

function BankIcon({ size = 24, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
         className={className}>
      <path d="M3 10h18M3 22h18M12 2L3 10h18L12 2z" />
      <line x1="6" y1="10" x2="6" y2="22" />
      <line x1="10" y1="10" x2="10" y2="22" />
      <line x1="14" y1="10" x2="14" y2="22" />
      <line x1="18" y1="10" x2="18" y2="22" />
    </svg>
  );
}

function SocialIcon({ size = 24, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
         className={className}>
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
    </svg>
  );
}

function MedicalIcon({ size = 24, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
         className={className}>
      <path d="M9 2h6v6h6v6h-6v6H9v-6H3V8h6z" />
    </svg>
  );
}

function IdCardIcon({ size = 24, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
         className={className}>
      <rect x="2" y="5" width="20" height="14" rx="2" />
      <circle cx="8" cy="12" r="2" />
      <path d="M14 9h4M14 13h3" />
    </svg>
  );
}

function ContactlessIcon({ size = 24, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
         className={className}>
      <rect x="2" y="5" width="20" height="14" rx="2" />
      <path d="M2 10h20" />
      <path d="M14 14.5a2.5 2.5 0 0 0 0-5" />
      <path d="M17.5 16a5 5 0 0 0 0-8" />
    </svg>
  );
}

function VpnIcon({ size = 24, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
         className={className}>
      <path d="M12 22C6.5 19.5 3 15 3 12V5l9-3 9 3v7c0 3-3.5 7.5-9 10z" />
      <circle cx="12" cy="12" r="2" />
      <path d="M12 8v2M12 14v2M8 12h2M14 12h2" />
    </svg>
  );
}

function CloudLockIcon({ size = 24, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
         className={className}>
      <path d="M17.5 19H7a4 4 0 0 1 0-8h.5A6 6 0 0 1 19 13.5" />
      <rect x="9" y="14" width="6" height="6" rx="1" />
      <path d="M10 14v-1.5a2 2 0 1 1 4 0V14" />
    </svg>
  );
}

export const ICON_MAP: Record<string, React.ComponentType<IconProps>> = {
  // General
  Folder: FolderIcon,
  Home,
  Star,
  User,
  Users,
  // Finance
  Wallet,
  CreditCard,
  Contactless: ContactlessIcon,
  Bitcoin,
  Bank: BankIcon,
  Landmark,
  // Work & Office
  Briefcase,
  Building2,
  // Technology
  Globe,
  Server,
  Cloud,
  CloudLock: CloudLockIcon,
  Database,
  Code,
  Terminal,
  Cpu,
  Wifi,
  Smartphone,
  AtSign,
  // Security & Identity
  Shield,
  Lock,
  Key,
  Vpn: VpnIcon,
  Fingerprint,
  IdCard: IdCardIcon,
  // Communication
  Mail,
  Phone,
  // Entertainment & Gaming
  Gamepad2,
  Music,
  Headphones,
  Film,
  Tv,
  Camera,
  // Shopping & Services
  ShoppingCart,
  ShoppingBag,
  Package,
  // Health & Medical
  Heart,
  HeartPulse,
  Medical: MedicalIcon,
  // Travel & Transport
  Plane,
  Car,
  // Education
  GraduationCap,
  BookOpen,
  // Social & News
  Social: SocialIcon,
  Rss,
  Newspaper,
  // Other
  Zap,
  Dices,
};
