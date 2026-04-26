import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import SEO from '../components/SEO';

export default function NotFound() {
  const { t } = useTranslation();
  
  return (
    <div className="min-h-screen bg-surface flex flex-col items-center justify-center p-6 text-center">
      <SEO 
        title={t('notfound.title', 'Vault Not Found')}
        description={t('notfound.description', 'The encrypted sector you are looking for does not exist or you do not have the required clearance.')}
      />
      <div className="w-24 h-24 bg-error/10 text-error rounded-3xl flex items-center justify-center mb-8 shadow-sm">
        <ShieldAlert size={48} strokeWidth={1.5} />
      </div>
      <h1 className="text-8xl font-headline font-black tracking-tighter text-black mb-4 leading-none">404</h1>
      <h2 className="text-2xl font-bold text-black mb-6 tracking-tight">{t('notfound.title', 'Vault Not Found')}</h2>
      <p className="text-on-surface-variant max-w-md mx-auto mb-10 text-lg font-medium leading-relaxed">
        {t('notfound.description', 'The encrypted sector you are looking for does not exist or you do not have the required clearance.')}
      </p>
      <Link 
        to="/vault"
        className="group relative inline-flex items-center gap-3 bg-black text-white px-8 py-4 rounded-2xl font-black text-xs uppercase tracking-widest transition-all hover:bg-neutral-800 active:scale-95 shadow-lg"
      >
        <ArrowLeft size={16} className="group-hover:-translate-x-1 transition-transform" />
        {t('notfound.back', 'Return to Vault')}
      </Link>
    </div>
  );
}
