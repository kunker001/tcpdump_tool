import React from 'react';

interface EmptyStateProps {
  variant: 'disconnected' | 'ready' | 'servers' | 'logs';
  title: string;
  description: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ variant, title, description, action }) => {
  return (
    <div className="empty-state">
      {variant === 'disconnected' && (
        <svg width="88" height="72" viewBox="0 0 88 72" fill="none">
          <rect x="8" y="14" width="30" height="44" rx="5" fill="#F7F9FC" stroke="#CBD5E1" strokeWidth="1.5" />
          <circle cx="16" cy="24" r="2.5" fill="#94A3B8" />
          <line x1="22" y1="24" x2="32" y2="24" stroke="#CBD5E1" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="16" cy="34" r="2.5" fill="#94A3B8" />
          <line x1="22" y1="34" x2="32" y2="34" stroke="#CBD5E1" strokeWidth="1.5" strokeLinecap="round" />
          <rect x="50" y="14" width="30" height="44" rx="5" fill="#EBF5FF" stroke="#93C5FD" strokeWidth="1.5" />
          <circle cx="58" cy="24" r="2.5" fill="#1677FF" />
          <line x1="64" y1="24" x2="74" y2="24" stroke="#93C5FD" strokeWidth="1.5" strokeLinecap="round" />
          <line x1="38" y1="36" x2="50" y2="36" stroke="#CBD5E1" strokeWidth="1.5" strokeDasharray="3 3" />
        </svg>
      )}
      {variant === 'ready' && (
        <svg width="88" height="72" viewBox="0 0 88 72" fill="none">
          <rect x="10" y="12" width="68" height="48" rx="6" fill="#F7F9FC" stroke="#CBD5E1" strokeWidth="1.5" />
          <line x1="10" y1="24" x2="78" y2="24" stroke="#E2E8F0" strokeWidth="1.5" />
          <circle cx="18" cy="18" r="2" fill="#94A3B8" />
          <circle cx="25" cy="18" r="2" fill="#CBD5E1" />
          <path d="M22 44 L34 36 L44 42 L56 30 L66 38" stroke="#1677FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          <circle cx="56" cy="30" r="3" fill="#EBF5FF" stroke="#1677FF" strokeWidth="1.5" />
        </svg>
      )}
      {variant === 'servers' && (
        <svg width="84" height="68" viewBox="0 0 84 68" fill="none">
          <rect x="14" y="12" width="56" height="18" rx="4" fill="#F7F9FC" stroke="#CBD5E1" strokeWidth="1.5" />
          <circle cx="24" cy="21" r="2.5" fill="#1677FF" />
          <line x1="32" y1="21" x2="60" y2="21" stroke="#CBD5E1" strokeWidth="1.5" strokeLinecap="round" />
          <rect x="14" y="38" width="56" height="18" rx="4" fill="#F7F9FC" stroke="#CBD5E1" strokeWidth="1.5" />
          <circle cx="24" cy="47" r="2.5" fill="#94A3B8" />
          <line x1="32" y1="47" x2="54" y2="47" stroke="#CBD5E1" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      )}
      {variant === 'logs' && (
        <svg width="80" height="64" viewBox="0 0 80 64" fill="none">
          <rect x="16" y="10" width="48" height="44" rx="5" fill="#F7F9FC" stroke="#CBD5E1" strokeWidth="1.5" />
          <line x1="25" y1="22" x2="55" y2="22" stroke="#93C5FD" strokeWidth="2" strokeLinecap="round" />
          <line x1="25" y1="32" x2="49" y2="32" stroke="#CBD5E1" strokeWidth="1.5" strokeLinecap="round" />
          <line x1="25" y1="42" x2="43" y2="42" stroke="#CBD5E1" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      )}
      <div className="empty-title">{title}</div>
      <div className="empty-desc">{description}</div>
      {action && <div style={{ marginTop: 14 }}>{action}</div>}
    </div>
  );
};
