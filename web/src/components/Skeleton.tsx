import React from 'react';

/** Single pulsing placeholder block. Shape/size is controlled entirely via `className`. */
export function SkeletonBlock({ className = '' }: { className?: string }) {
  return <div className={`bg-surface-container-high/60 animate-pulse rounded-lg ${className}`} aria-hidden="true" />;
}

/** Row of skeleton blocks matching the shape of a Sidebar folder entry. */
export function SkeletonFolderRow() {
  return (
    <div className="w-full flex items-center py-3 px-4 gap-3">
      <SkeletonBlock className="w-5 h-5 rounded-md shrink-0" />
      <SkeletonBlock className="h-3.5 flex-1 max-w-[120px]" />
    </div>
  );
}
