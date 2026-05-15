import React from 'react';

interface UserAvatarProps {
  firstName: string;
  lastName: string;
  photoUrl?: string;
  className?: string;
}

export default function UserAvatar({ firstName, lastName, photoUrl, className }: UserAvatarProps) {
  // Accept either `blob:` (preferred — CSP allows it; UserContext uses it) or
  // `data:` (legacy callers / FileReader previews) so this component renders
  // photos regardless of how the URL was produced. `http(s):` is intentionally
  // NOT accepted: external image sources would defeat the same-origin avatar
  // policy and the CSP's `img-src 'self' blob:` would block them anyway.
  if (photoUrl && (photoUrl.startsWith('blob:') || photoUrl.startsWith('data:'))) {
    return (
      <img
        src={photoUrl}
        alt="Profile"
        className={className}
        referrerPolicy="no-referrer"
      />
    );
  }

  const initials = [firstName, lastName]
    .filter(Boolean)
    .map(n => n.charAt(0).toUpperCase())
    .join('')
    .slice(0, 2) || '?';

  // letter-spacing = -6% of font-size 636 = -38.16 SVG user units
  return (
    <svg
      viewBox="0 0 1000 1000"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label={`${firstName} ${lastName}`}
    >
      <rect width="1000" height="1000" fill="#8D60FF" />
      <text
        x="500"
        y="500"
        textAnchor="middle"
        dominantBaseline="central"
        fontFamily="Inter, sans-serif"
        fontWeight="bold"
        fontSize="636"
        letterSpacing="-38.16"
        fill="#fff"
        stroke="#000"
        strokeWidth="7"
        paintOrder="stroke fill"
      >
        {initials}
      </text>
    </svg>
  );
}
