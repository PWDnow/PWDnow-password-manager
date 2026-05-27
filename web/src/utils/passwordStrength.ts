/** Returns a numeric strength score 0–5 for a password (higher = stronger). */
export function passwordScore(pwd: string): number {
  if (!pwd) return 0;
  const len = pwd.length;
  const hasUpper   = /[A-Z]/.test(pwd);
  const hasLower   = /[a-z]/.test(pwd);
  const hasNumber  = /[0-9]/.test(pwd);
  const hasSpecial = /[^A-Za-z0-9]/.test(pwd);

  if (len >= 16 && hasUpper && hasLower && hasNumber && hasSpecial) return 5;
  if (len >= 12 && hasUpper && hasLower && hasNumber && hasSpecial) return 4;
  if (len >= 8  && hasUpper && hasLower && hasNumber)               return 3;
  if (len >= 6  && hasLower && hasNumber && !hasSpecial)            return 2;
  if (len >= 4  && hasLower && !hasUpper && !hasSpecial)            return 1;
  if (len >= 1  && len <= 3 && !hasUpper && !hasNumber && !hasSpecial) return 0;

  // Dynamic fallback: length alone still gives credit (matches AddCredential display logic)
  if (len >= 20) return 5;
  if (len >= 12) return 3;
  if (len >= 8)  return 2;
  return 1;
}

/** Returns a label for a given score. */
export function scoreLabel(score: number): string {
  return ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong', 'Excellent'][score] ?? 'Unknown';
}
