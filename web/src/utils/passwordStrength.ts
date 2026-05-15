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
  if (len >= 6  && hasLower && hasNumber)                           return 2;
  if (len >= 4  && hasLower)                                        return 1;
  return 0;
}

/** Returns a label for a given score. */
export function scoreLabel(score: number): string {
  return ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong', 'Excellent'][score] ?? 'Unknown';
}
