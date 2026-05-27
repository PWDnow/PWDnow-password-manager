import { describe, it, expect } from 'vitest';
import {
  charsetSize,
  randomPasswordBits,
  passphraseBits,
  classifyQuantum,
  crackTime,
  quantumCrackTime,
  ATTACKER_PROFILES,
  QUANTUM_PROOF_BITS,
  QUANTUM_RESISTANT_BITS,
} from './passwordEntropy';

describe('charsetSize', () => {
  it('sums the enabled character classes', () => {
    expect(charsetSize({ uppercase: true, lowercase: true, numbers: true, symbols: true })).toBe(92);
    expect(charsetSize({ uppercase: false, lowercase: true, numbers: true, symbols: false })).toBe(36);
  });
  it('never returns 0 (avoids log2(0))', () => {
    expect(charsetSize({ uppercase: false, lowercase: false, numbers: false, symbols: false })).toBe(1);
  });
});

describe('entropy helpers', () => {
  it('computes random-password entropy as length * log2(charset)', () => {
    // 24 chars from the full 92-symbol pool ≈ 156.6 bits (the advisory's example)
    expect(randomPasswordBits(24, 92)).toBeCloseTo(156.6, 0);
  });
  it('computes passphrase entropy from the wordlist size', () => {
    // 6 words from the EFF long list (7776 words) ≈ 77.5 bits
    expect(passphraseBits(6, 7776)).toBeCloseTo(77.5, 0);
  });
  it('returns 0 for degenerate inputs', () => {
    expect(randomPasswordBits(0, 92)).toBe(0);
    expect(passphraseBits(3, 1)).toBe(0);
  });
});

describe('classifyQuantum', () => {
  it('flags <128 bits as vulnerable', () => {
    expect(classifyQuantum(100).level).toBe('vulnerable');
    expect(classifyQuantum(127.9).level).toBe('vulnerable');
  });
  it('flags 128–255 bits as resistant (e.g. the 156-bit example)', () => {
    expect(classifyQuantum(QUANTUM_RESISTANT_BITS).level).toBe('resistant');
    expect(classifyQuantum(156).level).toBe('resistant');
    expect(classifyQuantum(156).isQuantumProof).toBe(false);
  });
  it('flags >=256 bits as quantum-proof', () => {
    const a = classifyQuantum(QUANTUM_PROOF_BITS);
    expect(a.level).toBe('proof');
    expect(a.isQuantumProof).toBe(true);
    expect(a.postQuantumBits).toBe(128); // matches AES-256 post-Grover
  });
  it('halves the bits for the post-quantum figure', () => {
    expect(classifyQuantum(156).postQuantumBits).toBe(78);
  });
  it('handles non-finite / negative input safely', () => {
    expect(classifyQuantum(NaN).bits).toBe(0);
    expect(classifyQuantum(-5).level).toBe('vulnerable');
  });
});

describe('crackTime', () => {
  it('reports instant for trivial passwords', () => {
    expect(crackTime(10, ATTACKER_PROFILES.gpu).unit).toBe('instant');
  });

  it('produces a representable year count for mid-strength passwords', () => {
    // 64 bits at 1e10/s: 2^63 / 1e10 ≈ 9.2e8 s ≈ 29 years
    const t = crackTime(64, ATTACKER_PROFILES.gpu);
    expect(t.unit).toBe('years');
    expect(t.value).toBeGreaterThan(20);
    expect(t.value).toBeLessThan(40);
    expect(t.beyondUniverse).toBe(false);
  });

  it('flags astronomically strong passwords as beyond the age of the universe', () => {
    const t = crackTime(156, ATTACKER_PROFILES.nationState);
    expect(t.beyondUniverse).toBe(true);
    expect(['years', 'powerYears']).toContain(t.unit);
  });

  it('uses powerYears (order-of-magnitude) for the very largest spaces', () => {
    const t = crackTime(256, ATTACKER_PROFILES.nationState);
    expect(t.unit).toBe('powerYears');
    expect(t.value).toBeGreaterThan(50);
  });

  it('scales inversely with attacker speed', () => {
    const slow = crackTime(80, ATTACKER_PROFILES.online).log10Seconds;
    const fast = crackTime(80, ATTACKER_PROFILES.nationState).log10Seconds;
    expect(slow).toBeGreaterThan(fast);
    // exactly the ratio of the two rates (10^10), in log10 space
    expect(slow - fast).toBeCloseTo(10, 6);
  });
});

describe('quantumCrackTime (Grover)', () => {
  it('matches the classical estimate evaluated at half the entropy', () => {
    const q = quantumCrackTime(156, ATTACKER_PROFILES.nationState);
    const c = crackTime(78, ATTACKER_PROFILES.nationState);
    expect(q.log10Seconds).toBeCloseTo(c.log10Seconds, 6);
  });

  it('makes a 156-bit password quantum-crackable in a human-comprehensible span', () => {
    // 78 effective bits at 1e12/s ≈ thousands of years — finite, not eternity
    const q = quantumCrackTime(156, ATTACKER_PROFILES.nationState);
    expect(q.unit).toBe('years');
  });

  it('keeps a 256-bit password effectively uncrackable even with Grover', () => {
    const q = quantumCrackTime(256, ATTACKER_PROFILES.nationState);
    expect(q.beyondUniverse).toBe(true);
  });
});
