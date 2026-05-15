import { describe, it, expect } from 'vitest';
import { exportToP2W } from './p2wFormat';
import type { Credential } from '../types';

const PASS = 'test-pass';
const FAST = { kdfParams: { log2M: 12, t: 1, p: 1 } } as const;

describe('P2W Payload Padding (Finding 2 fix)', () => {
  it('pads the payload to a consistent block size', async () => {
    const c1: Credential = { id: '1', service: 'A', username: 'U', password: 'P' } as any;
    const c2: Credential = { id: '2', service: 'B'.repeat(100), username: 'U', password: 'P' } as any;

    const file1 = await exportToP2W([c1], [], PASS, FAST);
    const file2 = await exportToP2W([c2], [], PASS, FAST);

    // Fixed overhead: 2 (NZ) + 96 (HDR) + 64 (HMAC) + 4 (LEN) + 64 (MAC) = 230 bytes
    // Plus the AES-GCM tag (16) and XChaCha tag (16) = 32 bytes
    // Total overhead = 262 bytes
    const PADDING_BLOCK_SIZE = 16384;

    const payloadLen1 = file1.length - 230 - 32;
    const payloadLen2 = file2.length - 230 - 32;

    expect(payloadLen1 % PADDING_BLOCK_SIZE).toBe(0);
    expect(payloadLen2 % PADDING_BLOCK_SIZE).toBe(0);
    
    // Even though c2 is ~100 bytes larger, the file sizes should be identical 
    // because they both fit into the first 16KB block.
    expect(file1.length).toBe(file2.length);
  });

  it('increases file size by exactly PADDING_BLOCK_SIZE when jumping blocks', async () => {
    // Create a credential large enough to push us into the next block
    // 16KB = 16384 bytes.
    const largeService = 'A'.repeat(16000);
    const c_large: Credential = { id: '3', service: largeService, username: 'U', password: 'P' } as any;
    
    const file_large = await exportToP2W([c_large], [], PASS, FAST);
    const payloadLen = file_large.length - 230 - 32;

    expect(payloadLen).toBeGreaterThan(16384);
    expect(payloadLen % 16384).toBe(0);
  });
});
