import { argon2id, argon2d } from '@noble/hashes/argon2.js';

// Runs inside a Web Worker — never touches the main thread
self.onmessage = (e: MessageEvent) => {
  const { id, password, salt, memory, iterations, length, parallelism, type } = e.data as {
    id: number;
    password: ArrayBuffer;
    salt: ArrayBuffer;
    memory: number;
    iterations: number;
    length: number;
    parallelism: number;
    type: number;
  };

  try {
    const opts = { m: memory, t: iterations, p: parallelism, dkLen: length };
    let hash: Uint8Array;
    if (type === 0) {
      hash = argon2d(new Uint8Array(password), new Uint8Array(salt), opts);
    } else if (type === 2) {
      hash = argon2id(new Uint8Array(password), new Uint8Array(salt), opts);
    } else {
      throw new Error(`Unsupported Argon2 type: ${type}`);
    }
    self.postMessage({ id, result: hash.slice().buffer }, [hash.slice().buffer]);
  } catch (err) {
    self.postMessage({ id, error: (err as Error).message });
  }
};
