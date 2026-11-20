/**
 * Base64url helpers shared across modules (internal, not part of the public API)
 *
 * Processes data in chunks so large payloads don't overflow the stack when spreading.
 */

const CHUNK_SIZE = 8192;

export const toBase64Url = (bytes: Uint8Array): string => {
  let binaryString = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    binaryString += String.fromCharCode(...bytes.subarray(i, i + CHUNK_SIZE));
  }
  return btoa(binaryString).replace(/[+/=]/g, char =>
    char === '+' ? '-' : char === '/' ? '_' : ''
  );
};

export const fromBase64Url = (data: string): Uint8Array<ArrayBuffer> => {
  const base64 = data.replace(/[-_]/g, char => (char === '-' ? '+' : '/'));
  const pad = base64.length % 4;
  const paddedBase64 = pad ? base64 + '='.repeat(4 - pad) : base64;
  const binaryString = atob(paddedBase64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
};
