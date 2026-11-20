/**
 * Encryption/Decryption Error Classes
 */

export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncryptionError';
  }
}

export class DecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecryptionError';
  }
}

export class InvalidCiphertextError extends DecryptionError {
  constructor() {
    super('Invalid ciphertext format');
    this.name = 'InvalidCiphertextError';
  }
}

export class InvalidKeyError extends EncryptionError {
  constructor(message = 'Invalid encryption key') {
    super(message);
    this.name = 'InvalidKeyError';
  }
}

export class AuthenticationFailedError extends DecryptionError {
  constructor() {
    super('Authentication failed - data may have been tampered with');
    this.name = 'AuthenticationFailedError';
  }
}
