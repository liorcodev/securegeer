/**
 * Base JWT error class
 */
export class JWTError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JWTError';
  }
}

/**
 * Thrown when JWT token has invalid format (not 3 parts separated by dots)
 */
export class JWTInvalidFormatError extends JWTError {
  constructor() {
    super('Invalid JWT format');
    this.name = 'JWTInvalidFormatError';
  }
}

/**
 * Thrown when JWT header cannot be decoded or is malformed
 */
export class JWTInvalidHeaderError extends JWTError {
  constructor() {
    super('Invalid JWT header');
    this.name = 'JWTInvalidHeaderError';
  }
}

/**
 * Thrown when JWT payload cannot be decoded or is malformed
 */
export class JWTInvalidPayloadError extends JWTError {
  constructor() {
    super('Invalid JWT payload');
    this.name = 'JWTInvalidPayloadError';
  }
}

/**
 * Thrown when JWT token is generally invalid
 */
export class JWTInvalidTokenError extends JWTError {
  constructor() {
    super('Invalid JWT token');
    this.name = 'JWTInvalidTokenError';
  }
}

/**
 * Thrown when JWT signature verification fails
 */
export class JWTInvalidSignatureError extends JWTError {
  constructor() {
    super('Invalid signature');
    this.name = 'JWTInvalidSignatureError';
  }
}

/**
 * Thrown when JWT algorithm doesn't match expected algorithm
 */
export class JWTAlgorithmMismatchError extends JWTError {
  constructor(expected: string, got: string) {
    super(`Algorithm mismatch: expected ${expected}, got ${got}`);
    this.name = 'JWTAlgorithmMismatchError';
  }
}

/**
 * Thrown when JWT token type is not "JWT"
 */
export class JWTInvalidTokenTypeError extends JWTError {
  constructor() {
    super('Invalid token type');
    this.name = 'JWTInvalidTokenTypeError';
  }
}

/**
 * Thrown when JWT token has expired (exp claim)
 */
export class JWTExpiredError extends JWTError {
  constructor() {
    super('Token has expired');
    this.name = 'JWTExpiredError';
  }
}

/**
 * Thrown when JWT token is not yet valid (nbf claim)
 */
export class JWTNotBeforeError extends JWTError {
  constructor() {
    super('Token not yet valid');
    this.name = 'JWTNotBeforeError';
  }
}

/**
 * Thrown when JWT issuer doesn't match expected issuer
 */
export class JWTIssuerMismatchError extends JWTError {
  constructor(expected: string, got: string | undefined) {
    super(`Issuer mismatch: expected ${expected}, got ${got}`);
    this.name = 'JWTIssuerMismatchError';
  }
}

/**
 * Thrown when JWT subject doesn't match expected subject
 */
export class JWTSubjectMismatchError extends JWTError {
  constructor(expected: string, got: string | undefined) {
    super(`Subject mismatch: expected ${expected}, got ${got}`);
    this.name = 'JWTSubjectMismatchError';
  }
}

/**
 * Thrown when JWT audience doesn't match expected audience
 */
export class JWTAudienceMismatchError extends JWTError {
  constructor() {
    super('Audience mismatch');
    this.name = 'JWTAudienceMismatchError';
  }
}

/**
 * Thrown when time format string is invalid (should be like "1h", "7d")
 */
export class JWTInvalidTimeFormatError extends JWTError {
  constructor(time: string) {
    super(`Invalid time format: ${time}`);
    this.name = 'JWTInvalidTimeFormatError';
  }
}
