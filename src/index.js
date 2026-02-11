const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class AuthService {
  constructor(options = {}) {
    this.secret = options.secret || crypto.randomBytes(32).toString('hex');
    this.expiresIn = options.expiresIn || '24h';
    this.algorithm = options.algorithm || 'HS256';
  }

  generateToken(payload) {
    return jwt.sign(payload, this.secret, {
      expiresIn: this.expiresIn,
      algorithm: this.algorithm
    });
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, this.secret);
    } catch (err) {
      throw new AuthError('Invalid token', 'INVALID_TOKEN');
    }
  }

  refreshToken(token) {
    const decoded = this.verifyToken(token);
    delete decoded.iat;
    delete decoded.exp;
    return this.generateToken(decoded);
  }

  hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return ${salt}:;
  }

  verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const verify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === verify;
  }
}

class AuthError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

module.exports = { AuthService, AuthError };