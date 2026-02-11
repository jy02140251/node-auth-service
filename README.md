# Node Auth Service

JWT authentication service with OAuth2 support.

## Features
- JWT token generation
- OAuth2 providers
- Session management
- Role-based access

## Install
```bash
npm install node-auth-service
```

## Usage
```javascript
const { AuthService } = require('node-auth-service');
const auth = new AuthService({ secret: 'your-secret' });
const token = auth.generateToken({ userId: 123 });
```