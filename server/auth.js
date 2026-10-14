import { createHash, randomBytes } from 'node:crypto';

// Salted password hashing
function hashPassword(password, salt) {
  return createHash('sha256').update(password + ':' + salt).digest('hex');
}

// Default initial accounts with cryptographic salts
const USERS = {
  'lab.assistant': {
    salt: 'salt_assistant_2026',
    passwordHash: hashPassword('LabTrace@2026', 'salt_assistant_2026'),
    role: 'Lab Assistant',
    displayName: 'Lab Assistant (Triage)'
  },
  'lab.supervisor': {
    salt: 'salt_supervisor_2026',
    passwordHash: hashPassword('Supervisor@2026', 'salt_supervisor_2026'),
    role: 'Supervisor',
    displayName: 'Security Supervisor (Sign-off)'
  }
};

// In-memory active session store
const sessions = new Map();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export const authService = {
  login(username, password) {
    const user = USERS[String(username).trim().toLowerCase()];
    if (!user) {
      throw new Error('Invalid credentials');
    }

    const testHash = hashPassword(password, user.salt);
    if (testHash !== user.passwordHash) {
      throw new Error('Invalid credentials');
    }

    const token = randomBytes(32).toString('hex');
    const sessionData = {
      token,
      username: String(username).trim().toLowerCase(),
      role: user.role,
      name: user.displayName,
      createdAt: Date.now(),
      expiresAt: Date.now() + SESSION_TTL_MS
    };

    sessions.set(token, sessionData);
    return sessionData;
  },

  // Mock SSO for Entra ID / Google Workspace sign-in demonstration
  ssoLogin(provider, email, role = 'Lab Assistant') {
    const username = email.split('@')[0].toLowerCase();
    const token = randomBytes(32).toString('hex');
    const sessionData = {
      token,
      username,
      role,
      name: `${username} (${provider} SSO)`,
      createdAt: Date.now(),
      expiresAt: Date.now() + SESSION_TTL_MS
    };

    sessions.set(token, sessionData);
    return sessionData;
  },

  demoLogin() {
    const token = randomBytes(32).toString('hex');
    const sessionData = {
      token,
      username: 'demo.supervisor',
      role: 'Supervisor',
      name: 'Supervisor (Demo Mode)',
      isDemo: true,
      createdAt: Date.now(),
      expiresAt: Date.now() + SESSION_TTL_MS
    };

    sessions.set(token, sessionData);
    return sessionData;
  },

  validateSession(token) {
    if (!token) return null;
    const session = sessions.get(token);
    if (!session) return null;

    if (Date.now() > session.expiresAt) {
      sessions.delete(token);
      return null;
    }

    return session;
  },

  logout(token) {
    if (token) {
      sessions.delete(token);
    }
    return true;
  },

  requireAuth(requiredRole = null) {
    return (req, res, next) => {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : req.headers['x-session-token'];

      const session = authService.validateSession(token);
      if (!session) {
        return res.status(401).json({ error: 'Unauthorized: valid session token required' });
      }

      if (requiredRole && session.role !== requiredRole && session.role !== 'Supervisor') {
        return res.status(403).json({ error: `Forbidden: requires ${requiredRole} role` });
      }

      req.user = session;
      next();
    };
  }
};
