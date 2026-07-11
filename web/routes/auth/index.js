import { mountSessionsRoutes } from './sessions.js';
import { mountRegisterRoutes } from './register.js';
import { mountLoginRoutes } from './login.js';
import { mountSmtpRoutes } from './smtp.js';
import { mountMfaRoutes } from './mfa.js';

export function mountAuthRoutes(app) {
  mountSessionsRoutes(app);
  mountRegisterRoutes(app);
  mountLoginRoutes(app);
  mountSmtpRoutes(app);
  mountMfaRoutes(app);
}
