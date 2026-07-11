import promClient from 'prom-client';

// Create a Registry
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

export const loginSuccessCounter = new promClient.Counter({
  name: 'pwdnow_login_success_total',
  help: 'Total number of successful logins',
  registers: [register],
});

export const loginFailureCounter = new promClient.Counter({
  name: 'pwdnow_login_failure_total',
  help: 'Total number of failed logins',
  registers: [register],
});

export const mfaVerificationLatency = new promClient.Histogram({
  name: 'pwdnow_mfa_verification_duration_seconds',
  help: 'Duration of MFA verifications',
  buckets: [0.1, 0.5, 1, 2, 5],
  registers: [register],
});

export const rateLimitHitCounter = new promClient.Counter({
  name: 'pwdnow_rate_limit_hit_total',
  help: 'Total number of rate limit hits',
  labelNames: ['endpoint'],
  registers: [register],
});

export const argon2idDerivationLatency = new promClient.Histogram({
  name: 'pwdnow_argon2id_derivation_duration_seconds',
  help: 'Duration of Argon2id master key derivations',
  buckets: [0.1, 0.5, 1, 2, 5, 10],
  registers: [register],
});

export const grpcLatency = new promClient.Histogram({
  name: 'pwdnow_grpc_request_duration_seconds',
  help: 'Duration of gRPC round-trip latency to the daemon',
  labelNames: ['method'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2],
  registers: [register],
});

export const metricsRegister = register;
