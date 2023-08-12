import "dotenv/config";
import { assertIsDefined } from "./assertion";

const envs = [
  "PORT",
  "RP_NAME",
  "RP_ID",
  "ORIGIN",
  "JWT_ALGORITHM",
  "JWT_PRIVATE_KEY",
  "JWT_PUBLIC_KEY",
  "JWT_MAX_AGE_MINUTES",
  "FIREBASE_CONFIG",
] as const;
type Env = (typeof envs)[number];

export function assertEnv() {
  envs.forEach((env) => assertIsDefined(env, process.env[env]));
}

export function getEnv(env: Env) {
  const value = process.env[env];
  assertIsDefined(env, value);
  return value;
}
