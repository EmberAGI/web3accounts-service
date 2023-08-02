import "dotenv/config";
import { assertIsDefined } from "./assertion";

const envs = ["PORT", "RP_NAME", "RP_ID", "ORIGIN", "FIREBASE_CONFIG"] as const;
type Env = (typeof envs)[number];

export function assertEnv() {
  envs.forEach((env) => assertIsDefined(env, process.env[env]));
}

export function getEnv(env: Env) {
  const value = process.env[env];
  assertIsDefined(env, value);
  return value;
}
