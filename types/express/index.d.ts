export {};

declare global {
  namespace Express {
    interface Locals {
      accessTokenPayload?: import("../../src/authorization").AccessTokenPayload;
      authTokenPayload?: import("../../src/authentication").AuthTokenPayload;
    }
  }
}
