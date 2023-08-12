import jwt from "jsonwebtoken";
import { getEnv } from "./lib/envVar";
import { getAccountIdFromUsername } from "./account";
import W3asError from "./lib/w3asError";
import { Request, Response, NextFunction } from "express";

export interface AccessTokenPayload {
  accountId: string;
}

export function authorize(req: Request, res: Response, next: NextFunction) {
  console.log(req.cookies);
  console.log(`req.cookies: ${JSON.stringify(req.cookies)}`);
  const token = req.cookies.accessToken;

  if (!token) {
    const error = new W3asError({
      type: "authorize/access-token/missing-access-token",
      title: "Access token not found",
      status: 401,
      detail: "Access token must be provided in cookie",
    });
    console.warn(error);
    return res.status(error.problemDetail.status).send(error.problemDetail);
  }

  try {
    const publicKeyBase64 = getEnv("JWT_PUBLIC_KEY");
    const publicKey = Buffer.from(publicKeyBase64, "base64");
    res.locals.accessTokenPayload = verifyAccessJwt(token);
    next();
  } catch (error) {
    console.error(error);
    return res.sendStatus(403);
  }
}

export async function createAccessJwt(
  accountId: string,
  expiresInMinutes: number
) {
  /*const accountId = await getAccountId(username);

  if (accountId == null) {
    throw new W3asError({
      type: "authorize/access-token/account-not-found",
      title: "Account not found for access token",
      status: 500,
      detail: `Account not found for username (${username})`,
    });
  }*/

  const payload: AccessTokenPayload = {
    accountId,
  };
  const privateKeyBase64 = getEnv("JWT_PRIVATE_KEY");
  const privateKey = Buffer.from(privateKeyBase64, "base64");
  const options: jwt.SignOptions = {
    algorithm: getEnv("JWT_ALGORITHM") as jwt.Algorithm,
    expiresIn: `${expiresInMinutes}m`,
  };

  return jwt.sign(payload, privateKey, options);
}

function verifyAccessJwt(token: string) {
  try {
    const publicKeyBase64 = getEnv("JWT_PUBLIC_KEY");
    const publicKey = Buffer.from(publicKeyBase64, "base64");
    return jwt.verify(token, publicKey) as AccessTokenPayload;
  } catch (error) {
    throw new W3asError(
      {
        type: "authorize/access-token/verification-failed",
        title: "Failed to verify access token",
        status: 403,
        detail: `Reason: ${error}`,
      },
      error
    );
  }
}
