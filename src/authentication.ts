import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import jwt from "jsonwebtoken";
import { getEnv } from "./lib/envVar";
import {
  AuthenticationResponseJSON,
  Base64URLString,
} from "@simplewebauthn/typescript-types";
import {
  getAccountAuthenticator,
  getAccountAuthenticators,
  getAccountIdFromUsername,
  toAuthenticatorDevice,
  updateAuthenticatorCounter,
} from "./account";
import W3asError from "./lib/w3asError";
import { Request, Response, NextFunction } from "express";
import UAParser from "ua-parser-js";
import { HOST, IS_PRODUCTION, MAX_AGE } from ".";

export interface AuthTokenPayload {
  authChallenge: Base64URLString;
}

export async function authenticationOptions(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const accountId = req.params.username
      ? await getAccountIdFromUsername(req.params.username)
      : undefined;
    const authenticators = accountId
      ? await getAccountAuthenticators(accountId)
      : [];
    const authOptions = generateAuthenticationOptions({
      // Require users to use a previously-registered authenticator
      allowCredentials: authenticators.map((authenticator) => ({
        id: Buffer.from(authenticator.credentialIdBase64Url, "base64url"),
        type: "public-key",
      })),
      userVerification: "preferred",
    });
    const token = createAuthJwt(authOptions.challenge, MAX_AGE);
    const userAgent = req.headers["user-agent"];
    const parser = new UAParser(userAgent);
    const parserResults = parser.getResult();
    const isCookieSecure =
      IS_PRODUCTION || parserResults.browser.name !== "Safari";

    res.cookie("authToken", token, {
      httpOnly: true,
      secure: isCookieSecure,
      sameSite: "none",
      domain: `.${HOST}`,
      expires: new Date(Date.now() + MAX_AGE * 60 * 1000),
      maxAge: MAX_AGE * 60 * 1000,
    });
    console.log("authToken", token);
    res.status(200).send(authOptions);
  } catch (error) {
    console.error(error);

    if (error instanceof W3asError) {
      res.status(error.problemDetail.status).send(error.problemDetail);
    } else {
      res.status(500).send(error);
    }
  }
}

export async function verifyAssertionReponse(
  //username: string,
  assertionResponse: AuthenticationResponseJSON,
  authToken: string
): Promise<{ verified: boolean }> {
  try {
    const publicKeyBase64 = getEnv("JWT_PUBLIC_KEY");
    const publicKey = Buffer.from(publicKeyBase64, "base64");
    const payload = jwt.verify(authToken, publicKey) as AuthTokenPayload;

    /*const accountId = await getAccountId(username);
    if (accountId == null) {
      throw new W3asError({
        type: "authenticate/assertion/account-not-found",
        title: "Account not found for assertion",
        status: 404,
        detail: `Account not found for username (${username})`,
      });
    }*/
    const accountAuthenticator = await getAccountAuthenticator(
      assertionResponse.id
    );
    if (accountAuthenticator == null) {
      throw new W3asError({
        type: "authentication/assertion/authenticator-not-found",
        title: "Authenticator not found for assertion",
        status: 404,
        detail: `Authenticator not found for credential (${assertionResponse.id})`,
      });
    }

    const authenticator = accountAuthenticator.authenticator;
    const authenticatorDevice = toAuthenticatorDevice(authenticator);
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: payload.authChallenge,
      expectedOrigin: getEnv("ORIGIN"),
      expectedRPID: getEnv("RP_ID"),
      authenticator: authenticatorDevice,
    });
    const { verified, authenticationInfo } = verification;

    if (!verified) {
      return { verified };
    }

    const { newCounter } = authenticationInfo;
    await updateAuthenticatorCounter(
      authenticator.credentialIdBase64Url,
      newCounter
    );

    return { verified };
  } catch (error) {
    if (error instanceof W3asError) {
      throw error;
    } else {
      throw new W3asError(
        {
          type: "authentication/assertion/verify-assertion-response-failed",
          title: "Failed to verify assertion response",
          status: 500,
          detail: `Reason: ${error}`,
        },
        error
      );
    }
  }
}

export function createAuthJwt(
  authChallenge: Base64URLString,
  expiresInMinutes: number
) {
  const payload: AuthTokenPayload = {
    authChallenge,
  };
  const privateKeyBase64 = getEnv("JWT_PRIVATE_KEY");
  const privateKey = Buffer.from(privateKeyBase64, "base64");
  const options: jwt.SignOptions = {
    algorithm: getEnv("JWT_ALGORITHM") as jwt.Algorithm,
    expiresIn: `${expiresInMinutes}m`,
  };

  return jwt.sign(payload, privateKey, options);
}
