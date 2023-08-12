import { assertEnv, getEnv } from "./lib/envVar";
assertEnv();

import express, { CookieOptions, Request, Response } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import {
  generateRegistrationOptions,
  verifyAttestationReponse,
} from "./registration";
import W3asError from "./lib/w3asError";
import {
  authenticationOptions,
  createAuthJwt,
  verifyAssertionReponse,
} from "./authentication";
import { authorize, createAccessJwt } from "./authorization";
import { UAParser } from "ua-parser-js";
import {
  getAccountAuthenticators,
  getAccountIdFromCredentialId,
  getAccountIdFromUsername,
} from "./account";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { AuthenticationResponseJSON } from "@simplewebauthn/typescript-types";

export const IS_PRODUCTION = process.env.NODE_ENV === "production";
export const MAX_AGE = parseInt(getEnv("JWT_MAX_AGE_MINUTES"));
export const HOST = "localhost";

const app = express();

var corsOptions = {
  origin: `http://${HOST}:5173`,
  credentials: true,
  optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};
app.use(cors(corsOptions));

app.use(cookieParser());

app.get(
  "/registration/options/:username",
  async (req: Request, res: Response) => {
    try {
      const username = req.params.username;
      const options = await generateRegistrationOptions(username);
      res.send(options);
    } catch (error) {
      console.error(error);

      if (error instanceof W3asError) {
        res.status(error.problemDetail.status).send(error.problemDetail);
      } else {
        res.status(500).send(error);
      }
    }
  }
);

app.post(
  "/registration/:username",
  express.json(),
  async (req: Request, res: Response) => {
    console.warn(req.body);
    console.warn(
      `req.body.attestationResponse: ${JSON.stringify(
        req.body.attestationResponse
      )}`
    );
    if (req.body?.attestationResponse == null) {
      const error = new W3asError({
        type: "registeration/attestation/missing-attestation-response",
        title: "Missing attestation response",
        status: 400,
        detail: "Missing 'attestationReponse' parameter",
      });

      console.log(error);

      return res.status(error.problemDetail.status).send(error.problemDetail);
    }

    const username = req.params.username;
    const attestation = req.body.attestationResponse;

    let verification: { verified: boolean };
    try {
      verification = await verifyAttestationReponse(username, attestation);
      if (!verification.verified) {
        throw new W3asError({
          type: "registeration/attestation/verification-failed",
          title: "Attestation verification failed",
          status: 400,
          detail: `Attestation verification failed during registration for username (${username})`,
        });
      }
      const accountId = await getAccountIdFromUsername(username);
      if (accountId == null) {
        throw new W3asError({
          type: "registration/account-id-not-found",
          title: "Account ID not found",
          status: 500,
          detail: `Account ID not found for username (${username})`,
        });
      }

      const accessToken = await createAccessJwt(
        accountId,
        parseInt(getEnv("JWT_MAX_AGE_MINUTES"))
      );
      res
        .cookie("accessToken", accessToken, getAccessTokenCookieOptions(req))
        .sendStatus(200);
    } catch (error) {
      console.error(error);

      if (error instanceof W3asError) {
        res.status(error.problemDetail.status).send(error.problemDetail);
      } else {
        res.status(500).send(error);
      }
    }
  }
);

app.get(
  "/authentication/options",
  authenticationOptions,
  (req: Request, res: Response) => {}
);

app.get(
  "/authentication/options/:username",
  authenticationOptions,
  async (req: Request, res: Response) => {}
);

app.get(
  "/authentication/session",
  authorize,
  async (req: Request, res: Response) => {
    res.send({ accountId: res.locals.accessTokenPayload?.accountId });
  }
);

app.post(
  "/authentication/session",
  express.json(),
  async (req: Request, res: Response) => {
    //const username = req.params.username;

    //console.log(`username: ${username}`);

    const assertion: AuthenticationResponseJSON = req.body.assertionResponse;
    if (assertion == null) {
      const error = new W3asError({
        type: "authentication/session/missing-assertion-response",
        title: "Missing assertion response",
        status: 400,
        detail: "Missing 'assertionReponse' parameter",
      });

      console.log(error);

      return res.status(error.problemDetail.status).send(error.problemDetail);
    }

    console.log(req.cookies);
    console.log(`req.cookies: ${JSON.stringify(req.cookies)}`);
    const authToken = req.cookies.authToken;
    if (authToken == null) {
      const error = new W3asError({
        type: "authentication/session/missing-authenication-token",
        title: "Missing authentication token",
        status: 400,
        detail: "Missing authentication token in cookie",
      });

      console.log(error);

      return res.status(error.problemDetail.status).send(error.problemDetail);
    }

    let verification: { verified: boolean };
    try {
      verification = await verifyAssertionReponse(assertion, authToken);

      if (!verification.verified) {
        throw new W3asError({
          type: "authentication/session/failed-assertion-verification",
          title: "Failed assertion verification",
          status: 400,
          detail: "Failed assertion verification",
        });
      }

      res.cookie("authToken", "", {
        httpOnly: true,
        secure: isCookieSecure(req),
        sameSite: "none",
        domain: `.${HOST}`,
        expires: new Date(0),
        maxAge: 0,
      });

      const accountId = await getAccountIdFromCredentialId(assertion.id);
      if (accountId == null) {
        throw new W3asError({
          type: "authentication/session/account-id-not-found",
          title: "Account ID not found",
          status: 500,
          detail: `Account ID not found for credential ID (${assertion.id})`,
        });
      }

      const accessToken = await createAccessJwt(
        accountId,
        parseInt(getEnv("JWT_MAX_AGE_MINUTES"))
      );
      res
        .cookie("accessToken", accessToken, getAccessTokenCookieOptions(req))
        .sendStatus(200);
    } catch (error) {
      console.error(error);

      if (error instanceof W3asError) {
        res.status(error.problemDetail.status).send(error.problemDetail);
      } else {
        res.status(500).send(error);
      }
    }
  }
);

app.delete(
  "/authentication/session",
  authorize,
  async (req: Request, res: Response) => {
    res.cookie("accessToken", "", {
      httpOnly: true,
      secure: isCookieSecure(req),
      sameSite: "none",
      domain: `.${HOST}`,
      expires: new Date(0),
      maxAge: 0,
    });
    res.sendStatus(200);
  }
);

function isCookieSecure(req: Request): boolean {
  const userAgent = req.headers["user-agent"];
  const parser = new UAParser(userAgent);
  const parserResults = parser.getResult();
  return IS_PRODUCTION || parserResults.browser.name !== "Safari";
}

function getAccessTokenCookieOptions(req: Request): CookieOptions {
  return {
    httpOnly: true,
    secure: isCookieSecure(req),
    sameSite: "none",
    domain: `.${HOST}`,
    expires: new Date(Date.now() + MAX_AGE * 60 * 1000),
    maxAge: MAX_AGE * 60 * 1000,
  };
}

const port = parseInt(getEnv("PORT"));
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
