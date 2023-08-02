import {
  generateRegistrationOptions as genRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { RegistrationResponseJSON } from "@simplewebauthn/typescript-types";
import { getEnv } from "./lib/envVar";
import { base64ToBytes, bytesToBase64 } from "./lib/base64";
import W3asError from "./lib/w3asError";
import {
  Authenticator,
  getAccountAuthenticators,
  getAccountId,
  getCurrentChallenge,
  removeCurrentChallenge,
  setAccountAuthenticator,
  setAccountId,
  setCurrentChallenge,
} from "./account";

export async function generateRegistrationOptions(username: string) {
  const userId =
    (await getAccountId(username)) || (await setAccountId(username));
  const userAuthenticators = await getAccountAuthenticators(userId);
  const options = genRegistrationOptions({
    rpName: getEnv("RP_NAME"),
    rpID: getEnv("RP_ID"),
    userID: userId,
    userName: username,
    timeout: 60000,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
    excludeCredentials: userAuthenticators.map((authenticator) => ({
      id: base64ToBytes(authenticator.credentialIdBase64),
      type: "public-key",
    })),
  });

  await setCurrentChallenge(userId, options.challenge);

  return options;
}

export async function verifyRegistration(
  username: string,
  response: RegistrationResponseJSON
) {
  const userId = await getAccountId(username);

  if (userId == null) {
    throw new W3asError({
      type: "register/verification/user-not-found",
      title: "User not found for verification",
      status: 404,
      detail: `User (${username}) not found`,
    });
  }

  const expectedChallenge = await getCurrentChallenge(userId);

  if (expectedChallenge == null) {
    throw new W3asError({
      type: "register/verification/challenge-not-found",
      title: "Challenge not found during verification",
      status: 500,
      detail: `Challenge not found for user (${username})`,
    });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getEnv("ORIGIN"),
      expectedRPID: getEnv("RP_ID"),
    });
  } catch (error) {
    await removeCurrentChallenge(userId);
    throw new W3asError(
      {
        type: "register/verification/verify-registration-response-failed",
        title: "Failed to verify registration response",
        status: 500,
        detail: `Reason: ${error}`,
      },
      error
    );
  }

  const { verified, registrationInfo } = verification;

  console.warn(JSON.stringify(registrationInfo, null, 2));

  if (registrationInfo == null) {
    await removeCurrentChallenge(userId);
    throw new W3asError({
      type: "register/verification/registration-info-not-found",
      title: "Challenge not found during verification",
      status: 500,
      detail: `Challenge not found for user (${username})`,
    });
  }

  const {
    credentialPublicKey,
    credentialID,
    counter,
    credentialDeviceType,
    credentialBackedUp,
  } = registrationInfo;

  /*if (credentialDeviceType !== "multiDevice" || credentialBackedUp !== true) {
    removeCurrentUserChallenge(userId);
    return { verified: false, message: "Not a passkey" };
  }*/

  const authenticator: Authenticator = {
    credentialIdBase64: bytesToBase64(credentialID),
    credentialPublicKeyBase64: bytesToBase64(credentialPublicKey),
    counter: counter,
    credentialDeviceType: credentialDeviceType,
    credentialBackedUp: credentialBackedUp,
  };

  await setAccountAuthenticator(userId, authenticator);
  await removeCurrentChallenge(userId);

  return { verified };
}
