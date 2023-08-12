import {
  generateRegistrationOptions as genRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { RegistrationResponseJSON } from "@simplewebauthn/typescript-types";
import { getEnv } from "./lib/envVar";
import W3asError from "./lib/w3asError";
import {
  Authenticator,
  getAccountAuthenticators,
  getAccountIdFromUsername,
  getCurrentChallenge,
  removeCurrentChallenge,
  setAccountAuthenticator,
  setAccountId,
  setCurrentChallenge,
} from "./account";

export async function generateRegistrationOptions(username: string) {
  if ((await getAccountIdFromUsername(username)) != null) {
    throw new W3asError({
      type: "registeration/options/account-already-exists",
      title: "Account already exists",
      status: 400,
      detail: `Account already exists for ${username}`,
    });
  }

  const accountId = await setAccountId(username);
  const userAuthenticators = await getAccountAuthenticators(accountId);
  const options = genRegistrationOptions({
    rpName: getEnv("RP_NAME"),
    rpID: getEnv("RP_ID"),
    userID: accountId,
    userName: username,
    timeout: 60000,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
    excludeCredentials: userAuthenticators.map((authenticator) => ({
      id: Buffer.from(authenticator.credentialIdBase64Url, "base64url"),
      type: "public-key",
    })),
  });

  await setCurrentChallenge(accountId, options.challenge);

  return options;
}

export async function verifyAttestationReponse(
  username: string,
  attestationReponse: RegistrationResponseJSON
) {
  const accountId = await getAccountIdFromUsername(username);

  if (accountId == null) {
    throw new W3asError({
      type: "registeration/attestation/user-not-found",
      title: "User not found for attestation",
      status: 404,
      detail: `User (${username}) not found`,
    });
  }

  const expectedChallenge = await getCurrentChallenge(accountId);

  if (expectedChallenge == null) {
    throw new W3asError({
      type: "registeration/attestation/challenge-not-found",
      title: "Challenge not found during attestation",
      status: 500,
      detail: `Challenge not found for user (${username})`,
    });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attestationReponse,
      expectedChallenge,
      expectedOrigin: getEnv("ORIGIN"),
      expectedRPID: getEnv("RP_ID"),
    });
    if (!verification.verified) {
      return { verified: false };
    }
  } catch (error) {
    await removeCurrentChallenge(accountId);
    throw new W3asError(
      {
        type: "registeration/attestation/verify-registration-response-failed",
        title: "Failed to verify registration response",
        status: 500,
        detail: `Reason: ${error}`,
      },
      error
    );
  }

  const { registrationInfo } = verification;

  console.warn(JSON.stringify(registrationInfo, null, 2));

  if (registrationInfo == null) {
    await removeCurrentChallenge(accountId);
    throw new W3asError({
      type: "registeration/attestation/registration-info-missing",
      title: "Registration info missing",
      status: 500,
      detail: `Registration info missing from attestation verification response`,
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

  const credentialIdBase64Url = Buffer.from(credentialID).toString("base64url");
  console.log("credentialIdBase64: " + credentialIdBase64Url);
  const credentialPublicKeyBase64Url =
    Buffer.from(credentialPublicKey).toString("base64url");
  console.log("credentialPublicKey: " + credentialPublicKeyBase64Url);
  const authenticator: Authenticator = {
    credentialIdBase64Url: credentialIdBase64Url,
    credentialPublicKeyBase64Url: credentialPublicKeyBase64Url,
    counter: counter,
    credentialDeviceType: credentialDeviceType,
    credentialBackedUp: credentialBackedUp,
  };

  await setAccountAuthenticator(accountId, authenticator);
  await removeCurrentChallenge(accountId);

  return { verified: true };
}
