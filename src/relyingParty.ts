import {
  generateRegistrationOptions as genRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import {
  CredentialDeviceType,
  RegistrationResponseJSON,
} from "@simplewebauthn/typescript-types";

interface Authenticator {
  credentialIdBase64: string;
  credentialPublicKeyBase64: string;
  counter: number;
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
}

// Human-readable title for your website
const RP_NAME = "Firepot Web3account";
// A unique identifier for your website
const RP_ID = location.hostname;
// The URL at which registrations and authentications should occur
const ORIGIN = `http://${RP_ID}:5173`;

export function generateRegistrationOptions(username: string) {
  const userId = getUserId(username) || setUserId(username);
  const userAuthenticators = getUserAuthenticators(userId);

  const options = genRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
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

  setCurrentUserChallenge(userId, options.challenge);

  return options;
}

export async function verifyRegistration(
  username: string,
  response: RegistrationResponseJSON,
) {
  const userId = getUserId(username);

  if (userId == null) {
    throw new Error(`User (${username}) not found`);
  }

  const expectedChallenge = getCurrentUserChallenge(userId);

  if (expectedChallenge == null) {
    throw new Error(`Challenge not found for user (${username})`);
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
  } catch (error) {
    console.error(error);
    removeCurrentUserChallenge(userId);
    throw error;
  }

  const { verified, registrationInfo } = verification;

  console.warn(JSON.stringify(registrationInfo, null, 2));

  if (registrationInfo == null) {
    removeCurrentUserChallenge(userId);
    throw new Error("Registration info not found");
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

  setUserAuthenticator(userId, authenticator);
  removeCurrentUserChallenge(userId);

  return { verified };
}

function setUserId(username: string) {
  const userId = crypto.randomUUID();
  localStorage.setItem(username, userId);
  return userId;
}

function getUserId(username: string) {
  return localStorage.getItem(username);
}

function setCurrentUserChallenge(userId: string, challenge: string) {
  localStorage.setItem(userId + "-challenge", challenge);
}

function getCurrentUserChallenge(userId: string) {
  return localStorage.getItem(userId + "-challenge");
}

function removeCurrentUserChallenge(userId: string) {
  localStorage.removeItem(userId + "-challenge");
}

function setUserAuthenticator(userId: string, authenticator: Authenticator) {
  const authenticators = getUserAuthenticators(userId);
  authenticators.push(authenticator);
  localStorage.setItem(userId, JSON.stringify(authenticators));
}

function getUserAuthenticators(userId: string): Authenticator[] {
  const authenticatorsJson = localStorage.getItem(userId);
  return authenticatorsJson ? JSON.parse(authenticatorsJson) : [];
}

function base64ToBytes(base64: string) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0)!);
}

function bytesToBase64(bytes: ArrayLike<number>) {
  const binString = Array.from(bytes, (x: number) =>
    String.fromCodePoint(x),
  ).join("");
  return btoa(binString);
}
