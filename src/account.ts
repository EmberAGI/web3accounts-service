import {
  collection,
  doc,
  setDoc,
  getDoc,
  getDocs,
  updateDoc,
  deleteField,
  arrayUnion,
} from "firebase/firestore";
import db from "./firestore";
import W3asError from "./lib/w3asError";
import {
  AuthenticatorDevice,
  CredentialDeviceType,
} from "@simplewebauthn/typescript-types";
import crypto from "crypto";

export interface Authenticator {
  credentialIdBase64Url: string;
  credentialPublicKeyBase64Url: string;
  counter: number;
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
}

interface AccountAuthenticator {
  accountId: string;
  authenticator: Authenticator;
}

const usernamesRef = collection(db, "usernames");

export async function setAccountId(username: string) {
  let accountId = await getAccountIdFromUsername(username);

  if (accountId != null) {
    throw new W3asError({
      type: "register/options/username-already-exists",
      title: "Username already exists",
      status: 404,
      detail: `Username already exists for ${username}`,
    });
  }

  accountId = crypto.randomUUID();
  const accountIdRef = doc(usernamesRef, username);
  await setDoc(accountIdRef, { accountId: accountId });

  return accountId;
}

export async function getAccountIdFromUsername(username: string) {
  const accountIdRef = doc(usernamesRef, username);
  const accountIdSnap = await getDoc(accountIdRef);

  return accountIdSnap.data()?.accountId as string | undefined;
}

export async function getAccountIdFromCredentialId(credentialId: string) {
  const authenticatorRef = doc(authenticatorsRef, credentialId);
  const authenticatorSnap = await getDoc(authenticatorRef);

  return authenticatorSnap.data()?.accountId as string | undefined;
}

export function toAuthenticatorDevice(authenticator: Authenticator) {
  const authenticatorDevice: AuthenticatorDevice = {
    credentialID: Buffer.from(authenticator.credentialIdBase64Url, "base64url"),
    credentialPublicKey: Buffer.from(
      authenticator.credentialPublicKeyBase64Url,
      "base64url"
    ),
    counter: authenticator.counter,
  };

  return authenticatorDevice;
}

const accountsRef = collection(db, "accounts");
const authenticatorsRef = collection(db, "authenticators");

export async function setAccountAuthenticator(
  accountId: string,
  authenticator: Authenticator
) {
  const accountRef = doc(accountsRef, accountId);
  const credentialId = authenticator.credentialIdBase64Url;
  await updateDoc(accountRef, { authenticators: arrayUnion(credentialId) });

  const authenticatorRef = doc(authenticatorsRef, credentialId);
  await setDoc(authenticatorRef, { accountId, authenticator });
}

export async function getAccountAuthenticator(credentialId: string) {
  const authenticatorRef = doc(authenticatorsRef, credentialId);
  const authenticatorSnap = await getDoc(authenticatorRef);

  return authenticatorSnap.data() as AccountAuthenticator | undefined;
}

export async function updateAuthenticatorCounter(
  credentialId: string,
  newCounter: number
) {
  const authenticatorRef = doc(authenticatorsRef, credentialId);
  await updateDoc(authenticatorRef, { "authenticator.counter": newCounter });
}

export async function getAccountAuthenticators(
  accountId: string
): Promise<Authenticator[]> {
  const accountRef = doc(accountsRef, accountId);
  const accountSnap = await getDoc(accountRef);
  const credentialIds = (accountSnap.data()?.credentialIds as string[]) ?? [];
  const authenticators = await Promise.all(
    credentialIds.map(async (credentialId) => {
      try {
        const authenticatorRef = await doc(authenticatorsRef, credentialId);
        const authenticatorSnap = await getDoc(authenticatorRef);
        return authenticatorSnap.data()?.authenticator as Authenticator;
      } catch (error) {
        console.log(error);
      }
    })
  );

  return authenticators.filter(
    (authenticator): authenticator is Authenticator => authenticator != null
  );
}

export async function setCurrentChallenge(
  accountId: string,
  challenge: string
) {
  const accountRef = doc(accountsRef, accountId);
  await setDoc(accountRef, { challenge: challenge }, { merge: true });
}

export async function getCurrentChallenge(accountId: string) {
  const accountRef = doc(accountsRef, accountId);
  const accountSnap = await getDoc(accountRef);

  return accountSnap.data()?.challenge as string | undefined;
}

export async function removeCurrentChallenge(accountId: string) {
  const accountRef = doc(accountsRef, accountId);
  await updateDoc(accountRef, { challenge: deleteField() });
}
