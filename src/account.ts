import {
  collection,
  doc,
  setDoc,
  getDoc,
  getDocs,
  updateDoc,
  deleteField,
} from "firebase/firestore";
import db from "./firestore";
import W3asError from "./lib/w3asError";
import { CredentialDeviceType } from "@simplewebauthn/typescript-types";
import crypto from "crypto";

export interface Authenticator {
  credentialIdBase64: string;
  credentialPublicKeyBase64: string;
  counter: number;
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
}

const accountIdsRef = collection(db, "accountIds");

export async function setAccountId(username: string) {
  let accountId = await getAccountId(username);

  if (accountId != null) {
    throw new W3asError({
      type: "register/options/username-already-exists",
      title: "Username already exists",
      status: 404,
      detail: `Username already exists for ${username}`,
    });
  }

  accountId = crypto.randomUUID();
  const accountIdRef = doc(accountIdsRef, username);
  await setDoc(accountIdRef, { id: accountId });

  return accountId;
}

export async function getAccountId(username: string) {
  const accountIdRef = doc(accountIdsRef, username);
  const accountIdSnap = await getDoc(accountIdRef);

  return accountIdSnap.exists() ? (accountIdSnap.data().id as string) : null;
}

const accountsRef = collection(db, "accounts");

export async function setAccountAuthenticator(
  accountId: string,
  authenticator: Authenticator
) {
  const authenticatorRef = doc(
    accountsRef,
    accountId,
    "authenticators",
    authenticator.credentialIdBase64
  );
  await setDoc(authenticatorRef, authenticator);
}

export async function getAccountAuthenticators(
  accountId: string
): Promise<Authenticator[]> {
  const authenticatorsRef = collection(
    accountsRef,
    accountId,
    "authenticators"
  );
  const authenticatorsSnap = await getDocs(authenticatorsRef);

  return authenticatorsSnap.docs.map((doc) => doc.data() as Authenticator);
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

  if (!accountSnap.exists()) {
    return null;
  }

  const challenge = accountSnap.data().challenge;
  return challenge ? (challenge as string) : null;
}

export async function removeCurrentChallenge(accountId: string) {
  const accountRef = doc(accountsRef, accountId);
  await updateDoc(accountRef, { challenge: deleteField() });
}
