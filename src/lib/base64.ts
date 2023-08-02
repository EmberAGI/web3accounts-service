export function base64ToBytes(base64: string) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0)!);
}

export function bytesToBase64(bytes: ArrayLike<number>) {
  const binString = Array.from(bytes, (x: number) =>
    String.fromCodePoint(x)
  ).join("");
  return btoa(binString);
}
