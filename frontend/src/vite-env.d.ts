/// <reference types="vite/client" />

declare module "jsqr" {
  interface QRCode {
    data: string;
    binaryData: number[];
    chunks: unknown[];
    version: number;
    location: unknown;
  }

  function jsQR(
    data: Uint8ClampedArray,
    width: number,
    height: number,
    options?: { inversionAttempts?: "dontInvert" | "onlyInvert" | "attemptBoth" | "invertFirst" },
  ): QRCode | null;

  export default jsQR;
}
