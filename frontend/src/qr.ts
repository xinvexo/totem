import jsQR from "jsqr";

interface LoadedImage {
  source: CanvasImageSource;
  width: number;
  height: number;
  close?: () => void;
}

async function loadImage(blob: Blob): Promise<LoadedImage> {
  if (typeof createImageBitmap === "function") {
    try {
      const bitmap = await createImageBitmap(blob);
      return {
        source: bitmap,
        width: bitmap.width,
        height: bitmap.height,
        close: () => bitmap.close(),
      };
    } catch {
      // Fall back to an HTMLImageElement for browsers without full ImageBitmap support.
    }
  }

  const objectUrl = URL.createObjectURL(blob);
  try {
    const image = await new Promise<HTMLImageElement>((resolve, reject) => {
      const element = new Image();
      element.onload = () => resolve(element);
      element.onerror = () => reject(new Error("image_load_failed"));
      element.src = objectUrl;
    });
    return {
      source: image,
      width: image.naturalWidth,
      height: image.naturalHeight,
      close: () => URL.revokeObjectURL(objectUrl),
    };
  } catch (error) {
    URL.revokeObjectURL(objectUrl);
    throw error;
  }
}

function decodeCanvas(canvas: HTMLCanvasElement): string | null {
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return null;
  const image = context.getImageData(0, 0, canvas.width, canvas.height);
  return jsQR(image.data, canvas.width, canvas.height, { inversionAttempts: "attemptBoth" })?.data ?? null;
}

/** Decode a QR code from a local image without uploading or persisting the image. */
export async function decodeQrImage(blob: Blob): Promise<string | null> {
  const image = await loadImage(blob);
  try {
    const longestSide = Math.max(image.width, image.height);
    if (!longestSide) return null;

    // Keep the first pass close to the source, then retry at larger/smaller
    // scales so a QR inside a full-page screenshot has a better chance to scan.
    const longestSides = [...new Set([
      Math.min(longestSide, 1800),
      Math.min(longestSide, 2400),
      Math.min(Math.round(longestSide * 1.5), 2800),
    ])];
    const canvas = document.createElement("canvas");
    for (const targetLongestSide of longestSides) {
      const scale = targetLongestSide / longestSide;
      canvas.width = Math.max(1, Math.round(image.width * scale));
      canvas.height = Math.max(1, Math.round(image.height * scale));
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) return null;
      context.clearRect(0, 0, canvas.width, canvas.height);
      context.imageSmoothingEnabled = scale < 1;
      context.drawImage(image.source, 0, 0, canvas.width, canvas.height);
      const result = decodeCanvas(canvas);
      if (result) return result;
    }
    return null;
  } finally {
    image.close?.();
  }
}
