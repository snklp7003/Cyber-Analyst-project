import jsQR from 'jsqr';
import QRCode from 'qrcode';
import type { LiveScanResult, LookalikeGenerationResult, QrPlainTextResult } from '../types/scan';

export const MAX_QR_FILE_BYTES = 5 * 1024 * 1024; // 5 MB

export interface QrDecodeOutcome {
  extractedText?: string;
  isUrl?: boolean;
  detectedFormat?: 'PNG' | 'JPEG';
  plainTextResult?: QrPlainTextResult;
  error?: string;
}

/**
 * Validates genuine image binary magic bytes:
 * PNG:  89 50 4E 47 0D 0A 1A 0A
 * JPEG: FF D8 FF
 */
export async function detectActualImageFormat(file: File): Promise<'PNG' | 'JPEG' | null> {
  const headerBuffer = await file.slice(0, 12).arrayBuffer();
  const bytes = new Uint8Array(headerBuffer);
  if (bytes.length < 4) return null;

  const isPng =
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a;

  if (isPng) return 'PNG';

  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return 'JPEG';
  }

  return null;
}

function isLikelyUrl(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      return Boolean(parsed.hostname && parsed.hostname.includes('.'));
    } catch {
      return false;
    }
  }

  return /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(\/.*)?$/.test(trimmed);
}

function loadImageFromFile(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const objectUrl = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error('The uploaded file could not be decoded as a valid image.'));
    };
    img.src = objectUrl;
  });
}

function decodeQrFromImageElement(img: HTMLImageElement): string | null {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) return null;

  const maxDim = Math.max(img.naturalWidth, img.naturalHeight);
  const attempts: number[] =
    maxDim > 1400 ? [1200 / maxDim, 800 / maxDim, 1] : [1, 0.75, 1.5];

  for (const scale of attempts) {
    const width = Math.max(1, Math.round(img.naturalWidth * scale));
    const height = Math.max(1, Math.round(img.naturalHeight * scale));
    canvas.width = width;
    canvas.height = height;

    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(img, 0, 0, width, height);

    const imageData = ctx.getImageData(0, 0, width, height);
    const decoded = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth',
    });

    if (decoded && decoded.data.trim()) {
      return decoded.data.trim();
    }
  }

  return null;
}

export async function decodeQrImageFile(file: File): Promise<QrDecodeOutcome> {
  if (!file) {
    return { error: 'Please select a PNG or JPG image containing a QR code.' };
  }

  if (file.size === 0) {
    return { error: 'The selected file is empty. Please upload a valid PNG or JPG image.' };
  }

  if (file.size > MAX_QR_FILE_BYTES) {
    return {
      error: `Image is too large (${(file.size / (1024 * 1024)).toFixed(
        2
      )} MB). Maximum allowed file size is 5 MB.`,
    };
  }

  const actualFormat = await detectActualImageFormat(file);
  if (!actualFormat) {
    return {
      error:
        'Invalid image format. Only genuine PNG and JPG images are accepted (file header verification failed).',
    };
  }

  let img: HTMLImageElement;
  try {
    img = await loadImageFromFile(file);
  } catch (err) {
    return {
      error:
        err instanceof Error
          ? err.message
          : 'Could not read image data. Please upload a valid PNG or JPG file.',
    };
  }

  const extracted = decodeQrFromImageElement(img);
  if (!extracted) {
    return {
      error:
        'No readable QR code was detected in this image. Ensure the QR code is clear, well-lit, and uncropped.',
    };
  }

  if (isLikelyUrl(extracted)) {
    return {
      extractedText: extracted,
      isUrl: true,
      detectedFormat: actualFormat,
    };
  }

  return {
    extractedText: extracted,
    isUrl: false,
    detectedFormat: actualFormat,
    plainTextResult: {
      source: 'qr',
      contentType: 'text',
      extractedText: extracted,
      qrFileName: file.name,
      detectedFormat: actualFormat,
    },
  };
}

/**
 * Client-side QR Code Generation for Live Demos & Quishing Lab testing
 */
export async function generateQrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, {
    width: 320,
    margin: 2,
    color: {
      dark: '#0B0D11',
      light: '#FFFFFF',
    },
  });
}

export async function createQrFileFromDataUrl(dataUrl: string, filename = 'sample-quishing-qr.png'): Promise<File> {
  const res = await fetch(dataUrl);
  const blob = await res.blob();
  return new File([blob], filename, { type: 'image/png' });
}

export async function requestLiveUrlScan(
  url: string,
  source: 'url' | 'qr' = 'url',
  qrFileName?: string
): Promise<{ result?: LiveScanResult; error?: string }> {
  try {
    const response = await fetch('/api/scan-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, source, qrFileName }),
    });

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return {
        error:
          'Live scanner API (/api/scan-url) is not running. In VS Code, start the project with "npm run dev" and open http://localhost:3000.',
      };
    }

    const data = (await response.json()) as { result?: LiveScanResult; error?: string };
    if (!response.ok || data.error) {
      return { error: data.error || `Live scan failed (HTTP ${response.status}).` };
    }

    return { result: data.result };
  } catch {
    return {
      error:
        'Could not reach the live scanner backend. Make sure "npm run dev" is running in your terminal.',
    };
  }
}

export async function requestLookalikeGeneration(
  domain: string
): Promise<{ result?: LookalikeGenerationResult; error?: string }> {
  try {
    const response = await fetch('/api/generate-lookalikes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return {
        error:
          'Backend API (/api/generate-lookalikes) is not running. Start the server with "npm run dev".',
      };
    }

    const data = (await response.json()) as {
      result?: LookalikeGenerationResult;
      error?: string;
    };
    if (!response.ok || data.error) {
      return { error: data.error || `Generation failed (HTTP ${response.status}).` };
    }

    return { result: data.result };
  } catch {
    return {
      error:
        'Could not reach the backend server. Make sure "npm run dev" is running in your terminal.',
    };
  }
}
