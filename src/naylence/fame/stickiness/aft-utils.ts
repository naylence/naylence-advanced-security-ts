function toUint8Array(data: string | Uint8Array): Uint8Array {
  if (typeof data === "string") {
    if (typeof TextEncoder !== "undefined") {
      return new TextEncoder().encode(data);
    }

    if (typeof Buffer !== "undefined") {
      return Buffer.from(data, "utf-8");
    }

    const arr = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) {
      arr[i] = data.charCodeAt(i);
    }
    return arr;
  }

  return data;
}

export function base64UrlEncode(data: string | Uint8Array): string {
  const bytes = toUint8Array(data);

  let base64: string;
  if (typeof Buffer !== "undefined") {
    base64 = Buffer.from(bytes).toString("base64");
  } else {
    let binary = "";
    const length = bytes.length ?? 0;
    for (let i = 0; i < length; i += 1) {
      const charCode = bytes[i];
      if (charCode !== undefined) {
        binary += String.fromCharCode(charCode);
      }
    }

    if (typeof btoa === "function") {
      base64 = btoa(binary);
    } else if (
      typeof globalThis !== "undefined" &&
      "btoa" in globalThis &&
      typeof (globalThis as { btoa?: unknown }).btoa === "function"
    ) {
      base64 = (globalThis as { btoa: (str: string) => string }).btoa(binary);
    } else {
      throw new Error("No base64 encoder available in this environment");
    }
  }

  return base64.replace(/=+$/u, "").replace(/\+/gu, "-").replace(/\//gu, "_");
}

export function base64UrlDecode(data: string): Uint8Array {
  const normalized = data.replace(/-/gu, "+").replace(/_/gu, "/");
  const padding =
    normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const base64 = normalized + padding;

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }

  let binary: string;
  if (typeof atob === "function") {
    binary = atob(base64);
  } else if (
    typeof globalThis !== "undefined" &&
    "atob" in globalThis &&
    typeof (globalThis as { atob?: unknown }).atob === "function"
  ) {
    binary = (globalThis as { atob: (str: string) => string }).atob(base64);
  } else {
    throw new Error("No base64 decoder available in this environment");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    const charCode = binary.charCodeAt(i);
    if (charCode !== undefined) {
      bytes[i] = charCode;
    }
  }
  return bytes;
}

export function utf8Decode(data: Uint8Array): string {
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(data);
  }

  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("utf-8");
  }

  let str = "";
  for (let i = 0; i < data.length; i += 1) {
    const charCode = data[i];
    if (charCode !== undefined) {
      str += String.fromCharCode(charCode);
    }
  }
  return decodeURIComponent(escape(str));
}
