import { base64UrlToBytes, bytesToBase64Url } from "./base64url";

const PREFIX = "enc:v1:";
const IV_BYTES = 12;

function requireKeyMaterial(): string {
    const secret = process.env.JWKS_ENCRYPTION_KEY?.trim();
    if (!secret) {
        throw new Error("JWKS_ENCRYPTION_KEY is not set");
    }
    return secret;
}

async function aesKey(): Promise<CryptoKey> {
    // Derive a fixed 256-bit AES-GCM key from the configured secret.
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(requireKeyMaterial()),
    );
    return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
        "encrypt",
        "decrypt",
    ]);
}

export function isEncryptedPrivateKey(value: string): boolean {
    return value.startsWith(PREFIX);
}

/** AES-256-GCM at rest. Format: `enc:v1:` + base64url(iv || ciphertext). */
export async function encryptPrivateKey(plaintext: string): Promise<string> {
    const key = await aesKey();
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            new TextEncoder().encode(plaintext),
        ),
    );
    const payload = new Uint8Array(iv.length + ciphertext.length);
    payload.set(iv, 0);
    payload.set(ciphertext, iv.length);
    return PREFIX + bytesToBase64Url(payload);
}

/**
 * Decrypts a stored private key. Rows written before encryption was enabled
 * carry no prefix and are returned as-is (migration shim for local data).
 */
export async function decryptPrivateKey(stored: string): Promise<string> {
    if (!isEncryptedPrivateKey(stored)) {
        return stored;
    }
    const payload = base64UrlToBytes(stored.slice(PREFIX.length));
    if (payload.length <= IV_BYTES) {
        throw new Error("Encrypted JWKS private key is malformed");
    }
    const iv = payload.slice(0, IV_BYTES);
    const ciphertext = payload.slice(IV_BYTES);
    const key = await aesKey();
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new TextDecoder().decode(plaintext);
}
