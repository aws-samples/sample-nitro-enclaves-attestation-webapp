/**
 * HPKE (Hybrid Public Key Encryption) for Nitro Enclave Communication
 * 
 * This module implements RFC 9180 HPKE for secure bidirectional communication
 * with the enclave, using the public key from the verified attestation document.
 * 
 * Flow:
 * 1. Client verifies attestation document (COSE signature, certificate chain)
 * 2. Client extracts enclave's public key from verified attestation
 * 3. Client uses HPKE to encrypt request with enclave's public key
 * 4. Enclave decrypts request with its private key
 * 5. Enclave encrypts response using HPKE export mechanism
 * 6. Client decrypts response using same exported key
 * 
 * Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
 */

import { CipherSuite, Kem, Kdf, Aead } from 'hpke-js';

// HPKE info/context labels for domain separation
const INFO_REQUEST = new TextEncoder().encode('nitro-enclave-request');
const INFO_RESPONSE = new TextEncoder().encode('nitro-enclave-response');

/**
 * Convert ArrayBuffer to hex string
 */
function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to Uint8Array
 */
function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * HPKE Sender Context - created for each message
 * Stores the encapsulated key and context for potential response decryption
 */
class HpkeSenderSession {
  constructor(encapsulatedKey, senderContext, exportedResponseKey) {
    this.encapsulatedKey = encapsulatedKey;        // enc - sent to recipient
    this.senderContext = senderContext;             // For sealing additional messages
    this.exportedResponseKey = exportedResponseKey; // For decrypting response
  }
}

/**
 * Create HPKE cipher suite for P-256
 * Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
 */
function createCipherSuite() {
  return new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });
}

/**
 * Encrypt a message for the enclave using HPKE
 * 
 * @param {CryptoKey} enclavePublicKey - The enclave's public key from attestation document
 * @param {string} plaintext - Message to encrypt
 * @param {Uint8Array} aad - Additional authenticated data (optional)
 * @returns {Promise<{enc: string, ciphertext: string, exportedResponseKeyHex: string}>}
 */
export async function hpkeEncrypt(enclavePublicKey, plaintext, aad = new Uint8Array(0)) {
  const suite = createCipherSuite();
  
  // Export the public key to raw format (uncompressed point)
  let publicKeyBytes;
  if (enclavePublicKey instanceof CryptoKey) {
    publicKeyBytes = await crypto.subtle.exportKey('raw', enclavePublicKey);
  } else if (enclavePublicKey instanceof Uint8Array) {
    publicKeyBytes = enclavePublicKey;
  } else {
    throw new Error('Invalid public key format');
  }
  
  // Import the public key into HPKE format
  const recipientPublicKey = await suite.kem.importKey('raw', publicKeyBytes, true);
  
  // Create sender context with info for domain separation
  const sender = await suite.createSenderContext({
    recipientPublicKey,
    info: INFO_REQUEST,
  });
  
  // Encrypt the plaintext
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const ciphertext = await sender.seal(plaintextBytes, aad);
  
  // Export a key for response decryption (32 bytes for AES-256)
  // This allows the enclave to encrypt a response that only we can decrypt
  const exportedResponseKey = await sender.export(INFO_RESPONSE, 32);
  
  // Get the encapsulated key (sent to recipient)
  const enc = sender.enc;
  
  console.log('HPKE Encryption:', {
    enc_length: enc.byteLength,
    ciphertext_length: ciphertext.byteLength,
    exported_key_length: exportedResponseKey.byteLength,
  });
  
  return {
    // The encapsulated key - recipient needs this to derive the shared secret
    enc: arrayBufferToHex(enc),
    // The encrypted message
    ciphertext: arrayBufferToHex(ciphertext),
    // Exported key for response decryption (kept client-side)
    exportedResponseKeyHex: arrayBufferToHex(exportedResponseKey),
    // Store for later response decryption
    _session: new HpkeSenderSession(enc, sender, exportedResponseKey),
  };
}

/**
 * Decrypt a response from the enclave using the exported response key
 * 
 * @param {string} exportedResponseKeyHex - The exported key from hpkeEncrypt
 * @param {string} ivHex - The IV used for response encryption
 * @param {string} ciphertextHex - The encrypted response
 * @returns {Promise<string>} Decrypted plaintext
 */
export async function hpkeDecryptResponse(exportedResponseKeyHex, ivHex, ciphertextHex) {
  const responseKey = hexToUint8Array(exportedResponseKeyHex);
  const iv = hexToUint8Array(ivHex);
  const ciphertext = hexToUint8Array(ciphertextHex);
  
  // Import the response key as AES-GCM key
  const aesKey = await crypto.subtle.importKey(
    'raw',
    responseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Decrypt the response
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );
  
  return new TextDecoder().decode(plaintext);
}

/**
 * Full HPKE encryption flow for enclave communication
 * 
 * This is the main function to use for sending encrypted messages to the enclave.
 * The enclave's public key must come from a verified attestation document.
 * 
 * @param {CryptoKey} enclavePublicKey - From verified attestation document
 * @param {string} message - Plaintext message to send
 * @returns {Promise<{requestPayload: object, responseDecryptor: function}>}
 */
export async function createSecureRequest(enclavePublicKey, message) {
  // Encrypt the message using HPKE
  const encrypted = await hpkeEncrypt(enclavePublicKey, message);
  
  // Prepare the request payload for the enclave
  const requestPayload = {
    enc: encrypted.enc,           // Encapsulated key
    ciphertext: encrypted.ciphertext,  // Encrypted message
    hpke_suite: 'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM',
  };
  
  // Return a decryptor function for the response
  const responseDecryptor = async (ivHex, responseCiphertextHex) => {
    return hpkeDecryptResponse(encrypted.exportedResponseKeyHex, ivHex, responseCiphertextHex);
  };
  
  return {
    requestPayload,
    responseDecryptor,
    // For debugging
    _exportedResponseKey: encrypted.exportedResponseKeyHex,
  };
}

/**
 * Get HPKE parameters for display/documentation
 */
export function getHpkeInfo() {
  return {
    suite: 'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM',
    kem: 'DHKEM(P-256, HKDF-SHA256)',
    kdf: 'HKDF-SHA256',
    aead: 'AES-128-GCM',
    rfc: 'RFC 9180',
    description: 'Hybrid Public Key Encryption',
  };
}