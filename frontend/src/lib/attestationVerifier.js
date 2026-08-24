/**
 * Browser-side Nitro Enclave Attestation Verifier
 * 
 * This module verifies AWS Nitro Enclave attestation documents entirely in the browser
 * using WebCrypto APIs and CBOR parsing.
 */

import * as cbor from 'cbor-web';
import { parseX509Certificate } from './x509Parser';

// AWS Nitro Enclaves Root CA Certificate (PEM format)
// This is the public root CA that signs all Nitro Enclave attestation certificates
const AWS_NITRO_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

/**
 * Convert PEM to ArrayBuffer
 */
function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s/g, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert ArrayBuffer to hex string
 */
function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to ArrayBuffer
 */
function hexToArrayBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

/**
 * Parse X.509 certificate from DER format
 * Returns basic certificate info
 */
function parseCertificateBasicInfo(derBytes) {
  // This is a simplified parser - for full parsing we'd need asn1.js
  // For now, extract the public key and basic info
  return {
    raw: derBytes,
  };
}

/**
 * Parse COSE_Sign1 structure from attestation document
 * COSE_Sign1 = [protected, unprotected, payload, signature]
 */
function parseCoseSign1(coseBytes) {
  // COSE_Sign1 is tagged with 18 (0xD2 in CBOR)
  const decoded = cbor.decode(coseBytes);
  
  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error('Invalid COSE_Sign1 structure');
  }
  
  const [protectedHeader, unprotectedHeader, payload, signature] = decoded;
  
  // Decode protected header (CBOR encoded map)
  const protectedMap = cbor.decode(protectedHeader);
  
  // Decode payload (attestation document)
  const attestationDoc = cbor.decode(payload);
  
  return {
    protected: protectedHeader,
    protectedMap,
    unprotected: unprotectedHeader,
    payload,
    payloadDecoded: attestationDoc,
    signature,
  };
}

/**
 * Verify ECDSA signature using WebCrypto
 */
async function verifyEcdsaSignature(publicKeyDer, signature, signedData, algorithm) {
  try {
    // Import the public key
    const publicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyDer,
      {
        name: 'ECDSA',
        namedCurve: algorithm === -35 ? 'P-384' : 'P-256', // -35 = ES384, -7 = ES256
      },
      false,
      ['verify']
    );
    
    // COSE signature format is (r || s), need to convert for WebCrypto
    // WebCrypto expects IEEE P1363 format which is the same as COSE for EC signatures
    const hashAlgorithm = algorithm === -35 ? 'SHA-384' : 'SHA-256';
    
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: hashAlgorithm,
      },
      publicKey,
      signature,
      signedData
    );
    
    return isValid;
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Encode a CBOR byte string (bstr) with deterministic length encoding
 */
function encodeCborBstr(data) {
  const len = data.length;
  if (len < 24) {
    const result = new Uint8Array(1 + len);
    result[0] = 0x40 | len;
    result.set(data, 1);
    return result;
  } else if (len < 256) {
    const result = new Uint8Array(2 + len);
    result[0] = 0x58;
    result[1] = len;
    result.set(data, 2);
    return result;
  } else if (len < 65536) {
    const result = new Uint8Array(3 + len);
    result[0] = 0x59;
    result[1] = (len >> 8) & 0xff;
    result[2] = len & 0xff;
    result.set(data, 3);
    return result;
  } else {
    const result = new Uint8Array(5 + len);
    result[0] = 0x5a;
    result[1] = (len >> 24) & 0xff;
    result[2] = (len >> 16) & 0xff;
    result[3] = (len >> 8) & 0xff;
    result[4] = len & 0xff;
    result.set(data, 5);
    return result;
  }
}

/**
 * Build the Sig_structure for COSE_Sign1 verification
 * Sig_structure = ["Signature1", body_protected, external_aad, payload]
 * Per RFC 8152, using deterministic CBOR encoding to match NSM
 */
function buildSigStructure(protectedHeader, payload) {
  // Ensure inputs are Uint8Array
  const protectedBytes = protectedHeader instanceof Uint8Array 
    ? protectedHeader 
    : new Uint8Array(protectedHeader);
  const payloadBytes = payload instanceof Uint8Array 
    ? payload 
    : new Uint8Array(payload);
  
  // Manually build CBOR to ensure deterministic encoding
  // Array of 4 elements: 0x84
  // Text string "Signature1" (10 chars): 0x6a + ASCII bytes
  // bstr for protected header
  // bstr for external_aad (empty): 0x40
  // bstr for payload
  
  const signature1Text = new TextEncoder().encode('Signature1'); // 10 bytes
  const protectedEncoded = encodeCborBstr(protectedBytes);
  const externalAad = new Uint8Array([0x40]); // empty bstr
  const payloadEncoded = encodeCborBstr(payloadBytes);
  
  // Calculate total length
  const totalLen = 1 + 1 + 10 + protectedEncoded.length + 1 + payloadEncoded.length;
  const result = new Uint8Array(totalLen);
  
  let offset = 0;
  result[offset] = 0x84; offset += 1; // array of 4
  result[offset] = 0x6a; offset += 1; // text string of 10 chars
  result.set(signature1Text, offset);
  offset += 10;
  result.set(protectedEncoded, offset);
  offset += protectedEncoded.length;
  result.set(externalAad, offset);
  offset += 1;
  result.set(payloadEncoded, offset);
  
  console.log('Sig_structure (manual CBOR):', result.length, 'bytes, first 20:', 
    Array.from(result.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  
  return result;
}

/**
 * Parse DER length field (handles multi-byte lengths)
 * Returns {length, bytesRead}
 */
function parseDerLength(bytes, offset) {
  const firstByte = bytes[offset];
  if (firstByte < 128) {
    // Short form: length in single byte
    return { length: firstByte, bytesRead: 1 };
  } else {
    // Long form: first byte indicates number of length bytes
    const numLengthBytes = firstByte & 0x7f;
    let length = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      length = (length << 8) | bytes[offset + 1 + i];
    }
    return { length, bytesRead: 1 + numLengthBytes };
  }
}

/**
 * Extract SubjectPublicKeyInfo from X.509 certificate
 * X.509 structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 * tbsCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
 */
function extractSpkiFromCert(certBytes) {
  let offset = 0;
  
  // Parse outer SEQUENCE (Certificate)
  if (certBytes[offset] !== 0x30) throw new Error('Not a valid certificate');
  offset++;
  const { length: certLen, bytesRead: certLenBytes } = parseDerLength(certBytes, offset);
  offset += certLenBytes;
  
  // Parse tbsCertificate SEQUENCE
  if (certBytes[offset] !== 0x30) throw new Error('Invalid tbsCertificate');
  const tbsStart = offset;
  offset++;
  const { length: tbsLen, bytesRead: tbsLenBytes } = parseDerLength(certBytes, offset);
  offset += tbsLenBytes;
  
  // Skip version (optional, tagged [0])
  if (certBytes[offset] === 0xa0) {
    offset++;
    const { length: vLen, bytesRead: vLenBytes } = parseDerLength(certBytes, offset);
    offset += vLenBytes + vLen;
  }
  
  // Skip serialNumber (INTEGER)
  if (certBytes[offset] !== 0x02) throw new Error('Invalid serialNumber');
  offset++;
  const { length: snLen, bytesRead: snLenBytes } = parseDerLength(certBytes, offset);
  offset += snLenBytes + snLen;
  
  // Skip signature (AlgorithmIdentifier SEQUENCE)
  if (certBytes[offset] !== 0x30) throw new Error('Invalid signature algorithm');
  offset++;
  const { length: sigAlgLen, bytesRead: sigAlgLenBytes } = parseDerLength(certBytes, offset);
  offset += sigAlgLenBytes + sigAlgLen;
  
  // Skip issuer (Name SEQUENCE)
  if (certBytes[offset] !== 0x30) throw new Error('Invalid issuer');
  offset++;
  const { length: issuerLen, bytesRead: issuerLenBytes } = parseDerLength(certBytes, offset);
  offset += issuerLenBytes + issuerLen;
  
  // Skip validity (SEQUENCE)
  if (certBytes[offset] !== 0x30) throw new Error('Invalid validity');
  offset++;
  const { length: validityLen, bytesRead: validityLenBytes } = parseDerLength(certBytes, offset);
  offset += validityLenBytes + validityLen;
  
  // Skip subject (Name SEQUENCE)
  if (certBytes[offset] !== 0x30) throw new Error('Invalid subject');
  offset++;
  const { length: subjectLen, bytesRead: subjectLenBytes } = parseDerLength(certBytes, offset);
  offset += subjectLenBytes + subjectLen;
  
  // Now at SubjectPublicKeyInfo (SEQUENCE)
  if (certBytes[offset] !== 0x30) throw new Error('Invalid SubjectPublicKeyInfo');
  const spkiStart = offset;
  offset++;
  const { length: spkiLen, bytesRead: spkiLenBytes } = parseDerLength(certBytes, offset);
  const spkiTotalLen = 1 + spkiLenBytes + spkiLen;
  
  return certBytes.slice(spkiStart, spkiStart + spkiTotalLen);
}

/**
 * Extract public key from certificate chain
 */
async function extractPublicKeyFromCert(certDer) {
  try {
    // Convert to Uint8Array if needed
    const certBytes = certDer instanceof Uint8Array ? certDer : new Uint8Array(certDer);
    
    // Extract SPKI using proper ASN.1 parsing
    const spki = extractSpkiFromCert(certBytes);
    
    // Try to import as P-384 first (Nitro uses ES384)
    try {
      const key = await crypto.subtle.importKey(
        'spki',
        spki,
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['verify']
      );
      return { key, spki, curve: 'P-384' };
    } catch (e) {
      // Try P-256 as fallback
      const key = await crypto.subtle.importKey(
        'spki',
        spki,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );
      return { key, spki, curve: 'P-256' };
    }
  } catch (error) {
    console.error('Error extracting public key from certificate:', error);
    throw error;
  }
}

/**
 * Normalize a CBOR-decoded byte field (Uint8Array, ArrayBuffer, Buffer-like, or
 * array) into a Uint8Array.
 */
function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (value && value.buffer instanceof ArrayBuffer) {
    return new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);
  }
  if (Array.isArray(value)) return new Uint8Array(value);
  if (value && Array.isArray(value.data)) return new Uint8Array(value.data);
  throw new Error('Unsupported byte field type in attestation document');
}

/**
 * Constant-length byte comparison of two Uint8Arrays.
 */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Strip leading zero bytes from a DER INTEGER, then left-pad to `size` bytes.
 */
function normalizeInteger(bytes, size) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) start++;
  const trimmed = bytes.slice(start);
  if (trimmed.length > size) {
    throw new Error('ECDSA signature integer longer than field size');
  }
  const out = new Uint8Array(size);
  out.set(trimmed, size - trimmed.length);
  return out;
}

/**
 * Convert a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) into
 * the raw r||s (IEEE P1363) form that the Web Crypto API expects. `size` is the
 * field element size for the curve (48 for P-384, 32 for P-256).
 */
function derEcdsaSignatureToRaw(der, size) {
  let offset = 0;
  if (der[offset] !== 0x30) throw new Error('Invalid ECDSA signature: no SEQUENCE');
  offset++;
  const seqLen = parseDerLength(der, offset);
  offset += seqLen.bytesRead;

  if (der[offset] !== 0x02) throw new Error('Invalid ECDSA signature: r is not INTEGER');
  offset++;
  const rLen = parseDerLength(der, offset);
  offset += rLen.bytesRead;
  const r = der.slice(offset, offset + rLen.length);
  offset += rLen.length;

  if (der[offset] !== 0x02) throw new Error('Invalid ECDSA signature: s is not INTEGER');
  offset++;
  const sLen = parseDerLength(der, offset);
  offset += sLen.bytesRead;
  const s = der.slice(offset, offset + sLen.length);

  const raw = new Uint8Array(size * 2);
  raw.set(normalizeInteger(r, size), 0);
  raw.set(normalizeInteger(s, size), size);
  return raw;
}

/**
 * Extract the raw tbsCertificate bytes (the portion that is signed) from a DER
 * certificate: Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
 * signatureValue }.
 */
function extractTbsCertificate(certBytes) {
  let offset = 0;
  if (certBytes[offset] !== 0x30) throw new Error('Not a valid certificate');
  offset++;
  offset += parseDerLength(certBytes, offset).bytesRead;

  const tbsStart = offset;
  if (certBytes[offset] !== 0x30) throw new Error('Invalid tbsCertificate');
  offset++;
  const tbs = parseDerLength(certBytes, offset);
  offset += tbs.bytesRead;
  return certBytes.slice(tbsStart, offset + tbs.length);
}

/**
 * Extract the signatureValue from a DER certificate as raw r||s bytes.
 */
function extractCertSignatureRaw(certBytes, size) {
  let offset = 0;
  if (certBytes[offset] !== 0x30) throw new Error('Not a valid certificate');
  offset++;
  offset += parseDerLength(certBytes, offset).bytesRead;

  // Skip tbsCertificate
  if (certBytes[offset] !== 0x30) throw new Error('Invalid tbsCertificate');
  offset++;
  const tbs = parseDerLength(certBytes, offset);
  offset += tbs.bytesRead + tbs.length;

  // Skip signatureAlgorithm (SEQUENCE)
  if (certBytes[offset] !== 0x30) throw new Error('Invalid signatureAlgorithm');
  offset++;
  const sigAlg = parseDerLength(certBytes, offset);
  offset += sigAlg.bytesRead + sigAlg.length;

  // signatureValue (BIT STRING)
  if (certBytes[offset] !== 0x03) throw new Error('Invalid signatureValue');
  offset++;
  const bitStr = parseDerLength(certBytes, offset);
  offset += bitStr.bytesRead;
  // First content byte of a BIT STRING is the count of unused bits (0x00 here).
  const sigDer = certBytes.slice(offset + 1, offset + bitStr.length);
  return derEcdsaSignatureToRaw(sigDer, size);
}

/**
 * Verify that `subjectCertBytes` was signed by the key in `issuerCertBytes`.
 * Nitro certificates use ECDSA with SHA-384.
 */
async function verifyCertificateSignature(subjectCertBytes, issuerCertBytes) {
  const { key, curve } = await extractPublicKeyFromCert(issuerCertBytes);
  const size = curve === 'P-384' ? 48 : 32;
  const hash = curve === 'P-384' ? 'SHA-384' : 'SHA-256';
  const tbs = extractTbsCertificate(subjectCertBytes);
  const signature = extractCertSignatureRaw(subjectCertBytes, size);
  return crypto.subtle.verify({ name: 'ECDSA', hash }, key, signature, tbs);
}

/**
 * Validate the full certificate chain from the attestation document up to the
 * pinned AWS Nitro Enclaves root.
 *
 * The attestation document carries the CA bundle ordered root-first
 * (cabundle[0] is the root, the last entry is the issuer of the signing
 * certificate) and the leaf signing certificate separately. This function:
 *   1. anchors trust by requiring cabundle[0] to be byte-identical to the pinned
 *      AWS Nitro Enclaves root certificate embedded in the client,
 *   2. verifies each certificate's signature against its issuer's public key
 *      along the chain root -> intermediates -> leaf, and
 *   3. checks every certificate's validity window against the current time.
 *
 * @param {Uint8Array} leafCertBytes - The signing (leaf) certificate.
 * @param {Array} cabundle - CA certificates, ordered root-first.
 * @param {Date} now - Reference time for validity checks.
 * @returns {Promise<{chainLength: number}>}
 */
async function validateCertificateChain(leafCertBytes, cabundle, now) {
  if (!cabundle || cabundle.length === 0) {
    throw new Error('No certificate bundle found');
  }

  const bundle = cabundle.map(toUint8Array);
  const leaf = toUint8Array(leafCertBytes);
  const pinnedRoot = new Uint8Array(pemToArrayBuffer(AWS_NITRO_ROOT_CA_PEM));

  // 1. Anchor to the pinned root. Trusting the bundle's own root without this
  //    check would let a forged bundle define its own trust anchor. The AWS Nitro
  //    cabundle is ordered root-first, but accept root-last as well so the check
  //    does not depend on that ordering.
  let orderedBundle;
  if (bytesEqual(bundle[0], pinnedRoot)) {
    orderedBundle = bundle;
  } else if (bytesEqual(bundle[bundle.length - 1], pinnedRoot)) {
    orderedBundle = [...bundle].reverse();
  } else {
    throw new Error('CA bundle root does not match the pinned AWS Nitro Enclaves root certificate');
  }

  // 2/3. Walk root -> intermediates -> leaf, verifying signatures and validity.
  const chain = [...orderedBundle, leaf];
  for (let i = 0; i < chain.length; i++) {
    const parsed = parseX509Certificate(chain[i]);
    if (parsed.error) {
      throw new Error(`Certificate ${i} could not be parsed: ${parsed.error}`);
    }
    const { notBefore, notAfter } = parsed.validity;
    if (!notBefore || !notAfter || now < notBefore || now > notAfter) {
      throw new Error(`Certificate ${i} is outside its validity window`);
    }
    if (i > 0) {
      const signedByIssuer = await verifyCertificateSignature(chain[i], chain[i - 1]);
      if (!signedByIssuer) {
        throw new Error(`Certificate ${i} signature does not verify against issuer ${i - 1}`);
      }
    }
  }

  return { chainLength: chain.length };
}

/**
 * Main function to verify attestation document
 */
/**
 * Decode a CBOR byte-string field (nonce / user_data) to a UTF-8 string for
 * display and comparison. Returns null if absent, or a hex string if the bytes
 * are not valid UTF-8 text.
 */
function decodeCborText(field) {
  if (field === null || field === undefined) return null;
  let bytes;
  if (field instanceof Uint8Array) bytes = field;
  else if (field instanceof ArrayBuffer) bytes = new Uint8Array(field);
  else if (field && field.buffer instanceof ArrayBuffer) bytes = new Uint8Array(field.buffer, field.byteOffset || 0, field.byteLength);
  else if (Array.isArray(field)) bytes = new Uint8Array(field);
  else return String(field);
  if (bytes.length === 0) return '';
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return arrayBufferToHex(bytes);
  }
}

export async function verifyAttestationDocument(attestationDocBase64, expectedNonce = null, expectedUserData = null) {
  const steps = [];
  
  try {
    // Step 1: Decode base64
    steps.push({ step: 'Decode Base64', status: 'pending', details: 'Decoding attestation document from base64' });
    const attestationBytes = Uint8Array.from(atob(attestationDocBase64), c => c.charCodeAt(0));
    steps[steps.length - 1] = { step: 'Decode Base64', status: 'success', details: `Decoded ${attestationBytes.length} bytes` };
    
    // Step 2: Parse COSE_Sign1 structure
    steps.push({ step: 'Parse COSE_Sign1', status: 'pending', details: 'Parsing CBOR/COSE structure' });
    const coseData = parseCoseSign1(attestationBytes);
    steps[steps.length - 1] = { step: 'Parse COSE_Sign1', status: 'success', details: 'Successfully parsed COSE_Sign1 structure' };
    
    // Step 3: Extract attestation data
    steps.push({ step: 'Extract Attestation Data', status: 'pending', details: 'Extracting attestation document fields' });
    const attestationData = {
      moduleId: coseData.payloadDecoded.module_id,
      digest: coseData.payloadDecoded.digest,
      timestamp: coseData.payloadDecoded.timestamp,
      pcrs: {},
      publicKey: coseData.payloadDecoded.public_key,
      userData: coseData.payloadDecoded.user_data,
      nonce: coseData.payloadDecoded.nonce,
      certificate: coseData.payloadDecoded.certificate,  // The signing certificate
      cabundle: coseData.payloadDecoded.cabundle,        // The CA chain
    };

    // Decode the signed nonce and user_data (CBOR byte strings) to text so the UI
    // can show the values that the enclave echoed back inside the signed document.
    attestationData.nonceText = decodeCborText(attestationData.nonce);
    attestationData.userDataText = decodeCborText(attestationData.userData);

    // Convert PCRs to hex strings
    // Note: CBOR Map objects need special handling
    const pcrsData = coseData.payloadDecoded.pcrs;
    if (pcrsData) {
      // Handle both Map and plain object
      const entries = pcrsData instanceof Map ? pcrsData.entries() : Object.entries(pcrsData);
      for (const [key, value] of entries) {
        let hexValue = '';
        if (value instanceof Uint8Array) {
          hexValue = arrayBufferToHex(value);
        } else if (value instanceof ArrayBuffer) {
          hexValue = arrayBufferToHex(value);
        } else if (value && value.buffer instanceof ArrayBuffer) {
          hexValue = arrayBufferToHex(value.buffer);
        } else if (ArrayBuffer.isView(value)) {
          hexValue = arrayBufferToHex(value.buffer);
        } else if (typeof value === 'string') {
          hexValue = value;
        } else {
          hexValue = value?.toString() || '';
        }
        attestationData.pcrs[key.toString()] = hexValue;
      }
    }
    
    steps[steps.length - 1] = { 
      step: 'Extract Attestation Data', 
      status: 'success', 
      details: `Module ID: ${attestationData.moduleId}, Timestamp: ${new Date(attestationData.timestamp).toISOString()}`
    };
    
    // Step 4: Check for debug mode (PCR0, PCR1, PCR2 all zeros = debug mode)
    steps.push({ step: 'Check Debug Mode', status: 'pending', details: 'Checking PCR0, PCR1, PCR2 values for debug mode indicators' });
    const debugPcrs = ['0', '1', '2'];
    const isDebugMode = debugPcrs.every(pcr => {
      const value = attestationData.pcrs[pcr] || '';
      return value.length > 0 && /^0+$/.test(value);
    });
    
    if (isDebugMode) {
      steps[steps.length - 1] = { 
        step: 'Check Debug Mode', 
        status: 'warning', 
        details: '⚠️ ENCLAVE IS RUNNING IN DEBUG MODE — PCR0, PCR1, PCR2 are all zeros. Attestation is NOT trustworthy in production.' 
      };
    } else {
      steps[steps.length - 1] = { 
        step: 'Check Debug Mode', 
        status: 'success', 
        details: 'Enclave is running in production mode (PCR values are non-zero)' 
      };
    }
    
    // Step 5: Verify nonce if provided (freshness / replay protection)
    if (expectedNonce) {
      steps.push({ step: 'Verify Nonce', status: 'pending', details: 'Checking nonce matches expected value' });

      const docNonce = attestationData.nonceText;

      if (docNonce === expectedNonce) {
        steps[steps.length - 1] = { step: 'Verify Nonce', status: 'success', details: `Match — signed nonce equals the input: "${expectedNonce}"` };
      } else {
        steps[steps.length - 1] = { step: 'Verify Nonce', status: 'failed', details: `No match — expected "${expectedNonce}", document has "${docNonce}"` };
        return { verified: false, error: 'Nonce mismatch', verificationSteps: steps, attestationData };
      }
    }

    // Step 5b: Verify user_data echo if provided. Unlike the nonce, a mismatch here
    // does not abort verification (user_data is application-defined); it is reported
    // as a match / no-match indicator.
    if (expectedUserData) {
      steps.push({ step: 'Verify User Data', status: 'pending', details: 'Checking user data matches the input' });
      const docUserData = attestationData.userDataText;
      if (docUserData === expectedUserData) {
        steps[steps.length - 1] = { step: 'Verify User Data', status: 'success', details: `Match — signed user data equals the input: "${expectedUserData}"` };
      } else {
        steps[steps.length - 1] = { step: 'Verify User Data', status: 'failed', details: `No match — input "${expectedUserData}", document has "${docUserData ?? '(none)'}"` };
      }
    }

    // Step 5: Validate certificate chain to the pinned AWS Nitro Enclaves root.
    steps.push({ step: 'Validate Certificate Chain', status: 'pending', details: 'Validating certificate chain against the pinned AWS Nitro Enclaves root CA' });

    if (!attestationData.cabundle || attestationData.cabundle.length === 0) {
      steps[steps.length - 1] = { step: 'Validate Certificate Chain', status: 'failed', details: 'No certificate bundle found' };
      return { verified: false, error: 'No certificate bundle', verificationSteps: steps };
    }

    // The signing certificate is in the 'certificate' field, NOT in cabundle.
    // cabundle contains the CA chain (root first, through the intermediates).
    if (!attestationData.certificate) {
      steps[steps.length - 1] = { step: 'Validate Certificate Chain', status: 'failed', details: 'No signing certificate found in attestation document' };
      return { verified: false, error: 'No signing certificate', verificationSteps: steps };
    }

    const signingCert = attestationData.certificate;  // The certificate that signed the attestation
    try {
      const chainInfo = await validateCertificateChain(signingCert, attestationData.cabundle, new Date());
      steps[steps.length - 1] = {
        step: 'Validate Certificate Chain',
        status: 'success',
        details: `Chain of ${chainInfo.chainLength} certificates verified to the pinned AWS Nitro Enclaves root; all within their validity windows`,
      };
    } catch (chainError) {
      console.error('Certificate chain validation failed:', chainError);
      steps[steps.length - 1] = {
        step: 'Validate Certificate Chain',
        status: 'failed',
        details: `Certificate chain validation failed: ${chainError.message}`,
      };
      return { verified: false, error: `Certificate chain validation failed: ${chainError.message}`, verificationSteps: steps };
    }
    
    // Step 6: Verify COSE signature - MANDATORY for attestation to be valid
    steps.push({ step: 'Verify COSE Signature', status: 'pending', details: 'Verifying COSE_Sign1 signature (ECDSA P-384)' });
    
    // Build the Sig_structure
    const sigStructure = buildSigStructure(coseData.protected, coseData.payload);
    
    // Get the algorithm from protected header (should be ES384 = -35 for Nitro)
    const algorithm = coseData.protectedMap.get(1); // 1 = alg
    console.log('COSE algorithm:', algorithm, '(expected -35 for ES384)');
    
    // Extract public key from signing certificate (not cabundle)
    let signatureValid = false;
    try {
      // Convert certificate to Uint8Array if needed
      let certBytes;
      if (signingCert instanceof Uint8Array) {
        certBytes = signingCert;
      } else if (signingCert instanceof ArrayBuffer) {
        certBytes = new Uint8Array(signingCert);
      } else if (signingCert && signingCert.buffer instanceof ArrayBuffer) {
        certBytes = new Uint8Array(signingCert.buffer, signingCert.byteOffset, signingCert.byteLength);
      } else {
        throw new Error(`Unexpected certificate type: ${typeof signingCert}`);
      }
      
      console.log('Signing certificate:', certBytes.length, 'bytes, first bytes:', 
        Array.from(certBytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join(' '));
      
      const { spki } = await extractPublicKeyFromCert(certBytes);
      
      console.log('SPKI extracted:', spki.length, 'bytes');
      console.log('Signature:', coseData.signature.length, 'bytes');
      console.log('Sig structure:', sigStructure.length, 'bytes');
      
      signatureValid = await verifyEcdsaSignature(
        spki,
        coseData.signature,
        sigStructure,
        algorithm
      );
      
      if (signatureValid) {
        steps[steps.length - 1] = { step: 'Verify COSE Signature', status: 'success', details: 'ECDSA P-384 signature verified successfully' };
      } else {
        steps[steps.length - 1] = { step: 'Verify COSE Signature', status: 'failed', details: 'Signature verification failed - document may be tampered' };
        return { verified: false, error: 'COSE signature verification failed', verificationSteps: steps };
      }
    } catch (sigError) {
      console.error('Signature verification error:', sigError);
      steps[steps.length - 1] = { step: 'Verify COSE Signature', status: 'failed', details: 'Signature verification error: ' + sigError.message };
      return { verified: false, error: 'Signature verification failed: ' + sigError.message, verificationSteps: steps };
    }
    
    // Step 7: Extract enclave public key (if present in attestation document)
    let extractedPublicKey = null;
    if (attestationData.publicKey) {
      steps.push({ step: 'Extract Enclave Public Key', status: 'pending', details: 'Extracting public key from attestation document' });
      
      try {
        // Convert CBOR buffer to Uint8Array - handle various buffer types
        let pubKeyBytes;
        if (attestationData.publicKey instanceof Uint8Array) {
          pubKeyBytes = attestationData.publicKey;
        } else if (attestationData.publicKey instanceof ArrayBuffer) {
          pubKeyBytes = new Uint8Array(attestationData.publicKey);
        } else if (attestationData.publicKey.buffer instanceof ArrayBuffer) {
          // TypedArray view
          pubKeyBytes = new Uint8Array(attestationData.publicKey.buffer);
        } else if (Array.isArray(attestationData.publicKey)) {
          pubKeyBytes = new Uint8Array(attestationData.publicKey);
        } else if (typeof attestationData.publicKey === 'object' && attestationData.publicKey.data) {
          // CBOR Buffer type
          pubKeyBytes = new Uint8Array(attestationData.publicKey.data);
        } else {
          // Last resort - try to iterate
          pubKeyBytes = new Uint8Array(Object.values(attestationData.publicKey));
        }
        
        console.log('Public key from attestation doc:', pubKeyBytes.length, 'bytes, starts with:', pubKeyBytes[0]?.toString(16));
        
        // Validate it looks like an uncompressed EC point (starts with 0x04 for P-256)
        if (pubKeyBytes.length !== 65 || pubKeyBytes[0] !== 0x04) {
          throw new Error(`Invalid EC public key format: ${pubKeyBytes.length} bytes, first byte: 0x${pubKeyBytes[0]?.toString(16)}`);
        }
        
        // Import as raw EC public key for ECDH
        extractedPublicKey = await crypto.subtle.importKey(
          'raw',
          pubKeyBytes,
          { name: 'ECDH', namedCurve: 'P-256' },
          true,
          []
        );
        
        steps[steps.length - 1] = { 
          step: 'Extract Enclave Public Key', 
          status: 'success', 
          details: `Successfully extracted P-256 public key (65 bytes) from attestation document` 
        };
      } catch (keyError) {
        console.error('Could not extract public key from attestation document:', keyError);
        steps[steps.length - 1] = { 
          step: 'Extract Enclave Public Key', 
          status: 'failed', 
          details: 'Public key extraction failed: ' + keyError.message 
        };
        // Do NOT fall back to any other source - only attestation doc is trusted
      }
    } else {
      steps.push({ 
        step: 'Extract Enclave Public Key', 
        status: 'failed', 
        details: 'No public key found in attestation document. Enclave did not embed a public key for secure communication.' 
      });
    }
    
    return {
      verified: true,
      verificationSteps: steps,
      attestationData,
      publicKey: extractedPublicKey,
    };
    
  } catch (error) {
    console.error('Verification error:', error);
    steps.push({ step: 'Error', status: 'failed', details: error.message });
    return {
      verified: false,
      error: error.message,
      verificationSteps: steps,
    };
  }
}
