/**
 * Lightweight X.509 DER Certificate Parser
 * Parses DER-encoded certificates and extracts human-readable fields.
 * No external dependencies.
 */

// Well-known OIDs
const OID_NAMES = {
  '2.5.4.3': 'CN',     // Common Name
  '2.5.4.6': 'C',      // Country
  '2.5.4.7': 'L',      // Locality
  '2.5.4.8': 'ST',     // State
  '2.5.4.10': 'O',     // Organization
  '2.5.4.11': 'OU',    // Organizational Unit
  '2.5.4.5': 'serialNumber',
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.5': 'SHA1withRSA',
  '1.2.840.113549.1.1.11': 'SHA256withRSA',
  '1.2.840.113549.1.1.12': 'SHA384withRSA',
  '1.2.840.113549.1.1.13': 'SHA512withRSA',
  '1.2.840.10045.2.1': 'EC',
  '1.2.840.10045.3.1.7': 'P-256 (secp256r1)',
  '1.3.132.0.34': 'P-384 (secp384r1)',
  '1.2.840.10045.4.3.2': 'ECDSA-SHA256',
  '1.2.840.10045.4.3.3': 'ECDSA-SHA384',
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.15': 'Key Usage',
  '2.5.29.17': 'Subject Alt Name',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.37': 'Extended Key Usage',
  '2.5.29.31': 'CRL Distribution Points',
  '1.3.6.1.5.5.7.1.1': 'Authority Info Access',
};

const SIG_ALG_NAMES = {
  '1.2.840.113549.1.1.5': 'SHA-1 with RSA Encryption',
  '1.2.840.113549.1.1.11': 'SHA-256 with RSA Encryption',
  '1.2.840.113549.1.1.12': 'SHA-384 with RSA Encryption',
  '1.2.840.113549.1.1.13': 'SHA-512 with RSA Encryption',
  '1.2.840.10045.4.3.2': 'ECDSA with SHA-256',
  '1.2.840.10045.4.3.3': 'ECDSA with SHA-384',
};

class DERParser {
  constructor(bytes) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.pos = 0;
  }

  peek() {
    return this.bytes[this.pos];
  }

  readByte() {
    return this.bytes[this.pos++];
  }

  readTag() {
    return this.readByte();
  }

  readLength() {
    let len = this.readByte();
    if (len < 0x80) return len;
    const numBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < numBytes; i++) {
      len = (len << 8) | this.readByte();
    }
    return len;
  }

  readTLV() {
    const tag = this.readTag();
    const length = this.readLength();
    const value = this.bytes.slice(this.pos, this.pos + length);
    this.pos += length;
    return { tag, length, value };
  }

  readSequence() {
    const { tag, value } = this.readTLV();
    // Accept both SEQUENCE (0x30) and SET (0x31) as constructed types
    if (tag !== 0x30 && tag !== 0x31 && (tag & 0x20) === 0) {
      throw new Error(`Expected SEQUENCE/SET, got tag 0x${tag.toString(16)}`);
    }
    return new DERParser(value);
  }

  readOID() {
    const { tag, value } = this.readTLV();
    if (tag !== 0x06) return null;
    return decodeOID(value);
  }

  remaining() {
    return this.pos < this.bytes.length;
  }

  skip() {
    this.readTLV();
  }
}

function decodeOID(bytes) {
  const parts = [];
  parts.push(Math.floor(bytes[0] / 40));
  parts.push(bytes[0] % 40);
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function decodeUTF8String(bytes) {
  try {
    return new TextDecoder('utf-8').decode(bytes);
  } catch {
    return Array.from(bytes, b => String.fromCharCode(b)).join('');
  }
}

function parseName(parser) {
  // Name is a SEQUENCE of RDNs (each RDN is a SET of AttributeTypeAndValue)
  const parts = [];
  while (parser.remaining()) {
    // Each RDN is a SET containing one or more AttributeTypeAndValue SEQUENCEs
    const setParser = parser.readSequence(); // Reads SET (0x31) - now accepted by readSequence
    try {
      // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
      const attrSeqParser = setParser.readSequence(); // Inner SEQUENCE
      const oid = attrSeqParser.readOID();
      const valueTlv = attrSeqParser.readTLV();
      const name = OID_NAMES[oid] || oid;
      const val = decodeUTF8String(valueTlv.value);
      parts.push(`${name}=${val}`);
    } catch {
      // Skip unparseable RDN
    }
  }
  return parts.join(', ') || 'Unknown';
}

function parseValidity(parser) {
  const notBeforeTlv = parser.readTLV();
  const notAfterTlv = parser.readTLV();
  return {
    notBefore: parseTime(notBeforeTlv),
    notAfter: parseTime(notAfterTlv),
  };
}

function parseTime(tlv) {
  const str = decodeUTF8String(tlv.value);
  // UTCTime (tag 0x17): YYMMDDHHMMSSZ
  // GeneralizedTime (tag 0x18): YYYYMMDDHHMMSSZ
  if (tlv.tag === 0x17) {
    // UTCTime
    const year = parseInt(str.substring(0, 2));
    const fullYear = year >= 50 ? 1900 + year : 2000 + year;
    return new Date(`${fullYear}-${str.substring(2, 4)}-${str.substring(4, 6)}T${str.substring(6, 8)}:${str.substring(8, 10)}:${str.substring(10, 12)}Z`);
  } else {
    // GeneralizedTime
    return new Date(`${str.substring(0, 4)}-${str.substring(4, 6)}-${str.substring(6, 8)}T${str.substring(8, 10)}:${str.substring(10, 12)}:${str.substring(12, 14)}Z`);
  }
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(':');
}

function parseAlgorithmIdentifier(parser) {
  const oid = parser.readOID();
  // May have parameters (NULL or curve OID)
  let params = null;
  if (parser.remaining()) {
    const paramTlv = parser.readTLV();
    if (paramTlv.tag === 0x06) {
      params = decodeOID(paramTlv.value);
    }
  }
  return { oid, name: SIG_ALG_NAMES[oid] || OID_NAMES[oid] || oid, params: params ? (OID_NAMES[params] || params) : null };
}

/**
 * Parse a DER-encoded X.509 certificate
 * @param {Uint8Array} derBytes - Raw DER certificate bytes
 * @returns {object} Parsed certificate details
 */
export function parseX509Certificate(derBytes) {
  try {
    if (!derBytes || derBytes.length === 0) {
      return { error: 'Empty certificate' };
    }

    const bytes = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
    const certParser = new DERParser(bytes);
    
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    const certSeq = certParser.readSequence();
    
    // TBSCertificate ::= SEQUENCE { ... }
    const tbsSeq = certSeq.readSequence();
    
    const result = {
      version: 'v1',
      serialNumber: '',
      signatureAlgorithm: '',
      issuer: '',
      validity: { notBefore: null, notAfter: null },
      subject: '',
      publicKeyAlgorithm: '',
      publicKeySize: 0,
      extensions: [],
    };

    // Version (explicit tag [0])
    if ((tbsSeq.peek() & 0xf0) === 0xa0) {
      const versionTlv = tbsSeq.readTLV();
      const versionParser = new DERParser(versionTlv.value);
      const vTlv = versionParser.readTLV();
      const version = vTlv.value[0];
      result.version = `v${version + 1}`;
    }

    // Serial Number (INTEGER)
    const serialTlv = tbsSeq.readTLV();
    result.serialNumber = bytesToHex(serialTlv.value);

    // Signature Algorithm
    const sigAlgSeq = tbsSeq.readSequence();
    const sigAlg = parseAlgorithmIdentifier(sigAlgSeq);
    result.signatureAlgorithm = sigAlg.name + (sigAlg.params ? ` (${sigAlg.params})` : '');

    // Issuer (SEQUENCE of RDNs)
    const issuerTlv = tbsSeq.readTLV();
    const issuerParser = new DERParser(issuerTlv.value);
    result.issuer = parseName(issuerParser);

    // Validity
    const validitySeq = tbsSeq.readSequence();
    result.validity = parseValidity(validitySeq);

    // Subject
    const subjectTlv = tbsSeq.readTLV();
    const subjectParser = new DERParser(subjectTlv.value);
    result.subject = parseName(subjectParser);

    // SubjectPublicKeyInfo
    const spkiSeq = tbsSeq.readSequence();
    const pubKeyAlgSeq = spkiSeq.readSequence();
    const pubKeyAlg = parseAlgorithmIdentifier(pubKeyAlgSeq);
    result.publicKeyAlgorithm = pubKeyAlg.name + (pubKeyAlg.params ? ` (${pubKeyAlg.params})` : '');
    
    // Public key bit string
    const pubKeyBitString = spkiSeq.readTLV();
    // Subtract 1 for the unused-bits byte
    const keyBits = (pubKeyBitString.value.length - 1) * 8;
    result.publicKeySize = keyBits;

    // Extensions (if v3 - explicit tag [3])
    if (tbsSeq.remaining() && (tbsSeq.peek() & 0xf0) === 0xa0) {
      const extOuterTlv = tbsSeq.readTLV();
      try {
        const extOuterParser = new DERParser(extOuterTlv.value);
        const extSeqTlv = extOuterParser.readTLV(); // SEQUENCE of extensions
        const extSeqParser = new DERParser(extSeqTlv.value);
        
        while (extSeqParser.remaining()) {
          try {
            const extItemSeq = extSeqParser.readSequence();
            const extOid = extItemSeq.readOID();
            let critical = false;
            if (extItemSeq.remaining() && extItemSeq.peek() === 0x01) {
              const critTlv = extItemSeq.readTLV();
              critical = critTlv.value[0] !== 0;
            }
            const extName = OID_NAMES[extOid] || extOid;
            result.extensions.push({ name: extName, oid: extOid, critical });
          } catch {
            break;
          }
        }
      } catch {
        // Extensions parsing failed, that's ok
      }
    }

    // Outer signature algorithm
    const outerSigAlgSeq = certSeq.readSequence();
    const outerSigAlg = parseAlgorithmIdentifier(outerSigAlgSeq);
    result.signatureAlgorithm = outerSigAlg.name + (outerSigAlg.params ? ` (${outerSigAlg.params})` : '');

    return result;
  } catch (err) {
    return { error: `Failed to parse certificate: ${err.message}` };
  }
}
