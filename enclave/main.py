"""
Nitro Enclave Attestation API with HPKE
======================================

This enclave generates attestation documents and supports HPKE (RFC 9180)
encrypted communication. The enclave's public key is embedded in the
attestation document, allowing clients to verify the key's authenticity
through the attestation signature chain.

HPKE Flow:
1. Enclave generates P-256 key pair at startup
2. Public key is included in attestation documents
3. Clients verify attestation → extract public key
4. Clients use HPKE to encrypt messages with enclave's public key
5. Enclave decrypts using its private key
6. Enclave encrypts response using HPKE exported key
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import logging
import base64
import sys
import os
import secrets

# Add the shared directory to path
sys.path.append('/app/shared')

from nsm_client import NSMClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# HPKE imports
from pyhpke import AEADId, KDFId, KEMId, KEMKey, CipherSuite

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Nitro Enclaves Attestation API (Enclave)", version="3.0.0")

# CORS — the browser calls API Gateway cross-origin (Amplify origin), and these
# headers now originate here in the enclave (there is no parent backend to set them).
# They pass through the vsock proxy and API Gateway back to the browser.
app.add_middleware(  # nosemgrep: wildcard-cors
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_origin_regex=r"https://.*\.amplifyapp\.com",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HPKE Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
# This must match the frontend's suite
HPKE_KEM = KEMId.DHKEM_P256_HKDF_SHA256
HPKE_KDF = KDFId.HKDF_SHA256
HPKE_AEAD = AEADId.AES128_GCM

# HPKE info labels for domain separation (must match frontend)
INFO_REQUEST = b'nitro-enclave-request'
INFO_RESPONSE = b'nitro-enclave-response'

# Global key pair - generated once at startup and kept in memory
# Private key never leaves the enclave
_enclave_public_key_bytes = None
_hpke_suite = None
_hpke_private_key = None

def initialize_key_pair():
    """Generate the HPKE P-256 key pair at enclave startup"""
    global _enclave_public_key_bytes, _hpke_suite, _hpke_private_key

    if _hpke_private_key is None:
        logger.info("Generating HPKE P-256 key pair...")

        # Create HPKE cipher suite
        _hpke_suite = CipherSuite.new(HPKE_KEM, HPKE_KDF, HPKE_AEAD)

        # Generate HPKE key pair
        key_pair = _hpke_suite.kem.derive_key_pair(
            secrets.token_bytes(32)  # Random seed
        )
        _hpke_private_key = key_pair.private_key

        # Export public key in raw format (uncompressed point: 0x04 || x || y)
        _enclave_public_key_bytes = key_pair.public_key.to_public_bytes()

        logger.info(f"HPKE key pair generated. Public key length: {len(_enclave_public_key_bytes)} bytes")
        logger.info(f"HPKE Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM")

# Initialize key pair on module load
initialize_key_pair()

class AttestationRequest(BaseModel):
    nonce: Optional[str] = None
    user_data: Optional[str] = None

class HPKEDecryptRequest(BaseModel):
    """HPKE encrypted request format"""
    enc: str           # Hex-encoded encapsulated key
    ciphertext: str    # Hex-encoded ciphertext
    hpke_suite: Optional[str] = None  # Suite identifier (for validation)

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_str)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "attestation-api-enclave", 
        "environment": "enclave",
        "has_key_pair": _hpke_private_key is not None,
        "hpke_enabled": True,
        "hpke_suite": "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM"
    }

@app.post("/api/attestation")
async def get_attestation_document(request: AttestationRequest):
    """
    Get NSM attestation document with embedded HPKE public key.
    
    The public key in the attestation document is cryptographically bound
    to the enclave's identity through the NSM signature. Clients should:
    1. Verify the attestation signature chain to AWS root CA
    2. Extract the public key from the verified document
    3. Use HPKE with that public key to encrypt messages
    """
    global _enclave_public_key_bytes
    
    nsm_client = NSMClient()
    
    if not nsm_client.is_available():
        raise HTTPException(status_code=503, detail="NSM device not available")
    
    if _enclave_public_key_bytes is None:
        initialize_key_pair()
    
    try:
        nonce_bytes = request.nonce.encode() if request.nonce else None
        user_data_bytes = request.user_data.encode() if request.user_data else None
        
        # Include HPKE public key in attestation document
        # This cryptographically binds the key to the enclave's identity
        doc_bytes = nsm_client.get_attestation_document(
            nonce=nonce_bytes,
            user_data=user_data_bytes,
            public_key=_enclave_public_key_bytes
        )
        
        return {
            "status": "success",
            "attestation_document": base64.b64encode(doc_bytes).decode(),
            "size_bytes": len(doc_bytes),
            "environment": "enclave",
            "public_key_included": True,
            "public_key_hex": _enclave_public_key_bytes.hex(),
            "hpke_suite": "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM"
        }
    except Exception as e:
        logger.warning(f"Failed to get attestation document: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/decrypt/hpke")
async def decrypt_hpke_message(request: HPKEDecryptRequest):
    """
    Decrypt a message encrypted with HPKE using the enclave's private key.
    
    HPKE Flow:
    1. Client encrypts message with HPKE using enclave's public key from attestation
    2. Client sends 'enc' (encapsulated key) and 'ciphertext'
    3. Enclave creates recipient context with 'enc' and its private key
    4. Enclave decrypts ciphertext
    5. Enclave exports a response key and encrypts the response
    6. Client decrypts response using the same exported key
    
    Returns:
    - decrypted_message: The decrypted plaintext
    - response_iv: IV for the encrypted response
    - encrypted_response: The response encrypted with HPKE exported key
    """
    global _hpke_suite, _hpke_private_key
    
    if _hpke_private_key is None:
        raise HTTPException(status_code=503, detail="HPKE key pair not initialized")
    
    try:
        # Decode inputs from hex
        enc = hex_to_bytes(request.enc)
        ciphertext = hex_to_bytes(request.ciphertext)
        
        logger.info(f"HPKE Decrypting: enc={len(enc)} bytes, ciphertext={len(ciphertext)} bytes")
        
        # Create HPKE recipient context
        recipient = _hpke_suite.create_recipient_context(
            enc,
            _hpke_private_key,
            info=INFO_REQUEST
        )
        
        # Decrypt the message
        plaintext_bytes = recipient.open(ciphertext)
        plaintext = plaintext_bytes.decode('utf-8')
        
        logger.info(f"HPKE decrypted message: {len(plaintext)} characters")
        
        # Export a key for response encryption (must match what client exported)
        response_key = recipient.export(INFO_RESPONSE, 32)
        
        # Encrypt the response using the exported key
        response_iv = secrets.token_bytes(12)
        response_plaintext = f"Echo from enclave (HPKE): {plaintext}"
        
        aesgcm = AESGCM(response_key)
        encrypted_response = aesgcm.encrypt(response_iv, response_plaintext.encode(), None)
        
        return {
            "status": "success",
            # Only return encrypted response - plaintext never leaves enclave!
            "response_iv": response_iv.hex(),
            "encrypted_response": encrypted_response.hex(),
            "message_length": len(plaintext),  # Metadata only
            "hpke_suite": "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM"
        }
        
    except Exception as e:
        logger.warning(f"HPKE Decryption failed: {e}")
        raise HTTPException(status_code=400, detail=f"HPKE decryption failed: {str(e)}")

@app.get("/api/public-key")
async def get_public_key():
    """
    Get the enclave's HPKE public key.
    
    WARNING: For security, prefer getting the public key from a verified
    attestation document, not from this endpoint. The attestation document
    cryptographically proves the key belongs to this enclave.
    """
    global _enclave_public_key_bytes
    
    if _enclave_public_key_bytes is None:
        raise HTTPException(status_code=503, detail="Key pair not initialized")
    
    return {
        "public_key_hex": _enclave_public_key_bytes.hex(),
        "key_type": "EC",
        "curve": "P-256",
        "format": "uncompressed",
        "hpke_suite": "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
        "warning": "Use attestation document for verified public key"
    }

@app.get("/api/attestation")
async def get_attestation_simple(nonce: Optional[str] = None):
    """Simple GET endpoint for attestation document"""
    request = AttestationRequest(nonce=nonce)
    return await get_attestation_document(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)  # nosec B104 - enclave binds to all interfaces for vsock proxy
