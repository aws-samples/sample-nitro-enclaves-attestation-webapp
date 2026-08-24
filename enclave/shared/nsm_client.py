import os
from typing import Dict, Any, Optional
import cbor2
import base64
import logging
import struct
import fcntl
import ctypes

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# NSM ioctl definitions
NSM_IOCTL_MAGIC = 0x0A
NSM_REQUEST_MAX_SIZE = 0x1000
NSM_RESPONSE_MAX_SIZE = 0x3000

# NSM request types from aws-nitro-enclaves-nsm-api
NSM_REQUEST_ATTESTATION = 0
NSM_REQUEST_DESCRIBE_PCR = 1
NSM_REQUEST_EXTEND_PCR = 2
NSM_REQUEST_LOCK_PCR = 3
NSM_REQUEST_LOCK_PCRS = 4
NSM_REQUEST_DESCRIBE_NSM = 5
NSM_REQUEST_GET_RANDOM = 6


class NSMClient:
    """Client for interacting with AWS Nitro Secure Module (NSM) device"""
    
    def __init__(self, device_path: str = "/dev/nsm"):
        self.device_path = device_path
        self._fd = None
        logger.debug(f"NSM client initialized with device: {device_path}")
    
    def _ensure_device_open(self):
        """Ensure NSM device is open, open if needed"""
        if self._fd is None:
            self._fd = os.open(self.device_path, os.O_RDWR)
            logger.debug(f"NSM device opened, fd: {self._fd}")
    
    def close(self):
        """Close NSM device if open"""
        if self._fd is not None:
            os.close(self._fd)
            logger.debug("NSM device closed")
            self._fd = None
    
    def is_available(self) -> bool:
        """Check if NSM device is available"""
        return os.path.exists(self.device_path)
    
    def _nsm_ioctl(self, request_data: bytes) -> bytes:
        """
        Send ioctl request to NSM device and receive response
        Uses persistent file descriptor for better performance
        
        Uses proper NSM message structure matching Rust implementation
        """
        try:
            logger.debug(f"NSM device path: {self.device_path}")
            logger.debug(f"NSM device exists: {os.path.exists(self.device_path)}")
            
            # Ensure device is open (reuse existing fd)
            self._ensure_device_open()
            logger.debug(f"Using NSM device fd: {self._fd}")
            
            # NSM message structure matching Rust IoSlice/IoSliceMut (iovec)
            class NsmMessage(ctypes.Structure):
                _fields_ = [
                    ("request_base", ctypes.c_void_p),   # iovec.iov_base
                    ("request_len", ctypes.c_size_t),    # iovec.iov_len
                    ("response_base", ctypes.c_void_p),  # iovec.iov_base
                    ("response_len", ctypes.c_size_t),   # iovec.iov_len
                ]
            
            # Create buffers
            request_buf = ctypes.create_string_buffer(request_data)
            response_buf = ctypes.create_string_buffer(NSM_RESPONSE_MAX_SIZE)
            logger.debug(f"Created buffers - request: {len(request_data)} bytes, response buffer: {NSM_RESPONSE_MAX_SIZE} bytes")
            
            # Setup message structure
            msg = NsmMessage()
            msg.request_base = ctypes.cast(request_buf, ctypes.c_void_p)
            msg.request_len = len(request_data)
            msg.response_base = ctypes.cast(response_buf, ctypes.c_void_p)
            msg.response_len = NSM_RESPONSE_MAX_SIZE
            
            # NSM ioctl command: _IOWR(NSM_IOCTL_MAGIC, NSM_IO_REQUEST, struct nsm_request)
            # NSM_IOCTL_MAGIC = 0x0A, NSM_IO_REQUEST = 0x00
            struct_size = ctypes.sizeof(NsmMessage)
            NSM_IOCTL_REQUEST = (3 << 30) | (0x0A << 8) | 0x00 | (struct_size << 16)
            
            logger.debug(f"NSM ioctl command: 0x{NSM_IOCTL_REQUEST:08x}")
            logger.debug(f"NSM_IOCTL_MAGIC: 0x{NSM_IOCTL_MAGIC:02x}")
            logger.debug(f"Struct size: {struct_size}")
            logger.debug(f"Request data preview: {request_data[:100]}...")
            
            # Send ioctl
            logger.debug("Sending ioctl to NSM device...")
            fcntl.ioctl(self._fd, NSM_IOCTL_REQUEST, msg)
            logger.debug("ioctl completed successfully")
            
            # Get actual response size and data
            actual_response_size = msg.response_len
            logger.debug(f"NSM response size: {actual_response_size} bytes")
            
            if actual_response_size == 0:
                raise Exception("No response data received")
            
            response_data = response_buf.raw[:actual_response_size]
            logger.debug(f"Response data preview: {response_data[:100]}...")
            
            return response_data
            
        except Exception as e:
            logger.warning(f"NSM ioctl failed: {e}")
            logger.warning(f"Exception type: {type(e)}")
            import traceback
            logger.warning(f"Traceback: {traceback.format_exc()}")
            # Close and reset fd on error to force reopening
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except Exception:
                    logger.debug("Error closing NSM device fd during error recovery", exc_info=True)
                self._fd = None
            raise
    
    def get_attestation_document(
        self, 
        user_data: Optional[bytes] = None, 
        nonce: Optional[bytes] = None, 
        public_key: Optional[bytes] = None
    ) -> bytes:
        """
        Get attestation document from NSM via ioctl
        
        Args:
            user_data: Optional user data to include (max 512 bytes)
            nonce: Optional nonce for replay protection (max 512 bytes)
            public_key: Optional public key to include (max 1024 bytes)
            
        Returns:
            CBOR-encoded COSE_Sign1 attestation document
        """
        logger.debug("Requesting attestation document from NSM via ioctl")
        
        # Build NSM attestation request in CBOR format
        # Request format: {"Attestation": {"user_data": ..., "nonce": ..., "public_key": ...}}
        attestation_params = {}
        
        if user_data:
            if len(user_data) > 512:
                raise ValueError("user_data must be <= 512 bytes")
            attestation_params["user_data"] = user_data
        
        if nonce:
            if len(nonce) > 512:
                raise ValueError("nonce must be <= 512 bytes")
            attestation_params["nonce"] = nonce
        
        if public_key:
            if len(public_key) > 1024:
                raise ValueError("public_key must be <= 1024 bytes")
            attestation_params["public_key"] = public_key
        
        # Create request
        request = {"Attestation": attestation_params}
        request_cbor = cbor2.dumps(request)
        
        logger.debug(f"NSM request size: {len(request_cbor)} bytes")
        
        # Send to NSM device
        response_cbor = self._nsm_ioctl(request_cbor)
        
        # Parse response
        response = cbor2.loads(response_cbor)
        logger.debug(f"NSM response type: {type(response)}")
        
        # Response format: {"Attestation": {"document": <cbor_bytes>}} or {"Error": ...}
        if "Error" in response:
            raise Exception(f"NSM error: {response['Error']}")
        
        if "Attestation" not in response or "document" not in response["Attestation"]:
            raise Exception("Invalid NSM response format")
        
        attestation_doc = response["Attestation"]["document"]
        logger.debug(f"Attestation document size: {len(attestation_doc)} bytes")
        
        return attestation_doc
    
    def describe_pcr(self, index: int) -> Dict[str, Any]:
        """
        Describe a specific PCR
        
        Args:
            index: PCR index (0-31 for Nitro Enclaves)
            
        Returns:
            PCR information including lock status and data
        """
        if index < 0 or index > 31:
            raise ValueError("PCR index must be between 0 and 31")
        
        request = {"DescribePCR": {"index": index}}
        request_cbor = cbor2.dumps(request)
        
        response_cbor = self._nsm_ioctl(request_cbor)
        response = cbor2.loads(response_cbor)
        
        if "Error" in response:
            raise Exception(f"NSM error: {response['Error']}")
        
        result = response.get("DescribePCR", {})
        
        # Convert any bytes to hex strings for JSON serialization
        if "data" in result and isinstance(result["data"], bytes):
            result["data"] = result["data"].hex()
        
        return result
    
    def extend_pcr(self, index: int, data: bytes) -> Dict[str, Any]:
        """
        Extend a PCR with data
        
        Args:
            index: PCR index (0-31, but only certain PCRs are extendable)
            data: Data to extend PCR with (typically 32, 48, or 64 bytes)
            
        Returns:
            Extended PCR information
        """
        if index < 0 or index > 31:
            raise ValueError("PCR index must be between 0 and 31")
        
        # Note: Not all PCRs are extendable. PCR0-4 are reserved for enclave boot.
        # Applications can typically extend PCR8-31
        if index < 8:
            logger.warning(f"PCR{index} is typically reserved for enclave boot measurements")
        
        request = {"ExtendPCR": {"index": index, "data": data}}
        request_cbor = cbor2.dumps(request)
        
        response_cbor = self._nsm_ioctl(request_cbor)
        response = cbor2.loads(response_cbor)
        
        if "Error" in response:
            raise Exception(f"NSM error: {response['Error']}")
        
        result = response.get("ExtendPCR", {})
        
        # Convert any bytes to hex strings for JSON serialization
        if "data" in result and isinstance(result["data"], bytes):
            result["data"] = result["data"].hex()
        
        return result
    
    def lock_pcr(self, index: int) -> Dict[str, Any]:
        """
        Lock a PCR to prevent further extensions
        
        Args:
            index: PCR index to lock
            
        Returns:
            Lock status
        """
        if index < 0 or index > 31:
            raise ValueError("PCR index must be between 0 and 31")
        
        request = {"LockPCR": {"index": index}}
        request_cbor = cbor2.dumps(request)
        
        response_cbor = self._nsm_ioctl(request_cbor)
        response = cbor2.loads(response_cbor)
        
        if "Error" in response:
            raise Exception(f"NSM error: {response['Error']}")
        
        # NSM returns just the string "LockPCR" for successful lock operations
        if isinstance(response, str) and response == "LockPCR":
            return {"status": "locked", "operation": "LockPCR"}
        elif "LockPCR" in response:
            return {"status": "locked", "operation": response["LockPCR"]}
        else:
            return {"status": "unknown", "response": response}
    
    def describe_nsm(self) -> Dict[str, Any]:
        """
        Get NSM module description including version and capabilities
        
        Returns:
            NSM module information
        """
        # DescribeNSM request should be empty according to NSM API
        request = {"DescribeNSM": None}
        request_cbor = cbor2.dumps(request)
        
        response_cbor = self._nsm_ioctl(request_cbor)
        response = cbor2.loads(response_cbor)
        
        if "Error" in response:
            raise Exception(f"NSM error: {response['Error']}")
        
        return response.get("DescribeNSM", {})
    
    def get_random(self, length: int = 32) -> bytes:
        """
        Get random bytes from NSM
        
        Args:
            length: Number of random bytes to generate (max 256)
            
        Returns:
            Random bytes
        """
        if length <= 0 or length > 256:
            raise ValueError("Length must be between 1 and 256")
        
        request = {"GetRandom": {}}
        request_cbor = cbor2.dumps(request)
        
        response_cbor = self._nsm_ioctl(request_cbor)
        response = cbor2.loads(response_cbor)
        
        if "Error" in response:
            raise Exception(f"NSM error: {response['Error']}")
        
        random_bytes = response.get("GetRandom", {}).get("random", b"")
        return random_bytes[:length]


def parse_attestation_document(doc_bytes: bytes) -> Dict[str, Any]:
    """
    Parse NSM attestation document
    
    Args:
        doc_bytes: Raw CBOR-encoded COSE_Sign1 attestation document
        
    Returns:
        Parsed attestation document with all fields
    """
    logger.debug(f"Parsing NSM attestation document: {len(doc_bytes)} bytes")
    
    try:
        # Parse the COSE_Sign1 structure
        parsed = cbor2.loads(doc_bytes)
        
        # COSE_Sign1 structure: [protected, unprotected, payload, signature]
        if not isinstance(parsed, list) or len(parsed) < 4:
            raise Exception(f"Invalid COSE_Sign1 structure: expected list of 4 elements, got {type(parsed)}")
        
        protected_headers = parsed[0]
        unprotected_headers = parsed[1]
        payload = parsed[2]
        signature = parsed[3]
        
        logger.debug(f"COSE structure - protected: {type(protected_headers)}, payload: {type(payload)}, signature: {len(signature)} bytes")
        
        # Parse the attestation document from payload
        doc = cbor2.loads(payload)
        logger.debug(f"Document keys: {list(doc.keys())}")
        logger.debug(f"Full document structure: {doc}")
        
        # Parse PCRs - NSM uses 'pcrs' field directly
        pcrs = {}
        if "pcrs" in doc:
            logger.debug(f"Raw PCRs from NSM: {doc['pcrs']}")
            logger.debug(f"PCR keys from NSM: {list(doc['pcrs'].keys())}")
            logger.debug(f"Total PCR count from NSM: {len(doc['pcrs'])}")
            
            for pcr_num, pcr_value in doc["pcrs"].items():
                logger.debug(f"Processing PCR {pcr_num}: type={type(pcr_value)}, value={pcr_value}")
                if isinstance(pcr_value, bytes):
                    pcrs[str(pcr_num)] = pcr_value.hex()
                elif isinstance(pcr_value, str):
                    try:
                        pcr_bytes = base64.b64decode(pcr_value)
                        pcrs[str(pcr_num)] = pcr_bytes.hex()
                    except:
                        pcrs[str(pcr_num)] = pcr_value
        else:
            logger.warning("No 'pcrs' field found in attestation document!")
        
        return {
            "module_id": doc.get("module_id", "Unknown"),
            "timestamp": doc.get("timestamp", 0),
            "digest": doc.get("digest", "SHA384"),
            "pcrs": pcrs,
            "certificate": base64.b64encode(doc.get("certificate", b"")).decode() if doc.get("certificate") else "",
            "cabundle": [base64.b64encode(cert).decode() for cert in doc.get("cabundle", [])],
            "public_key": base64.b64encode(doc.get("public_key", b"")).decode() if doc.get("public_key") else "",
            "user_data": base64.b64encode(doc.get("user_data", b"")).decode() if doc.get("user_data") else None,
            "nonce": base64.b64encode(doc.get("nonce", b"")).decode() if doc.get("nonce") else None,
            "raw_certificate": doc.get("certificate", b""),
            "raw_cabundle": doc.get("cabundle", [])
        }
    except Exception as e:
        logger.warning(f"Failed to parse attestation document: {e}")
        raise Exception(f"Invalid attestation document format: {e}")
