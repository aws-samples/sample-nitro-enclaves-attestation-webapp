#!/usr/bin/env python3
"""
Vsock to HTTP proxy for enclave
Listens on vsock port 8000 and forwards to local HTTP backend on 127.0.0.1:8000
"""

import socket
import threading
import sys
import time
import logging

logger = logging.getLogger(__name__)

def handle_client(client_sock, target_host, target_port):
    """Handle client connection by forwarding to HTTP backend"""
    client_addr = client_sock.getpeername() if hasattr(client_sock, 'getpeername') else 'unknown'
    print(f"[PROXY] New client connection from {client_addr}")
    
    try:
        # Connect to backend
        print(f"[PROXY] Connecting to backend {target_host}:{target_port}")
        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.connect((target_host, target_port))
        print(f"[PROXY] Connected to backend successfully")
        
        # Forward data bidirectionally
        def forward(src, dst, direction):
            try:
                bytes_transferred = 0
                while True:
                    data = src.recv(4096)
                    if not data:
                        print(f"[PROXY] {direction}: Connection closed (no data)")
                        break
                    dst.sendall(data)
                    bytes_transferred += len(data)
                    
                    # Log first few bytes to see if it's HTTP/WebSocket
                    if bytes_transferred <= 4096:
                        data_preview = data[:200].decode('utf-8', errors='ignore')
                        print(f"[PROXY] {direction}: {len(data)} bytes - {data_preview[:100]}...")
                    
            except Exception as e:
                print(f"[PROXY] {direction}: Forward error: {e}")
            finally:
                print(f"[PROXY] {direction}: Closing connections (transferred {bytes_transferred} bytes)")
                try:
                    src.close()
                except Exception:
                    logger.debug("Error closing source socket on teardown", exc_info=True)
                try:
                    dst.close()
                except Exception:
                    logger.debug("Error closing destination socket on teardown", exc_info=True)
        
        # Start forwarding threads
        print(f"[PROXY] Starting bidirectional forwarding")
        t1 = threading.Thread(target=forward, args=(client_sock, backend_sock, "client->backend"), daemon=True)
        t2 = threading.Thread(target=forward, args=(backend_sock, client_sock, "backend->client"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print(f"[PROXY] Connection handling complete for {client_addr}")
        
    except Exception as e:
        print(f"[PROXY] Error handling client {client_addr}: {e}")
        try:
            client_sock.close()
        except Exception:
            logger.debug("Error closing client socket after handler failure", exc_info=True)

def main():
    if len(sys.argv) != 3:
        print("Usage: vsock-http-proxy.py <vsock_port> <http_port>")
        sys.exit(1)
    
    vsock_port = int(sys.argv[1])
    http_port = int(sys.argv[2])
    target_host = "127.0.0.1"
    
    print(f"[PROXY] Starting vsock-http proxy: vsock:{vsock_port} -> http://{target_host}:{http_port}")
    
    # Wait for HTTP backend to be ready
    print(f"[PROXY] Waiting for HTTP backend to be ready...")
    for i in range(30):
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(1)
            result = test_sock.connect_ex((target_host, http_port))
            test_sock.close()
            if result == 0:
                print(f"[PROXY] HTTP backend is ready")
                break
        except Exception:
            logger.debug("Backend readiness probe failed; will retry", exc_info=True)
        time.sleep(1)  # nosemgrep: arbitrary-sleep - intentional retry delay waiting for backend
    else:
        print(f"[PROXY] HTTP backend not ready, starting proxy anyway...")
    
    # Create vsock server socket
    server_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server_sock.bind((socket.VMADDR_CID_ANY, vsock_port))
    server_sock.listen(5)
    
    print(f"[PROXY] Vsock server listening on port {vsock_port}")
    
    try:
        while True:
            print(f"[PROXY] Waiting for connections on vsock port {vsock_port}")
            client_sock, addr = server_sock.accept()
            print(f"[PROXY] Accepted connection from {addr}")
            
            # Handle client in separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_sock, target_host, http_port)
            )
            client_thread.daemon = True
            client_thread.start()
            print(f"[PROXY] Started handler thread for {addr}")
            
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()