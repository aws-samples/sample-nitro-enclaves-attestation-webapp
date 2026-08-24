#!/usr/bin/env python3
"""
TCP to vsock proxy for Nitro Enclaves
Listens on TCP port and forwards to vsock CID:port
"""
import socket
import threading
import sys
import os
import logging

def handle_client(client_socket, vsock_cid, vsock_port):
    """Handle a client connection by forwarding to vsock"""
    try:
        # Connect to vsock
        vsock_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        vsock_socket.connect((vsock_cid, vsock_port))
        
        # Forward data in both directions
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                logging.debug("Socket error during bidirectional forward; tearing down", exc_info=True)
            finally:
                src.close()
                dst.close()
        
        # Start forwarding threads
        t1 = threading.Thread(target=forward, args=(client_socket, vsock_socket))
        t2 = threading.Thread(target=forward, args=(vsock_socket, client_socket))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
    except Exception as e:
        logging.error(f"Error handling client: {e}")
        client_socket.close()

def main():
    if len(sys.argv) != 4:
        print("Usage: tcp-vsock-proxy.py <tcp_port> <vsock_cid> <vsock_port>")
        sys.exit(1)
    
    tcp_port = int(sys.argv[1])
    vsock_cid = int(sys.argv[2])
    vsock_port = int(sys.argv[3])
    
    # Bind on all interfaces: this proxy is the Network Load Balancer target, so the
    # NLB health checks and forwarded requests arrive from other VPC IPs, not localhost.
    bind_host = os.environ.get("PROXY_BIND", "0.0.0.0")  # nosec B104 - NLB target must accept VPC-internal connections

    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting TCP-to-vsock proxy: {bind_host}:{tcp_port} -> vsock({vsock_cid}:{vsock_port})")

    # Create TCP server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((bind_host, tcp_port))
    server_socket.listen(128)
    
    try:
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Connection from {addr}")
            thread = threading.Thread(target=handle_client, args=(client_socket, vsock_cid, vsock_port))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        logging.info("Shutting down proxy")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()