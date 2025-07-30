#!/usr/bin/env python3

import os
import sys
import socket
import argparse
import logging
import requests
import ngrok
from typing import Optional
from dataclasses import dataclass
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

def parse_args():
    parser = argparse.ArgumentParser(description='TCP/HTTP Proxy Server')
    parser.add_argument('--http', type=str, default=None,
        help="Enable ngrok proxy ('/') to HOST:PORT")
    parser.add_argument('--listen', type=str, default=':3000',
        help='Run proxy server on PORT')
    parser.add_argument('--tcp', type=str, default=':12346',
        help='HOST:PORT to proxy to (TCP)')
    return parser.parse_args()

@dataclass
class Address:
    host: str
    port: int

    def __str__(self):
        return f'{self.host}:{self.port}'

def parse_addr(addr: str) -> Address:
    if not addr or ':' not in addr:
        raise ValueError('Invalid address {addr}')

    port_str = ''
    try:
        host, port_str = addr.split(':', maxsplit=1)
        port = int(port_str)
        if not host:
            host = 'localhost'
        return Address(host, port)
    except ValueError:
        raise ValueError(f"Given port '{port_str}' is invalid")

def send_tcp_message(target_addr: Address, data: bytes) -> bytes:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(10.0)  # 10 second timeout

            print("Beginning to connect...")
            client.connect((target_addr.host, target_addr.port))

            print("Beginning to write data...")
            client.sendall(data)
            print("Wrote data...")

            # Collect response
            response = b''
            while True:
                try:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    print("Got response chunk: {chunk}")
                except socket.timeout:
                    break

            return response

    except socket.error as e:
        raise Exception(f"TCP connection failed: {e}")

def create_app(tcp_addr: Address, http_addr: Optional[Address] = None):
    app = Flask(__name__)
    CORS(app)

    @app.route('/tcp', methods=['POST'])
    def tcp_endpoint():
        try:
            body = request.get_json()
            if not body or 'data' not in body:
                return jsonify({'error': 'Missing data field'}), 400

            # Convert data to bytes
            data_to_send = body['data'].encode('utf-8')

            # Send TCP message
            response = send_tcp_message(tcp_addr, data_to_send)

            print('Finished sending.')
            return response.decode('utf-8', errors='ignore')

        except Exception as err:
            print(f"TCP send error: {err}")
            return jsonify({
                'error': 'TCP connection failed',
                'detail': str(err)
            }), 502

    if http_addr:
        @app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
        @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
        def proxy_to_dev(path):
            try:
                target_url = f"http://{http_addr}/{path}"
                resp = requests.request(
                    method=request.method,
                    url=target_url,
                    headers={k: v for k, v in request.headers if k.lower() != 'host'},
                    data=request.get_data(),
                    cookies=request.cookies,
                    allow_redirects=False,
                    params=dict(request.args)
                )
                return resp.content, resp.status_code, dict(resp.headers)
            except requests.RequestException as e:
                return jsonify({'error': f'Proxy error: {str(e)}'}), 502

    return app

def main():
    load_dotenv()
    DOMAIN = os.getenv('DOMAIN')
    args = parse_args()
    use_ngrok = bool(DOMAIN)

    # Get device address
    tcp_addr = parse_addr(args.tcp)
    http_addr = parse_addr(args.http) if args.http else None
    self_addr = parse_addr(args.listen)

    app = create_app(tcp_addr, http_addr)

    if use_ngrok:
        listener = ngrok.forward(str(self_addr), authtoken_from_env=True, domain=DOMAIN)
        print(f'Ingress established at {listener.url()}\n')
    else:
        print("'DOMAIN' is not set in .env. Skipping ngrok. Proxy will not work on smartphones!\n")

    # Start server
    if use_ngrok:
        print(f"Forwarding http://{self_addr}/tcp and https://{DOMAIN}/tcp to tcp://{tcp_addr}...\n")
        if http_addr:
            print(f"Forwarding http://{self_addr}/ or https://{DOMAIN}/ to http://{http_addr}...\n")
    else:
        print(f"Forwarding http://{self_addr}/tcp to tcp://{tcp_addr}...\n")
        if http_addr:
            print(f"Forwarding http://{self_addr}/ to http://{http_addr}...\n")

    try:
        app.run(host=self_addr.host, port=self_addr.port)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
