import os
import sys
import asyncio
import ngrok
import argparse
import logging
from dotenv import load_dotenv
from aiohttp import web, ClientSession, ClientTimeout
from typing import Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Address:
    def __init__(self, *, host: Optional[str] = None, port: int):
        self.host = host or '127.0.0.1'
        self.port = port

    def __str__(self):
        return f'{self.host}:{self.port}'

def parse_address(value: str) -> Address:
    try:
        if value.isdigit():
            return Address(port=int(value))
        host, port = value.rsplit(':', 1)
        return Address(host=host, port=int(port))
    except ValueError:
        raise argparse.ArgumentTypeError(f"Address must be in host:port format; got '{value}'")

def parse_args():
    parser = argparse.ArgumentParser(description='TCP/HTTP Proxy Server')
    parser.add_argument('--to-http', type=parse_address, default=None,
        dest='to_http_address', help="Enable ngrok proxy ('/') to HOST:PORT")
    parser.add_argument('--from', type=parse_address, default=Address(port=9000),
        dest='from_address', help='Run proxy server on HOST:PORT')
    parser.add_argument('--to-tcp', type=parse_address, default=Address(port=12346),
        dest='to_tcp_address', help='HOST:PORT to proxy to (TCP)')
    return parser.parse_args()

async def send_tcp_data(data, address: Address):
    """Send data to TCP server asynchronously"""
    try:
        logging.info(f"Connecting to TCP server at {address}")
        reader, writer = await asyncio.open_connection(address.host, address.port)
        logging.info(f"Sending to TCP: {data}")
        writer.write(data.encode('utf-8'))
        await writer.drain()
    except Exception as e:
        logging.error(f"TCP connection failed: {e}")
        raise Exception(f"TCP connection failed: {str(e)}")

def init_server(to_tcp_address: Address, to_http_address: Address | None):
    async def handle_tcp(request):
        """Handle TCP forwarding requests"""
        headers = {'Access-Control-Allow-Origin': '*'}
        try:
            logging.info(f"Received /tcp POST from {request.remote}")
            # Parse JSON body
            if request.content_type != 'application/json':
                logging.warning("Received /tcp with incorrect Content-Type")
                return web.json_response(
                    {"error": "Content-Type must be application/json"},
                    status=400,
                    headers=headers
                )

            data = await request.json()
            if 'data' not in data:
                logging.warning("Received /tcp with missing 'data' field")
                return web.json_response(
                    {"error": "Missing 'data' field in JSON"},
                    status=400,
                    headers=headers
                )

            # Send to TCP server
            tcp_response = await send_tcp_data(data['data'], to_tcp_address)

            return web.json_response({
                "status": "success",
                "tcp_response": tcp_response
            }, headers=headers)

        except Exception as err:
            logging.error(f"Error handling /tcp request: {err}")
            return web.json_response({"error": str(err)}, status=500, headers=headers)

    async def handle_tcp_options(request):
        return web.Response(
            status=200,
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
            }
        )

    async def proxy_http(request):
        """Forward all other requests to HTTP server with streaming"""
        try:
            # Build target URL
            path = request.match_info.get('path', '')
            target_url = f"http://{to_http_address}/{path}"
            logging.info(f"Proxying {request.method} {request.path_qs} to {target_url}")

            # Prepare headers (exclude host and content-length)
            headers = {k: v for k, v in request.headers.items()
                if k.lower() not in ['host', 'content-length']}

            # Create HTTP session with streaming support
            timeout = ClientTimeout(total=None)  # No timeout for streaming

            async with ClientSession(timeout=timeout) as session:
                if request.can_read_body:
                    data = request.content  # This is a StreamReader for async reading
                else:
                    data = None

                async with session.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    params=request.query_string,
                    data=data,
                    allow_redirects=False
                ) as response:
                    response_headers = dict(response.headers)
                    web_response = web.StreamResponse(
                        status=response.status,
                        headers=response_headers
                    )
                    await web_response.prepare(request)
                    async for chunk in response.content.iter_chunked(8192):
                        if chunk:
                            await web_response.write(chunk)

                    await web_response.write_eof()
                    return web_response

        except Exception as err:
            logging.error(f"HTTP forwarding failed: {err}")
            return web.json_response(
                {"error": f"HTTP forwarding failed: {err}"},
                status=502
            )

    app = web.Application()
    app.add_routes([
        web.options('/tcp', handle_tcp_options),
        web.post('/tcp', handle_tcp)
    ])
    if to_http_address:
        app.add_routes([web.route('*', '/{path:.*}', proxy_http)])
    return app

if __name__ == '__main__':
    load_dotenv()
    DOMAIN = os.getenv('DOMAIN')
    if not DOMAIN:
        logging.error("DOMAIN environment variable is not set. Must be set to an ngrok domain.")
        sys.exit(1)

    args = parse_args()
    app = init_server(args.to_tcp_address, args.to_http_address)

    logging.info(f"Forwarding http://{args.from_address}/tcp and https://{DOMAIN}/tcp to tcp://{args.to_tcp_address}")
    if args.to_http_address:
        logging.info(f"Forwarding http://{args.from_address} or https://{DOMAIN} to http://{args.to_http_address}")

    listener = ngrok.forward(str(args.from_address), authtoken_from_env=True, domain=DOMAIN)
    logging.info(f"Ingress established at {listener.url()}")
    web.run_app(app, host=args.from_address.host, port=args.from_address.port)
