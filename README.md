# mp-proxy

This bridges the [Mission Planner client app](https://github.com/thomasm6m6/mpui) to target device.

## TLDR

1. Obtain an auth token and domain at https://ngrok.io.
2. Create a `.env` file with `NGROK_AUTHTOKEN` and `DOMAIN`.
3. Run `python3 proxy.py --http :3001`.

## More info

Running `python3 proxy.py` with no options will start a proxy from /tcp requests to `localhost:12346`; you may change this with the `--tcp` flag.

Running with the `--http HOST:PORT` flag will additionally start a proxy to the specified address via HTTP.

The proxy listens on `localhost:3000` by default. It will also proxy through an ngrok domain if `NGROK_AUTHTOKEN` and `DOMAIN` are set in the `.env` file. You may obtain these at https://ngrok.io. Proxying through ngrok is particularly useful for allowing smartphones to talk to devices on the local network.

TODO: consider changing to using different ports instead of different paths
