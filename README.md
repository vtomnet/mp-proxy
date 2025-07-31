# mp-proxy

This bridges the [Mission Planner client app](https://github.com/thomasm6m6/mpui) to target device.

## TLDR

1. Obtain an auth token and domain at https://ngrok.io.
2. Create a `.env` file with `NGROK_AUTHTOKEN` and `DOMAIN`.
3. Run `python3 proxy.py --to-http :9001`.
4. Open your ngrok URL in a browser.

## More info

Running `python3 proxy.py` with no options will start a proxy from /tcp requests to `localhost:12346`; you may change this with the `--tcp` flag.

Running with the `--to-http HOST:PORT` flag will additionally start a proxy to the specified address via HTTP.

The proxy listens on `localhost:9000` by default, and forwards through the given ngrok domain. Ngrok is used because the web app ([mpui](https://github.com/thomasm6m6/mpui)) requires https.
