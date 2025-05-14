import json
from mitmproxy import http, connection
from mitmproxy.io import FlowWriter

def har_to_flows(har_path: str, flows_path: str) -> None:
    """
    Convert a .har file to a mitmproxy .flows file.

    :param har_path: Path to the input HAR file.
    :param flows_path: Path to the output .flows file.
    """
    # Load HAR data
    with open(har_path, 'r', encoding='utf-8') as f:
        har = json.load(f)

    entries = har.get('log', {}).get('entries', [])
    if not entries:
        print("No entries found in HAR file.")
        return

    # Open the output .flows file
    with open(flows_path, 'wb') as wf:
        writer = FlowWriter(wf)

        for entry in entries:
            req = entry['request']
            res = entry.get('response')

            # Create minimal client and server connections
            client = connection.Client(peername=("", 0), sockname=("", 0))
            server = connection.Server(address=("", 0))

            # Create HTTPFlow
            flow = http.HTTPFlow(client, server)

            # Build mitmproxy HTTP request
            flow.request = http.Request.make(
                method=req.get('method', 'GET'),
                url=req.get('url', ''),
                headers={h['name']: h['value'] for h in req.get('headers', [])},
                content=(req.get('postData', {}).get('text') or "").encode('utf-8')
            )
            # Preserve HTTP version if available
            if 'httpVersion' in req:
                flow.request.http_version = req['httpVersion']

            # Build mitmproxy HTTP response, if present
            if res:
                flow.response = http.Response.make(
                    status_code=res.get('status', 200),
                    content=(res.get('content', {}).get('text') or "").encode('utf-8'),
                    headers={h['name']: h['value'] for h in res.get('headers', [])}
                )
                # Preserve HTTP version if available
                if 'httpVersion' in res:
                    flow.response.http_version = res['httpVersion']

            # Add flow to writer
            writer.add(flow)

    print(f"Converted {len(entries)} entries from '{har_path}' to '{flows_path}'.")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Convert a HAR file to mitmproxy .flows format.'
    )
    parser.add_argument('har', help='Input HAR file path')
    parser.add_argument('flows', help='Output .flows file path')
    args = parser.parse_args()

    har_to_flows(args.har, args.flows)
