import os, json, hmac, hashlib, base64, urllib.request

SLACK_URL      = os.environ.get("SLACK_URL", "")       # set in Lambda env
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")  # optional; if empty, skip verify


def _raw_body(event) -> bytes:
    body = event.get("body", "")
    is_b64 = event.get("isBase64Encoded", False)
    if isinstance(is_b64, str):
        is_b64 = is_b64.lower() == "true"
    if is_b64:
        try:
            return base64.b64decode(body)
        except Exception as e:
            print("base64 decode error:", e)
            return b""
    return body.encode("utf-8")


def _headers(event) -> dict:
    src = event.get("headers") or {}
    return {str(k).lower(): str(v) for k, v in src.items()}


def _verify(headers: dict, raw: bytes) -> bool:
    # If no secret configured, accept (matches assignment simplicity).
    if not WEBHOOK_SECRET:
        return True
    sig = headers.get("x-hub-signature-256")
    if not sig:
        return False
    mac = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, sig)


def _slack_text(text: str) -> None:
    if not SLACK_URL:
        print("slack missing: no SLACK_URL")
        return
    data = json.dumps({"text": text}).encode()
    req = urllib.request.Request(SLACK_URL, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print("slack status:", resp.status, "body:", resp.read().decode("utf-8", "ignore"))
    except Exception as e:
        print("slack error:", e)


def lambda_handler(event, _ctx):
    try:
        raw = _raw_body(event)
        headers = _headers(event)

        if not _verify(headers, raw):
            print("bad signature")  # do not 5xx to avoid GitHub retries
            return {"statusCode": 200, "body": "ok"}

        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as e:
            print("json error:", e, "raw_prefix:", raw[:200])
            return {"statusCode": 200, "body": "ok"}

        gh_event = headers.get("x-github-event", "unknown")
        action = payload.get("action")
        print("gh_event:", gh_event, "action:", action)

        if gh_event == "issues" and action in ("opened", "reopened"):
            issue = payload.get("issue") or {}
            url = issue.get("html_url") or issue.get("url")  # prefer human URL
            _slack_text(f"Issue Created: {url or 'URL not found'}")

        return {"statusCode": 200, "body": "ok"}
    except Exception as e:
        print("unhandled:", repr(e))
        return {"statusCode": 200, "body": "ok"}

