import os, json, hmac, hashlib, base64, urllib.request

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
SLACK_URL = os.environ.get("SLACK_URL", "")
ALLOW_UNVERIFIED = os.environ.get("ALLOW_UNVERIFIED", "false").lower() == "true"


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
    sig = headers.get("x-hub-signature-256")
    if not sig:
        return ALLOW_UNVERIFIED
    mac = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, sig)


def _slack(text: str) -> None:
    if not SLACK_URL:
        print("slack missing: no SLACK_URL")
        return
    data = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        SLACK_URL, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print("slack status:", resp.status, "body:", resp.read().decode("utf-8", "ignore"))
    except Exception as e:
        print("slack error:", e)


def lambda_handler(event, _ctx):
    raw = _raw_body(event)
    headers = _headers(event)

    if not _verify(headers, raw):
        return {"statusCode": 401, "body": "invalid signature"}

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as e:
        print("json error:", e)
        return {"statusCode": 200, "body": "ok"}

    gh_event = headers.get("x-github-event", "unknown")
    action = payload.get("action")
    print("gh_event:", gh_event, "action:", action)

    if gh_event == "issues" and action in ("opened", "reopened"):
        repo = (payload.get("repository") or {}).get("full_name", "")
        issue = payload.get("issue") or {}
        url = issue.get("html_url") or issue.get("url")
        if not url:
            repo_html = (payload.get("repository") or {}).get("html_url")
            num = issue.get("number")
            if repo_html and num:
                url = f"{repo_html}/issues/{num}"
        title = issue.get("title", "(no title)")
        _slack(f"Issue {action} in {repo}: {title}\n{url or 'URL not found'}")

    return {"statusCode": 200, "body": "ok"}

