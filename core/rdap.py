"""RDAP lookup of one IP address: who holds it (the modern WHOIS).

Runs as a child of sectop, as an unprivileged user: core/lookup.py starts it
with setpriv and passes this file's text with `python3 -I -c`. So data from
the network is never parsed by the root process. Prints one line of JSON:
{"ok": true, "fields": [[key, value], ...]} or {"ok": false, "error": "..."}.

RFC 9224: IANA bootstrap files map address blocks to the RDAP server of a
registry (RIR). RFC 9083: JSON of an IP network object. Stdlib only.
HTTPS only (redirects to other schemes refused), bodies max 1 MiB.
"""

import ipaddress
import json
import sys
import urllib.error
import urllib.request

BOOT = {4: "https://data.iana.org/rdap/ipv4.json", 6: "https://data.iana.org/rdap/ipv6.json"}
TIMEOUT = 4.0            # per request; bootstrap + query (+ redirect) stay below 12 s
MAX_BODY = 1 << 20
MAX_VALUE = 200
ACCEPT = "application/rdap+json, application/json"


class HttpsOnly(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(newurl, code, "redirect to non-https refused",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> dict:
    opener = urllib.request.build_opener(HttpsOnly)
    req = urllib.request.Request(url, headers={"Accept": ACCEPT, "User-Agent": "sectop-rdap"})
    with opener.open(req, timeout=TIMEOUT) as r:
        body = r.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError("response larger than 1 MiB")
    doc = json.loads(body)
    if not isinstance(doc, dict):
        raise ValueError("response is not a JSON object")
    return doc


def base_url(boot: dict, ip) -> str | None:
    """Most specific block that holds ip -> its first https server URL."""
    best, url = -1, None
    services = boot.get("services")
    for entry in services if isinstance(services, list) else ():
        if not (isinstance(entry, list) and len(entry) == 2):
            continue
        blocks, urls = entry
        if not (isinstance(blocks, list) and isinstance(urls, list)):
            continue
        https = [u for u in urls if isinstance(u, str) and u.lower().startswith("https://")]
        if not https:
            continue
        for block in blocks:
            try:
                net = ipaddress.ip_network(block, strict=False)
            except (TypeError, ValueError):
                continue
            if net.version == ip.version and ip in net and net.prefixlen > best:
                best, url = net.prefixlen, https[0]
    return url


def _list(d: dict, key: str) -> list:
    v = d.get(key)
    return v if isinstance(v, list) else []


def _vcard(ent: dict) -> dict:
    """jCard (RFC 7095) -> {'fn': ..., 'email': ...}, first value of each."""
    out = {}
    arr = ent.get("vcardArray")
    if isinstance(arr, list) and len(arr) == 2 and isinstance(arr[1], list):
        for prop in arr[1]:
            if isinstance(prop, list) and len(prop) >= 4 and prop[0] in ("fn", "email") \
                    and isinstance(prop[3], str) and prop[0] not in out:
                out[prop[0]] = prop[3]
    return out


def _entities(doc: dict, depth: int = 0):
    """-> (roles, vcard) of every entity, nested ones too (ARIN puts abuse there)."""
    for ent in _list(doc, "entities"):
        if not isinstance(ent, dict):
            continue
        roles = [r for r in _list(ent, "roles") if isinstance(r, str)]
        yield roles, _vcard(ent)
        if depth < 3:
            yield from _entities(ent, depth + 1)


def pick(doc: dict) -> list:
    """IP network object -> [(key, value)] worth showing."""
    out = []

    def put(k, v):
        if isinstance(v, str) and v.strip():
            out.append((k, " ".join(v.split())[:MAX_VALUE]))

    put("name", doc.get("name"))
    put("handle", doc.get("handle"))
    start, end = doc.get("startAddress"), doc.get("endAddress")
    if isinstance(start, str) and isinstance(end, str):
        put("range", f"{start} - {end}")
    cidrs = []
    for c in _list(doc, "cidr0_cidrs"):
        if isinstance(c, dict):
            prefix, length = c.get("v4prefix") or c.get("v6prefix"), c.get("length")
            if isinstance(prefix, str) and isinstance(length, int):
                cidrs.append(f"{prefix}/{length}")
    put("cidr", ", ".join(cidrs[:4]))
    put("type", doc.get("type"))
    put("country", doc.get("country"))
    put("parent", doc.get("parentHandle"))
    ents = list(_entities(doc))
    org = next((vc["fn"] for roles, vc in ents if "registrant" in roles and "fn" in vc), None)
    org = org or next((vc["fn"] for _roles, vc in ents if "fn" in vc), None)
    put("org", org)
    put("abuse", next((vc["email"] for roles, vc in ents if "abuse" in roles
                       and "email" in vc), None))
    for ev in _list(doc, "events"):
        if isinstance(ev, dict) and isinstance(ev.get("eventDate"), str):
            name = {"registration": "registered", "last changed": "changed"}.get(
                ev.get("eventAction"))
            if name:
                put(name, ev["eventDate"][:10])
    for rem in _list(doc, "remarks"):
        lines = _list(rem, "description") if isinstance(rem, dict) else []
        if lines and isinstance(lines[0], str):
            put("remark", lines[0])
            break
    put("whois server", doc.get("port43"))
    return out


def main(argv=None, get=fetch) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        ip = ipaddress.ip_address(argv[0] if argv else "")
        if not ip.is_global:
            raise ValueError("not a public address")
        base = base_url(get(BOOT[ip.version]), ip)
        if base is None:
            raise ValueError("no RDAP server for this address in the IANA bootstrap")
        url = base + ("" if base.endswith("/") else "/") + "ip/" + str(ip)
        result = {"ok": True, "fields": pick(get(url)) + [("source", url)]}
    except (OSError, ValueError, KeyError, TypeError) as e:     # URLError, HTTPError: OSError
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"[:MAX_VALUE]}
        if isinstance(e, urllib.error.HTTPError):
            e.close()                  # holds the response body; not left to the gc
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
