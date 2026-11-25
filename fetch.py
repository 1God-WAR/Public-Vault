"""A polite, generic page fetcher that runs from a sealed job and returns a sealed result.

Every site is asked for robots.txt first, one request at a time with a pause, and is left alone for the rest of the
run after a refusal (401, 403, 429, 430, a challenge, a robots.txt server error). Nothing is printed and nothing is
kept in the clear: the job is opened in memory, and each batch of pages is encrypted before it is written.
"""

import base64
import gzip
import hashlib
import json
import os
import re
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from html import unescape
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlsplit

import httpx
from nacl.public import PrivateKey, PublicKey, SealedBox

BATCH = 100
MAX_BYTES = 4_000_000
KEEP_HEADERS = ("content-type", "location", "x-wp-total", "x-wp-totalpages")
MIN_DELAY = 1.5
REDIRECTS = {301, 302, 303, 307, 308}


class Stopped(Exception):
    """The site refused, so nothing else is asked of it."""


def _normalise(path):
    return quote(unquote(path), safe="/*$?&=%:@!,;+~'()-._[]{}|")


class Robots:
    """RFC 9309: the longest matching rule wins, Allow wins a tie."""

    def __init__(self, text=""):
        self.groups, agents, rules, collecting = [], [], [], False
        for raw in text.lstrip("﻿").splitlines():
            name, colon, value = raw.split("#", 1)[0].partition(":")
            name, value = name.strip().lower(), value.strip()
            if not colon:
                continue
            if name == "user-agent":
                if not collecting:
                    agents, rules = [], []
                    self.groups.append((agents, rules))
                    collecting = True
                agents.append(value.lower())
            elif name in {"allow", "disallow", "crawl-delay", "request-rate"}:
                collecting = False
                if agents and value and name in {"allow", "disallow"}:
                    rules.append((name == "allow", _normalise(value)))

    def allows(self, agent, url):
        parts = urlsplit(url)
        path = _normalise((parts.path or "/") + (f"?{parts.query}" if parts.query else ""))
        if path == "/robots.txt":
            return True
        short = re.split(r"[/\s]", agent.strip(), maxsplit=1)[0].lower()
        named = [group for group in self.groups if short in group[0]] or [group for group in self.groups if "*" in group[0]]
        best = (-1, True)
        for _, rules in named:
            for allow, pattern in rules:
                end = pattern.endswith("$")
                expression = ".*".join(map(re.escape, pattern.removesuffix("$").split("*")))
                if re.match(expression + ("$" if end else ""), path, re.S):
                    best = max(best, (len(pattern), allow))
        return best[1]


class Result:
    """Collects records and writes them encrypted, so a cut-off run keeps what it has."""

    def __init__(self, folder, key):
        self.folder, self.box, self.rows, self.count = Path(folder), SealedBox(PublicKey(base64.b64decode(key))), [], 0
        self.folder.mkdir(parents=True, exist_ok=True)

    def add(self, row):
        self.rows.append(row)
        if len(self.rows) >= BATCH:
            self.flush()

    def flush(self):
        rows, self.rows = self.rows, []
        if rows:
            self.count += 1
            (self.folder / f"{id(self)}-{self.count}.bin").write_bytes(self.box.encrypt(zlib.compress(json.dumps(rows).encode())))


class Site:
    def __init__(self, spec, agent, result, deadline, client):
        self.spec, self.agent, self.result, self.deadline, self.client = spec, agent, result, deadline, client
        self.delay, self.last, self.rules, self.maps, self.seen = max(MIN_DELAY, spec.get("delay", MIN_DELAY)), 0.0, {}, [], set()
        self.hosts = {host.removeprefix("www.") for host in spec["hosts"]}
        skip = base64.b64decode(spec.get("skip", ""))
        self.skip = {skip[n:n + 5] for n in range(0, len(skip), 5)}

    def known(self, url):
        return hashlib.sha256(url.encode()).digest()[:5] in self.skip

    def send(self, url):
        time.sleep(max(0.0, self.delay - (time.monotonic() - self.last)))
        body = b""
        try:
            with self.client.stream("GET", url, headers={"User-Agent": self.agent}) as response:
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_BYTES:
                        break
        finally:
            self.last = time.monotonic()
        headers = {name: response.headers[name] for name in KEEP_HEADERS if name in response.headers}
        self.result.add({"u": url, "s": response.status_code, "h": headers, "b": base64.b64encode(zlib.compress(body)).decode()})
        if response.headers.get("cf-mitigated") or response.headers.get("x-amzn-waf-action"):
            raise Stopped("challenge")
        if response.status_code in {401, 403, 429, 430}:
            raise Stopped(f"http_{response.status_code}")
        if re.search(rb"<title[^>]*>\s*request rejected\b", body[:4096], re.I):
            raise Stopped("request_rejected")
        return response.status_code, headers, body

    def allowed(self, url):
        try:
            parts = urlsplit(url)
            return parts.scheme == "https" and not parts.username and not parts.port and parts.netloc.removeprefix("www.") in self.hosts
        except ValueError:
            return False

    def read_robots(self, base):
        self.rules[base] = Robots()
        url = base + "/robots.txt"
        status, headers, body = self.send(url)
        for _ in range(3):
            target = urljoin(url, headers.get("location", ""))
            if status not in REDIRECTS or not self.allowed(target):
                break
            url = target
            status, headers, body = self.send(url)
        if status >= 500:
            raise Stopped("robots_unavailable")
        text = body.decode("utf-8", "replace") if status == 200 else ""
        text = "" if "<html" in text[:500].lower() else text
        self.rules[base] = Robots(text)
        self.maps += re.findall(r"(?im)^\s*sitemap:\s*(\S+)", text)

    def get(self, url):
        """(address, body) or None. Redirects stay on the site, and every host's robots.txt is read first."""
        for _ in range(5):
            if time.monotonic() > self.deadline:
                raise Stopped("time")
            if not self.allowed(url):
                return None
            base = "https://" + urlsplit(url).netloc
            if base not in self.rules:
                self.read_robots(base)
            if url in self.seen or not self.rules[base].allows(self.agent, url):
                return None
            self.seen.add(url)
            try:
                status, headers, body = self.send(url)
            except httpx.TransportError:
                time.sleep(self.delay * 3)
                status, headers, body = self.send(url)
            if status in REDIRECTS and headers.get("location"):
                url = urljoin(url, headers["location"]).split("#")[0]
                continue
            return (url, body) if status in {200, 206} else None
        return None

    def wanted(self, url):
        spec, path = self.spec, urlsplit(url).path
        return (self.allowed(url) and bool(re.search(spec["include"], url, re.I)) and not any(re.search(rule, path if n == 0 else url, re.I) for n, rule in enumerate(spec.get("exclude", [])))
                and (not spec.get("depth") or len(path.strip("/").split("/")) >= spec["depth"]))

    def from_maps(self, queue):
        seen, found = set(), []
        while queue and len(seen) < 25 and len(found) < 6000:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            got = self.get(url)
            body = got[1] if got else b""
            body = gzip.decompress(body)[:MAX_BYTES * 2] if body[:2] == b"\x1f\x8b" else body
            for item in re.findall(r"<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)", body.decode("utf-8", "replace")):
                item = unescape(item)
                if re.search(r"\.xml(?:\.gz)?(?:$|\?)", item):
                    if not self.spec.get("maps") or re.search(self.spec["maps"], item):
                        queue.insert(0 if re.search(r"product|en[-_]in|/in/|in[-_]en", item, re.I) else len(queue), item)
                elif self.wanted(item):
                    found.append(item)
        return found

    def from_pages(self, queue):
        done, found = set(), []
        deeper = self.spec.get("categories")
        while queue and len(done) < 60:
            url = queue.pop(0)
            if url in done:
                continue
            done.add(url)
            got = self.get(url)
            if not got:
                continue
            text = got[1].decode("utf-8", "replace").replace("\\/", "/").replace('\\"', '"')
            for href in re.findall(r"""(?:href|"url"|"link"|"slug"|"pdpUrl"|"canonicalUrl")\s*[=:]\s*["']([^"'#\s]+)""", text):
                link = urljoin(got[0], unescape(href)).split("#")[0]
                if self.wanted(link):
                    found.append(link)
                elif deeper and self.allowed(link) and re.search(deeper, link, re.I) and link not in done:
                    queue.append(link)
        return found

    def from_list(self, rule):
        found = []
        for number in range(rule["first"], rule["first"] + rule["max"]):
            got = self.get(rule["url"].replace("{N}", str(number)))
            try:
                data = json.loads(got[1]) if got else []
            except ValueError:
                data = []
            items = data.get(rule["key"]) if rule.get("key") and isinstance(data, dict) else data
            items = items if isinstance(items, list) else []
            for item in items:
                value = item.get(rule["field"]) if isinstance(item, dict) else None
                if value:
                    found.append(rule["template"].replace("{}", str(value)) if rule.get("template") else str(value))
            if len(items) < rule["size"]:
                break
        return found

    def run(self):
        spec, reason, pages = self.spec, "done", 0
        try:
            first = spec["starts"][0]
            self.read_robots(f"https://{urlsplit(first).netloc}")
            if spec.get("list"):
                found = self.from_list(spec["list"])
            elif spec.get("sitemap"):
                found = self.from_maps(list(spec["starts"]))
            else:
                found = self.from_pages(list(spec["starts"]))
                if len(set(found)) < 10:
                    found += self.from_maps([*self.maps[:4], f"https://{urlsplit(first).netloc}/sitemap.xml"])
            for url in dict.fromkeys(found):
                if self.known(url):
                    continue
                if pages >= spec["max_pages"]:
                    reason = "page_limit"
                    break
                pages += 1
                try:
                    self.get(re.sub(spec["detail"][0], spec["detail"][1], url) if spec.get("detail") else url)
                except httpx.HTTPError:
                    continue
        except Stopped as stop:
            reason = str(stop)
        except Exception as error:
            reason = type(error).__name__
        self.result.add({"site": spec["id"], "reason": reason, "pages": pages})


def run(job, folder, client=None):
    deadline = time.monotonic() + min(job["minutes"], 330) * 60
    lanes = {}
    for spec in job["sites"]:
        lanes.setdefault(spec.get("lane") or spec["id"], []).append(spec)

    def lane(specs):
        result = Result(folder, job["result_key"])
        shared = client or httpx.Client(timeout=30, trust_env=False)
        for spec in specs:
            Site(spec, job["agent"], result, deadline, shared).run()
            result.flush()

    with ThreadPoolExecutor(min(16, len(lanes) or 1)) as pool:
        list(pool.map(lane, lanes.values()))


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    box = SealedBox(PrivateKey(base64.b64decode(os.environ.pop("OPEN_KEY"))))
    run(json.loads(zlib.decompress(box.decrypt(base64.b64decode(event["inputs"]["job"])))), sys.argv[1])


if __name__ == "__main__":
    try:
        main()
    except Exception:  # the message could hold an address
        sys.exit(1)
