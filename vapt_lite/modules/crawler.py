"""In-scope, evidence-preserving application crawler for authorised assessments."""
import re
from collections import deque
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = "VAPT-Ally/1.1 authorised-assessment"
JS_URL = re.compile(r"(?:fetch|axios\.(?:get|post)|XMLHttpRequest)\s*\(?\s*['\"]([^'\"\s]{1,512})", re.I)


def normalise_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


def same_origin(candidate: str, origin: str) -> bool:
    return urlparse(candidate).netloc.lower() == urlparse(origin).netloc.lower()


def crawl_website(start_url: str, max_pages: int = 30, max_depth: int = 3) -> list[str]:
    """Discover normalised, same-origin HTTP endpoints without brute forcing paths."""
    if not start_url.startswith(("http://", "https://")):
        start_url = "https://" + start_url
    start_url = normalise_url(start_url)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    queue, visited = deque([(start_url, 0)]), []
    queued = {start_url}

    def add(url: str, depth: int) -> None:
        if len(queued) >= max_pages * 4 or depth > max_depth:
            return
        candidate = normalise_url(url)
        if candidate.startswith(("http://", "https://")) and same_origin(candidate, start_url) and candidate not in queued:
            queued.add(candidate); queue.append((candidate, depth))

    # Passive discovery documents are part of the application surface.
    for path in ("/robots.txt", "/sitemap.xml", "/swagger.json", "/openapi.json"):
        add(urljoin(start_url, path), 0)

    while queue and len(visited) < max_pages:
        current, depth = queue.popleft()
        try:
            response = session.get(current, timeout=(4, 12), allow_redirects=True)
            final_url = normalise_url(str(response.url))
            if not same_origin(final_url, start_url):
                continue
            if final_url not in visited:
                visited.append(final_url)
            content_type = response.headers.get("content-type", "").lower()
            text = response.text[:2_000_000]
            if "xml" in content_type or current.endswith("sitemap.xml"):
                # Use the built-in parser so sitemap discovery never depends on lxml.
                soup = BeautifulSoup(text, "html.parser")
                for loc in soup.find_all("loc"):
                    add(loc.get_text(strip=True), depth + 1)
                continue
            if current.endswith("robots.txt"):
                for line in text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        add(line.split(":", 1)[1].strip(), depth + 1)
                continue
            if "html" not in content_type:
                continue
            soup = BeautifulSoup(text, "html.parser")
            canonical = soup.find("link", rel=lambda value: value and "canonical" in value.lower())
            if canonical and canonical.get("href"):
                add(urljoin(final_url, canonical["href"]), depth + 1)
            for tag in soup.find_all(["a", "form", "iframe", "script"]):
                reference = tag.get("href") or tag.get("action") or tag.get("src")
                if reference:
                    add(urljoin(final_url, reference), depth + 1)
            for script in soup.find_all("script", src=True):
                try:
                    source = session.get(urljoin(final_url, script["src"]), timeout=(4, 10)).text
                    for endpoint in JS_URL.findall(source):
                        add(urljoin(final_url, endpoint), depth + 1)
                except requests.RequestException:
                    continue
        except requests.RequestException:
            continue
    return visited
