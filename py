import asyncio
import base64
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup


# ============================================================
# CMS Scanner V4
# Authorized asset inventory / CMS fingerprint identification
# ============================================================

URLS_FILE = Path("urls.txt")
FINGERPRINT_FILE = Path("cms_fingerprints.json")

RESULT_DIR = Path("results")
PROGRESS_FILE = RESULT_DIR / "progress.txt"
DETAILS_FILE = RESULT_DIR / "details.jsonl"
UNKNOWN_DETAILS_FILE = RESULT_DIR / "Unknown_Details.txt"

CONCURRENCY = 30
TIMEOUT = 10
RETRIES = 1

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_PROBES_PER_DOMAIN = 12

USER_AGENT = "Authorized-CMS-Inventory/4.0"


# ============================================================
# Basic helpers
# ============================================================

def normalize_url(url: str):
    url = url.strip()

    if not url:
        return None

    if url.startswith("#"):
        return None

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    return url.rstrip("/")


def load_urls():
    if not URLS_FILE.exists():
        print("[ERROR] 找不到 urls.txt")
        return []

    result = []

    for line in URLS_FILE.read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines():

        url = normalize_url(line)

        if url:
            result.append(url)

    # 去重并保持顺序
    return list(dict.fromkeys(result))


def load_fingerprints():
    if not FINGERPRINT_FILE.exists():
        raise FileNotFoundError(
            f"找不到指纹库: {FINGERPRINT_FILE}"
        )

    with FINGERPRINT_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def ensure_result_dir():
    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


def append_line(path: Path, text: str):
    with path.open(
        "a",
        encoding="utf-8"
    ) as f:
        f.write(text + "\n")


def load_progress():
    if not PROGRESS_FILE.exists():
        return set()

    return {
        x.strip()
        for x in PROGRESS_FILE.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()
        if x.strip()
    }


# ============================================================
# MurmurHash3
# ============================================================

def murmur3_32(data, seed=0):
    if isinstance(data, str):
        data = data.encode("utf-8")

    h = seed
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    length = len(data)
    rounded_end = (length & 0xFFFFFFFC)

    for i in range(0, rounded_end, 4):

        k = (
            data[i]
            | (data[i + 1] << 8)
            | (data[i + 2] << 16)
            | (data[i + 3] << 24)
        )

        k = (k * c1) & 0xFFFFFFFF

        k = (
            ((k << 15) & 0xFFFFFFFF)
            | (k >> 17)
        )

        k = (k * c2) & 0xFFFFFFFF

        h ^= k

        h = (
            ((h << 13) & 0xFFFFFFFF)
            | (h >> 19)
        )

        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    k = 0
    tail = data[rounded_end:]

    if len(tail) == 3:
        k ^= tail[2] << 16

    if len(tail) >= 2:
        k ^= tail[1] << 8

    if len(tail) >= 1:
        k ^= tail[0]

        k = (k * c1) & 0xFFFFFFFF

        k = (
            ((k << 15) & 0xFFFFFFFF)
            | (k >> 17)
        )

        k = (k * c2) & 0xFFFFFFFF

        h ^= k

    h ^= length

    h ^= h >> 16

    h = (h * 0x85EBCA6B) & 0xFFFFFFFF

    h ^= h >> 13

    h = (h * 0xC2B2AE35) & 0xFFFFFFFF

    h ^= h >> 16

    return h


def calculate_favicon_hashes(data: bytes):

    result = {}

    # MD5
    result["md5"] = hashlib.md5(data).hexdigest()

    # Base64
    b64 = base64.b64encode(data).decode(
        "ascii",
        errors="ignore"
    )

    # Wappalyzer / favicon-style wrapped Base64
    wrapped = "\n".join(
        b64[i:i + 76]
        for i in range(0, len(b64), 76)
    )

    result["murmur3_base64_wrapped"] = str(
        murmur3_32(wrapped)
    )

    result["murmur3_base64_raw"] = str(
        murmur3_32(b64)
    )

    return result


# ============================================================
# Rule parsing
# ============================================================

def get_level(weight):

    try:
        weight = int(weight)
    except Exception:
        return "weak"

    if weight >= 5:
        return "strong"

    if weight >= 3:
        return "medium"

    return "weak"


def parse_rule(rule):

    """
    支持：

    ["keyword", 5]

    ["keyword", 5, "strong"]

    ["field", "keyword", 5]

    ["field", "keyword", 5, "strong"]
    """

    if not isinstance(rule, list):
        return None

    if len(rule) == 2:

        keyword = str(rule[0])
        weight = int(rule[1])

        return {
            "field": "html",
            "keyword": keyword,
            "weight": weight,
            "level": get_level(weight)
        }

    if len(rule) == 3:

        if rule[0] in {
            "html",
            "meta",
            "title",
            "resources",
            "headers",
            "cookies",
            "robots",
            "favicon"
        }:

            field = str(rule[0])
            keyword = str(rule[1])
            weight = int(rule[2])

            return {
                "field": field,
                "keyword": keyword,
                "weight": weight,
                "level": get_level(weight)
            }

        keyword = str(rule[0])
        weight = int(rule[1])

        return {
            "field": "html",
            "keyword": keyword,
            "weight": weight,
            "level": str(rule[2])
        }

    if len(rule) >= 4:

        return {
            "field": str(rule[0]),
            "keyword": str(rule[1]),
            "weight": int(rule[2]),
            "level": str(rule[3])
        }

    return None


# ============================================================
# HTTP Scanner
# ============================================================

class Scanner:

    def __init__(self, fingerprints):

        self.fingerprints = fingerprints

        self.semaphore = asyncio.Semaphore(
            CONCURRENCY
        )

        self.session = None

    # --------------------------------------------------------
    # HTTP request
    # --------------------------------------------------------

    async def fetch(
        self,
        url,
        method="GET"
    ):

        async with self.semaphore:

            for attempt in range(RETRIES + 1):

                try:

                    timeout = aiohttp.ClientTimeout(
                        total=TIMEOUT
                    )

                    async with self.session.request(
                        method,
                        url,
                        allow_redirects=True,
                        timeout=timeout,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "*/*"
                        }
                    ) as response:

                        headers = dict(
                            response.headers
                        )

                        final_url = str(
                            response.url
                        )

                        if method == "HEAD":

                            return {
                                "status": response.status,
                                "headers": headers,
                                "body": b"",
                                "url": final_url,
                                "cookies": response.cookies
                            }

                        body = await response.content.read(
                            MAX_BODY_BYTES
                        )

                        return {
                            "status": response.status,
                            "headers": headers,
                            "body": body,
                            "url": final_url,
                            "cookies": response.cookies
                        }

                except Exception:

                    if attempt < RETRIES:
                        await asyncio.sleep(0.3)

    return {
        "status": 0,
        "headers": {},
        "body": b"",
        "url": url,
        "cookies": {}
    }


# ============================================================
# HTML evidence extraction
# ============================================================

def extract_evidence(
    body: bytes,
    headers,
    cookies
):

    text = body.decode(
        "utf-8",
        errors="ignore"
    )

    soup = BeautifulSoup(
        text,
        "html.parser"
    )

    # HTML正文
    visible_text = soup.get_text(
        " ",
        strip=True
    )

    # HTML + visible text
    html_content = (
        text
        + "\n"
        + visible_text
    ).lower()

    # --------------------------------------------------------
    # Comments
    # --------------------------------------------------------

    comments = []

    for node in soup.find_all(
        string=lambda x:
        isinstance(x, type(soup.string))
    ):
        pass

    comments = re.findall(
        r"<!--(.*?)-->",
        text,
        re.S
    )

    comment_text = " ".join(
        comments
    ).lower()

    # --------------------------------------------------------
    # Meta
    # --------------------------------------------------------

    meta_values = []

    for meta in soup.find_all("meta"):

        name = meta.get(
            "name",
            ""
        )

        content = meta.get(
            "content",
            ""
        )

        meta_values.append(
            str(name)
        )

        meta_values.append(
            str(content)
        )

    meta_text = " ".join(
        meta_values
    ).lower()

    # --------------------------------------------------------
    # Title
    # --------------------------------------------------------

    title = ""

    if soup.title:

        title = soup.title.get_text(
            " ",
            strip=True
        )

    title = title.lower()

    # --------------------------------------------------------
    # JS / CSS / image / link resources
    # --------------------------------------------------------

    resources = []

    for tag in soup.find_all(
        ["script", "link", "img", "a"]
    ):

        for attr in (
            "src",
            "href",
            "data-src"
        ):

            value = tag.get(attr)

            if value:
                resources.append(
                    str(value)
                )

    resource_text = " ".join(
        resources
    ).lower()

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    header_parts = []

    for key, value in headers.items():

        header_parts.append(
            f"{key}:{value}"
        )

    header_text = " ".join(
        header_parts
    ).lower()

    # --------------------------------------------------------
    # Cookies
    # --------------------------------------------------------

    cookie_names = []

    try:

        for key in cookies.keys():

            cookie_names.append(
                str(key)
            )

    except Exception:
        pass

    cookie_text = " ".join(
        cookie_names
    ).lower()

    return {
        "html": html_content,
        "comments": comment_text,
        "meta": meta_text,
        "title": title,
        "resources": resource_text,
        "headers": header_text,
        "cookies": cookie_text,
        "status": None
    }


# ============================================================
# Field matching
# ============================================================

def match_keyword(
    field_text,
    keyword
):

    if not field_text:
        return False

    return keyword.lower() in field_text.lower()


def favicon_rule_matches(
    favicon_hashes,
    keyword
):

    keyword = str(keyword).strip()

    return any(
        keyword == str(value)
        for value in favicon_hashes.values()
    )


# ============================================================
# Negative fingerprint
# ============================================================

def apply_negative_rules(
    cms_name,
    cms_rules,
    evidence
):

    negative_rules = cms_rules.get(
        "negative",
        []
    )

    hits = []

    for rule in negative_rules:

        parsed = parse_rule(rule)

        if not parsed:
            continue

        field = parsed["field"]
        keyword = parsed["keyword"]

        if field == "favicon":

            if favicon_rule_matches(
                evidence.get("favicon", {}),
                keyword
            ):
                hits.append(parsed)

        else:

            value = evidence.get(
                field,
                ""
            )

            if match_keyword(
                value,
                keyword
            ):
                hits.append(parsed)

    return hits


# ============================================================
# Score engine
# ============================================================

def score_all(
    evidence
):

    scores = {}

    for cms_name, rules in self_fingerprints.items():

        score = 0
        hits = []
        seen = set()

        # ---------------------------------------------
        # Positive fingerprints
        # ---------------------------------------------

        for field_name, rule_list in rules.items():

            if field_name in {
                "threshold",
                "margin",
                "negative",
                "admin_paths",
                "probe"
            }:
                continue

            if not isinstance(
                rule_list,
                list
            ):
                continue

            for rule in rule_list:

                parsed = parse_rule(rule)

                if not parsed:
                    continue

                field = parsed["field"]
                keyword = parsed["keyword"]
                weight = parsed["weight"]
                level_name = parsed["level"]

                hit = False

                if field == "favicon":

                    hit = favicon_rule_matches(
                        evidence.get(
                            "favicon",
                            {}
                        ),
                        keyword
                    )

                else:

                    field_text = evidence.get(
                        field,
                        ""
                    )

                    hit = match_keyword(
                        field_text,
                        keyword
                    )

                if not hit:
                    continue

                # 同一CMS相同字段+关键词只计一次
                key = (
                    field,
                    keyword.lower()
                )

                if key in seen:
                    continue

                seen.add(key)

                score += weight

                hits.append({
                    "field": field,
                    "keyword": keyword,
                    "weight": weight,
                    "level": level_name
                })

        # ---------------------------------------------
        # Negative fingerprints
        # ---------------------------------------------

        negative_hits = apply_negative_rules(
            cms_name,
            rules,
            evidence
        )

        negative_score = 0

        for hit in negative_hits:

            negative_score += hit["weight"]

            hits.append({
                "field": "negative:" + hit["field"],
                "keyword": hit["keyword"],
                "weight": -hit["weight"],
                "level": hit["level"]
            })

        score -= negative_score

        scores[cms_name] = {
            "score": max(score, 0),
            "positive_score": score + negative_score,
            "negative_score": negative_score,
            "hits": hits
        }

    return scores


# ============================================================
# Decision
# ============================================================

def decide(
    scores,
    fingerprints
):

    if not scores:

        return {
            "cms": "Unknown",
            "reason": "没有可用指纹"
        }

    ordered = sorted(
        scores.items(),
        key=lambda item:
        item[1]["score"],
        reverse=True
    )

    best_name = ordered[0][0]
    best_score = ordered[0][1]["score"]

    second_score = 0

    if len(ordered) > 1:
        second_score = ordered[1][1]["score"]

    rules = fingerprints.get(
        best_name,
        {}
    )

    threshold = int(
        rules.get(
            "threshold",
            999
        )
    )

    margin = int(
        rules.get(
            "margin",
            3
        )
    )

    if best_score < threshold:

        return {
            "cms": "Unknown",
            "reason": (
                f"最高分不足阈值: "
                f"{best_score} < {threshold}"
            )
        }

    if (
        best_score - second_score
        < margin
    ):

        return {
            "cms": "Unknown",
            "reason": (
                f"Top1与Top2差距不足: "
                f"{best_score}-{second_score}"
                f" < {margin}"
            )
        }

    return {
        "cms": best_name,
        "reason": (
            f"score={best_score}, "
            f"second={second_score}, "
            f"threshold={threshold}, "
            f"margin={margin}"
        )
    }


# ============================================================
# Public favicon
# ============================================================

async def get_favicon(
    scanner,
    base_url
):

    favicon_url = urljoin(
        base_url + "/",
        "favicon.ico"
    )

    result = await scanner.fetch(
        favicon_url
    )

    if result["status"] <= 0:
        return {}

    if not result["body"]:
        return {}

    return {
        "url": favicon_url,
        "status": result["status"],
        "hashes": calculate_favicon_hashes(
            result["body"]
        )
    }


# ============================================================
# robots.txt
# ============================================================

async def get_robots(
    scanner,
    base_url
):

    url = urljoin(
        base_url + "/",
        "robots.txt"
    )

    result = await scanner.fetch(
        url
    )

    if result["status"] <= 0:
        return {
            "url": url,
            "status": 0,
            "text": ""
        }

    text = result["body"].decode(
        "utf-8",
        errors="ignore"
    )

    return {
        "url": url,
        "status": result["status"],
        "text": text.lower()
    }


# ============================================================
# Public probe
# ============================================================

async def run_probes(
    scanner,
    base_url,
    cms_name,
    fingerprints
):

    rules = fingerprints.get(
        cms_name,
        {}
    )

    probe_rules = rules.get(
        "probe",
        []
    )

    results = []

    if not isinstance(
        probe_rules,
        list
    ):
        return results

    probe_rules = probe_rules[
        :MAX_PROBES_PER_DOMAIN
    ]

    for rule in probe_rules:

        parsed = parse_rule(rule)

        if not parsed:
            continue

        path = parsed["keyword"]

        probe_url = urljoin(
            base_url + "/",
            path.lstrip("/")
        )

        response = await scanner.fetch(
            probe_url,
            method="GET"
        )

        results.append({
            "path": path,
            "url": probe_url,
            "status": response["status"],
            "exists": (
                response["status"] > 0
                and response["status"] not in {
                    404,
                    410
                }
            ),
            "weight": parsed["weight"],
            "level": parsed["level"]
        })

    return results


# ============================================================
# Admin existence
# ============================================================

async def check_admin_paths(
    scanner,
    base_url,
    cms_name,
    fingerprints
):

    rules = fingerprints.get(
        cms_name,
        {}
    )

    admin_paths = rules.get(
        "admin_paths",
        []
    )

    results = []

    if not isinstance(
        admin_paths,
        list
    ):
        return results

    for path in admin_paths:

        admin_url = urljoin(
            base_url + "/",
            str(path).lstrip("/")
        )

        response = await scanner.fetch(
            admin_url,
            method="GET"
        )

        results.append({
            "path": path,
            "url": admin_url,
            "status": response["status"],
            "exists": (
                response["status"] > 0
                and response["status"] not in {
                    404,
                    410
                }
            )
        })

    return results


# ============================================================
# Main single URL scan
# ============================================================

async def scan_url(
    scanner,
    url,
    fingerprints
):

    started = time.time()

    # --------------------------------------------------------
    # Homepage
    # --------------------------------------------------------

    response = await scanner.fetch(
        url,
        method="GET"
    )

    # HTTPS fallback
    if (
        response["status"] <= 0
        and url.startswith("https://")
    ):

        http_url = (
            "http://"
            + url[len("https://"):]
        )

        response = await scanner.fetch(
            http_url,
            method="GET"
        )

    final_url = response["url"]

    evidence = extract_evidence(
        response["body"],
        response["headers"],
        response["cookies"]
    )

    evidence["status"] = response["status"]

    # --------------------------------------------------------
    # Robots
    # --------------------------------------------------------

    robots = await get_robots(
        scanner,
        final_url
    )

    evidence["robots"] = robots["text"]

    # --------------------------------------------------------
    # Favicon
    # --------------------------------------------------------

    favicon = await get_favicon(
        scanner,
        final_url
    )

    evidence["favicon"] = (
        favicon.get(
            "hashes",
            {}
        )
    )

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    global self_fingerprints

    self_fingerprints = fingerprints

    scores = score_all(
        evidence
    )

    decision = decide(
        scores,
        fingerprints
    )

    cms_name = decision["cms"]

    # --------------------------------------------------------
    # Probe
    # --------------------------------------------------------

    probe_results = []

    # 只对当前最高候选做公共特征确认
    if cms_name != "Unknown":

        probe_results = await run_probes(
            scanner,
            final_url,
            cms_name,
            fingerprints
        )

    # --------------------------------------------------------
    # Admin existence
    # --------------------------------------------------------

    admin_results = []

    if cms_name != "Unknown":

        admin_results = await check_admin_paths(
            scanner,
            final_url,
            cms_name,
            fingerprints
        )

    # --------------------------------------------------------
    # Strong / Medium / Weak evidence
    # --------------------------------------------------------

    strong = []
    medium = []
    weak = []

    if cms_name in scores:

        for hit in scores[cms_name]["hits"]:

            if hit["weight"] < 0:
                continue

            if hit["level"] == "strong":
                strong.append(hit)

            elif hit["level"] == "medium":
                medium.append(hit)

            else:
                weak.append(hit)

    elapsed = round(
        time.time() - started,
        3
    )

    return {
        "url": url,
        "final_url": final_url,
        "status": response["status"],
        "cms": cms_name,
        "reason": decision["reason"],
        "elapsed": elapsed,

        "score": (
            scores.get(
                cms_name,
                {}
            ).get(
                "score",
                0
            )
            if cms_name != "Unknown"
            else 0
        ),

        "evidence": {
            "strong": strong,
            "medium": medium,
            "weak": weak
        },

        "scores": scores,

        "robots": {
            "status": robots["status"],
            "url": robots["url"]
        },

        "favicon": favicon,

        "probes": probe_results,

        "admin_paths": admin_results
    }


# ============================================================
# Save result
# ============================================================

def save_result(result):

    cms_name = result["cms"]

    # CMS TXT
    cms_file = (
        RESULT_DIR
        / f"{cms_name}.txt"
    )

    append_line(
        cms_file,
        result["url"]
    )

    # Unknown details
    if cms_name == "Unknown":

        append_line(
            UNKNOWN_DETAILS_FILE,
            json.dumps(
                result,
                ensure_ascii=False
            )
        )

    # Full JSONL
    append_line(
        DETAILS_FILE,
        json.dumps(
            result,
            ensure_ascii=False
        )
    )

    # Progress
    append_line(
        PROGRESS_FILE,
        result["url"]
    )


# ============================================================
# Batch worker
# ============================================================

async def worker(
    scanner,
    url,
    fingerprints
):

    try:

        result = await scan_url(
            scanner,
            url,
            fingerprints
        )

        save_result(
            result
        )

        print(
            f"[{result['cms']}] "
            f"{result['status']} "
            f"{url}"
        )

        return result

    except Exception as e:

        result = {
            "url": url,
            "cms": "Unknown",
            "reason": f"scanner_error: {e}"
        }

        append_line(
            UNKNOWN_DETAILS_FILE,
            json.dumps(
                result,
                ensure_ascii=False
            )
        )

        append_line(
            PROGRESS_FILE,
            url
        )

        print(
            f"[ERROR] {url}: {e}"
        )

        return result


# ============================================================
# Main
# ============================================================

async def main():

    ensure_result_dir()

    print("=" * 60)
    print("CMS Scanner V4")
    print("Authorized Asset Inventory")
    print("=" * 60)

    urls = load_urls()

    if not urls:

        print(
            "urls.txt 没有可扫描的 URL。"
        )

        return

    fingerprints = load_fingerprints()

    progress = load_progress()

    todo = [
        url
        for url in urls
        if url not in progress
    ]

    print(
        f"URL总数: {len(urls)}"
    )

    print(
        f"已完成: {len(progress)}"
    )

    print(
        f"待扫描: {len(todo)}"
    )

    print(
        f"并发数: {CONCURRENCY}"
    )

    if not todo:

        print(
            "全部 URL 已完成。"
        )

        return

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY,
        limit_per_host=5,
        ssl=False
    )

    async with aiohttp.ClientSession(
        connector=connector
    ) as session:

        scanner = Scanner(
            fingerprints
        )

        scanner.session = session

        # 有界批处理
        batch_size = CONCURRENCY * 4

        total = len(todo)

        for start in range(
            0,
            total,
            batch_size
        ):

            batch = todo[
                start:
                start + batch_size
            ]

            print(
                f"\n批次: "
                f"{start + 1}-"
                f"{start + len(batch)}"
                f"/{total}"
            )

            await asyncio.gather(
                *[
                    worker(
                        scanner,
                        url,
                        fingerprints
                    )
                    for url in batch
                ]
            )

    print()
    print("=" * 60)
    print("扫描完成")
    print("=" * 60)

    print(
        f"结果目录: {RESULT_DIR.resolve()}"
    )


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":

    try:

        asyncio.run(
            main()
        )

    except KeyboardInterrupt:

        print()
        print(
            "用户停止扫描。"
        )

        print(
            "再次运行会根据 "
            "results/progress.txt "
            "继续。"
        )
