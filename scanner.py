import asyncio
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup


# =========================
# 基础配置
# =========================

BASE_DIR = Path(__file__).resolve().parent

URLS_FILE = BASE_DIR / "urls.txt"
FINGERPRINT_FILE = BASE_DIR / "cms_fingerprints.json"
RESULT_DIR = BASE_DIR / "results"
PROGRESS_FILE = BASE_DIR / "progress.txt"

CONCURRENCY = 30
TIMEOUT = 10
RETRIES = 1

USER_AGENT = "Authorized-CMS-Inventory/1.0"

RESULT_DIR.mkdir(exist_ok=True)


# =========================
# URL处理
# =========================

def normalize_url(url):
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
        print("错误：没有找到 urls.txt")
        return []

    urls = []
    seen = set()

    with URLS_FILE.open(
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        for line in f:
            url = normalize_url(line)

            if url and url not in seen:
                seen.add(url)
                urls.append(url)

    return urls


# =========================
# 断点续跑
# =========================

def load_progress():
    completed = set()

    if not PROGRESS_FILE.exists():
        return completed

    with PROGRESS_FILE.open(
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        for line in f:
            line = line.strip()

            if line:
                completed.add(line)

    return completed


def save_progress(url):
    with PROGRESS_FILE.open(
        "a",
        encoding="utf-8"
    ) as f:

        f.write(url + "\n")


# =========================
# 指纹库
# =========================

def load_fingerprints():

    if not FINGERPRINT_FILE.exists():
        print("错误：没有找到 cms_fingerprints.json")
        return {}

    with FINGERPRINT_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


# =========================
# HTML分析
# =========================

def parse_html(html):

    soup = BeautifulSoup(
        html or "",
        "html.parser"
    )

    # 页面文本
    text = soup.get_text(
        " ",
        strip=True
    )

    # HTML注释
    comments = " ".join(
        re.findall(
            r"<!--(.*?)-->",
            html or "",
            re.S
        )
    )

    html_text = text + " " + comments

    # Meta
    meta_items = []

    for tag in soup.find_all("meta"):

        name = tag.get("name", "")
        property_name = tag.get("property", "")
        content = tag.get("content", "")

        meta_items.append(
            f"{name} {property_name} {content}"
        )

    meta_text = " ".join(meta_items)

    # 页面公开资源
    resources = []

    resource_tags = [
        ("script", "src"),
        ("link", "href"),
        ("img", "src"),
        ("iframe", "src"),
        ("source", "src"),
    ]

    for tag_name, attribute in resource_tags:

        for tag in soup.find_all(tag_name):

            value = tag.get(attribute)

            if value:
                resources.append(value)

    return (
        html_text,
        meta_text,
        resources
    )


# =========================
# 指纹匹配
# =========================

def match_fingerprints(
    fingerprints,
    html_text,
    meta_text,
    resources,
    headers,
    cookies,
    robots
):

    scores = {}
    matched_rules = {}

    html_lower = html_text.lower()
    meta_lower = meta_text.lower()

    resource_list = [
        str(x).lower()
        for x in resources
    ]

    header_map = {
        str(k).lower(): str(v).lower()
        for k, v in headers.items()
    }

    cookie_names = [
        str(k).lower()
        for k in cookies.keys()
    ]

    robots_lower = (
        robots or ""
    ).lower()

    for cms, rules in fingerprints.items():

        score = 0
        matches = []

        # -------------------------
        # HTML
        # -------------------------

        for rule in rules.get(
            "html",
            []
        ):

            pattern = str(rule[0])
            weight = int(rule[1])

            if pattern.lower() in html_lower:

                score += weight

                matches.append(
                    f"HTML:{pattern}(+{weight})"
                )

        # -------------------------
        # META
        # -------------------------

        for rule in rules.get(
            "meta",
            []
        ):

            pattern = str(rule[0])
            weight = int(rule[1])

            if pattern.lower() in meta_lower:

                score += weight

                matches.append(
                    f"META:{pattern}(+{weight})"
                )

        # -------------------------
        # Resources
        # -------------------------

        for rule in rules.get(
            "resources",
            []
        ):

            pattern = str(rule[0])
            weight = int(rule[1])

            pattern_lower = pattern.lower()

            if any(
                pattern_lower in resource
                for resource in resource_list
            ):

                score += weight

                matches.append(
                    f"RESOURCE:{pattern}(+{weight})"
                )

        # -------------------------
        # Headers
        # -------------------------

        for rule in rules.get(
            "headers",
            []
        ):

            if len(rule) < 3:
                continue

            header_name = str(rule[0]).lower()
            pattern = str(rule[1]).lower()
            weight = int(rule[2])

            value = header_map.get(
                header_name,
                ""
            )

            if pattern in value:

                score += weight

                matches.append(
                    f"HEADER:{header_name}:{pattern}(+{weight})"
                )

        # -------------------------
        # Cookies
        # -------------------------

        for rule in rules.get(
            "cookies",
            []
        ):

            pattern = str(rule[0])
            weight = int(rule[1])

            pattern_lower = pattern.lower()

            if any(
                pattern_lower in cookie
                for cookie in cookie_names
            ):

                score += weight

                matches.append(
                    f"COOKIE:{pattern}(+{weight})"
                )

        # -------------------------
        # Robots
        # -------------------------

        for rule in rules.get(
            "robots",
            []
        ):

            pattern = str(rule[0])
            weight = int(rule[1])

            if pattern.lower() in robots_lower:

                score += weight

                matches.append(
                    f"ROBOTS:{pattern}(+{weight})"
                )

        # -------------------------
        # Negative rules
        # -------------------------

        negative_hit = False

        for rule in rules.get(
            "negative",
            []
        ):

            pattern = str(rule[0])

            if pattern.lower() in html_lower:

                negative_hit = True

                matches.append(
                    f"NEGATIVE:{pattern}"
                )

        if negative_hit:

            score = 0

        scores[cms] = score
        matched_rules[cms] = matches

    return (
        scores,
        matched_rules
    )


# =========================
# 最终判断
# =========================

def decide_cms(
    scores,
    fingerprints
):

    if not scores:
        return (
            "Unknown",
            0,
            0,
            0,
            "Unknown"
        )

    ranked = sorted(
        scores.items(),
        key=lambda x: x[1],
        reverse=True
    )

    top_cms = ranked[0][0]
    top_score = ranked[0][1]

    second_score = (
        ranked[1][1]
        if len(ranked) > 1
        else 0
    )

    margin = (
        top_score -
        second_score
    )

    rules = fingerprints[top_cms]

    threshold = int(
        rules.get(
            "threshold",
            5
        )
    )

    required_margin = int(
        rules.get(
            "margin",
            2
        )
    )

    # 分数不够
    if top_score < threshold:

        return (
            "Unknown",
            top_score,
            second_score,
            margin,
            "Unknown"
        )

    # 第一名优势不够
    if margin < required_margin:

        return (
            "Unknown",
            top_score,
            second_score,
            margin,
            "Unknown"
        )

    # 这里的 Confidence
    # 是内部证据等级，不是概率
    ratio = (
        top_score /
        max(threshold, 1)
    )

    if (
        ratio >= 2
        and margin >= required_margin + 3
    ):

        confidence = "High"

    elif ratio >= 1.3:

        confidence = "Medium"

    else:

        confidence = "Low"

    return (
        top_cms,
        top_score,
        second_score,
        margin,
        confidence
    )


# =========================
# HTTP请求
# =========================

async def fetch(
    session,
    url
):

    last_error = ""

    for attempt in range(
        RETRIES + 1
    ):

        try:

            start = time.perf_counter()

            async with session.get(
                url,
                allow_redirects=True,
                max_redirects=5,
                timeout=aiohttp.ClientTimeout(
                    total=TIMEOUT
                )
            ) as response:

                body = await response.text(
                    errors="ignore"
                )

                elapsed = (
                    time.perf_counter()
                    - start
                )

                return {
                    "body": body,
                    "headers": response.headers,
                    "cookies": response.cookies,
                    "status": response.status,
                    "final_url": str(response.url),
                    "elapsed": elapsed,
                    "error": ""
                }

        except Exception as e:

            last_error = str(e)

            await asyncio.sleep(
                0.2 *
                (attempt + 1)
            )

    return {
        "body": "",
        "headers": {},
        "cookies": {},
        "status": 0,
        "final_url": url,
        "elapsed": 0,
        "error": last_error
    }


# =========================
# 单个URL
# =========================

async def scan_one(
    session,
    url,
    fingerprints
):

    response = await fetch(
        session,
        url
    )

    # HTTPS失败时尝试HTTP
    if (
        response["status"] == 0
        and url.lower().startswith(
            "https://"
        )
    ):

        http_url = (
            "http://" +
            url[8:]
        )

        response = await fetch(
            session,
            http_url
        )

    body = response["body"]

    if not body:

        return {
            "url": url,
            "cms": "Unknown",
            "score": 0,
            "second_score": 0,
            "margin": 0,
            "confidence": "Unknown",
            "matched": [],
            "status": response["status"],
            "time": response["elapsed"],
            "error": response["error"]
        }

    (
        html_text,
        meta_text,
        resources
    ) = parse_html(body)

    # 第一轮：不读取 robots
    (
        scores,
        matched
    ) = match_fingerprints(
        fingerprints,
        html_text,
        meta_text,
        resources,
        response["headers"],
        response["cookies"],
        ""
    )

    (
        cms,
        score,
        second_score,
        margin,
        confidence
    ) = decide_cms(
        scores,
        fingerprints
    )

    # 只有 Unknown 才读取 robots.txt
    if cms == "Unknown":

        robots_url = urljoin(
            response["final_url"],
            "/robots.txt"
        )

        robots_response = await fetch(
            session,
            robots_url
        )

        robots = robots_response["body"]

        if robots:

            (
                scores,
                matched
            ) = match_fingerprints(
                fingerprints,
                html_text,
                meta_text,
                resources,
                response["headers"],
                response["cookies"],
                robots
            )

            (
                cms,
                score,
                second_score,
                margin,
                confidence
            ) = decide_cms(
                scores,
                fingerprints
            )

    return {
        "url": url,
        "cms": cms,
        "score": score,
        "second_score": second_score,
        "margin": margin,
        "confidence": confidence,
        "matched": matched.get(
            cms,
            []
        ),
        "status": response["status"],
        "time": response["elapsed"],
        "error": response["error"]
    }


# =========================
# 写入TXT
# =========================

def write_result(result):

    cms = result["cms"]

    output_file = (
        RESULT_DIR /
        f"{cms}.txt"
    )

    with output_file.open(
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            result["url"] +
            "\n"
        )


# =========================
# 主程序
# =========================

async def main():

    print("=" * 60)
    print("CMS Scanner V3")
    print("Authorized CMS Inventory")
    print("=" * 60)

    urls = load_urls()

    if not urls:

        print(
            "urls.txt 没有可处理的 URL。"
        )

        return

    fingerprints = load_fingerprints()

    if not fingerprints:

        return

    completed = load_progress()

    pending = [
        url
        for url in urls
        if url not in completed
    ]

    print(
        f"总URL: {len(urls)}"
    )

    print(
        f"已完成: {len(completed)}"
    )

    print(
        f"待处理: {len(pending)}"
    )

    print(
        f"并发: {CONCURRENCY}"
    )

    print("=" * 60)

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY,
        limit_per_host=3,
        ttl_dns_cache=300
    )

    timeout = aiohttp.ClientTimeout(
        total=TIMEOUT
    )

    headers = {
        "User-Agent": USER_AGENT
    }

    semaphore = asyncio.Semaphore(
        CONCURRENCY
    )

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=headers
    ) as session:

        async def worker(url):

            async with semaphore:

                result = await scan_one(
                    session,
                    url,
                    fingerprints
                )

                write_result(
                    result
                )

                save_progress(
                    url
                )

                return result

        total = len(pending)

        finished = 0

        # 分批创建任务，避免10万条一次性进入内存
        batch_size = (
            CONCURRENCY * 4
        )

        for start in range(
            0,
            total,
            batch_size
        ):

            batch = pending[
                start:
                start + batch_size
            ]

            results = await asyncio.gather(
                *[
                    worker(url)
                    for url in batch
                ],
                return_exceptions=True
            )

            for result in results:

                finished += 1

                if isinstance(
                    result,
                    Exception
                ):

                    print(
                        f"[{finished}/{total}] "
                        f"任务异常: {result}"
                    )

                    continue

                print(
                    f"[{finished}/{total}] "
                    f"{result['url']} -> "
                    f"{result['cms']} "
                    f"score={result['score']} "
                    f"margin={result['margin']} "
                    f"time={result['time']:.2f}s"
                )

    print()
    print("=" * 60)
    print("扫描完成")
    print(
        f"结果目录: {RESULT_DIR}"
    )
    print("=" * 60)


if __name__ == "__main__":

    try:
        asyncio.run(
            main()
        )

    except KeyboardInterrupt:

        print()
        print(
            "程序已停止。"
        )

        print(
            "再次运行 start.bat "
            "会从 progress.txt 继续。"
        )
