# 3_filter_chinese_web.py
import asyncio
import os
import re
import aiohttp

input_file = "china_final_domains.txt"
output_file = "chinese_only_domains.txt"

if not os.path.exists(input_file):
    print(f"[-] 未找到 {input_file}，请先运行第二阶段脚本！")
    exit()

chinese_domains = set()
ZH_PATTERN = re.compile(r"[\u4e00-\u9fa5]")


def is_chinese_text(text, min_chinese_chars=5):
    if not text:
        return False
    return len(ZH_PATTERN.findall(text)) >= min_chinese_chars


async def check_chinese_site(domain, session, semaphore):
    async with semaphore:
        for scheme in ["https://", "http://"]:
            url = f"{scheme}{domain}"
            try:
                async with session.get(
                    url, timeout=2.5, ssl=False, headers={"User-Agent": "Mozilla/5.0"}
                ) as resp:
                    if resp.status < 400:
                        content_bytes = await resp.content.read(10240)
                        html = ""
                        for encoding in ["utf-8", "gbk", "gb2312", "gb18030"]:
                            try:
                                html = content_bytes.decode(encoding)
                                break
                            except Exception:
                                continue

                        if (
                            'lang="zh' in html.lower()
                            or "lang='zh" in html.lower()
                        ):
                            chinese_domains.add(domain)
                            return

                        if is_chinese_text(html, min_chinese_chars=5):
                            chinese_domains.add(domain)
                            return
            except Exception:
                continue


async def main():
    print("[+] 3/3 开始 HTTP 存活与中文内容特征识别...")
    with open(input_file, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    connector = aiohttp.TCPConnector(ssl=False, limit=0)
    semaphore = asyncio.Semaphore(300)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            check_chinese_site(domain, session, semaphore) for domain in domains
        ]
        await asyncio.gather(*tasks)

    with open(output_file, "w", encoding="utf-8") as f:
        for d in sorted(chinese_domains):
            f.write(d + "\n")

    print(
        f"[✓] 流程全部结束！成功导出最终【纯中文 Web 目标库】: {len(chinese_domains)} 个"
    )


if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
