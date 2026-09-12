# 2_filter_china_ip.py
import asyncio
import os
import aiodns
import geoip2.database

CHINA_CDN_KEYWORDS = [
    "kunlun",
    "aliyun",
    "alicdn",
    "dnsv1",
    "qcloud",
    "cdntip",
    "bdydns",
    "yunjiasu",
    "qiniudns",
    "chinanetcenter",
    "wswebcdn",
    "ourwebpic",
    "speedcdns",
    "upaiyun",
    "360wzb",
    "360yield",
    "incapdns",
    "anquanbao",
]

ip_db_file = "GeoLite2-Country.mmdb"
input_file = "filtered_domains.txt"
output_file = "china_final_domains.txt"

if not os.path.exists(ip_db_file) or not os.path.exists(input_file):
    print("[-] 缺失 GeoLite2-Country.mmdb 或 filtered_domains.txt！")
    exit()

reader = geoip2.database.Reader(ip_db_file)
china_domains = set()


def is_china_ip(ip_address):
    try:
        return reader.country(ip_address).country.iso_code == "CN"
    except Exception:
        return False


async def check_domain(domain, resolver, semaphore):
    async with semaphore:
        try:
            # 优先校验 CDN 域名
            try:
                cname_result = await resolver.query(domain, "CNAME")
                if cname_result and cname_result.cname:
                    cname_str = cname_result.cname.lower()
                    if any(kw in cname_str for kw in CHINA_CDN_KEYWORDS):
                        china_domains.add(domain)
                        return
            except Exception:
                pass

            # 校验 A 记录 IP 归属地
            a_result = await resolver.query(domain, "A")
            for ip_info in a_result:
                if is_china_ip(ip_info.host):
                    china_domains.add(domain)
                    break
        except Exception:
            pass


async def main():
    print("[+] 2/3 开始 DNS 归属地与 CDN 混合比对...")
    with open(input_file, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    resolver = aiodns.DNSResolver(
        nameservers=["223.5.5.5", "119.29.29.29", "180.76.76.76", "114.114.114.114"],
        timeout=1.5,
        tries=2,
    )
    semaphore = asyncio.Semaphore(400)

    tasks = [check_domain(d, resolver, semaphore) for d in domains]
    await asyncio.gather(*tasks)

    with open(output_file, "w", encoding="utf-8") as f:
        for d in sorted(china_domains):
            f.write(d + "\n")

    print(
        f"[✓] 第二阶段完成！提取国内机房/CDN 域名: {len(china_domains)} 个"
    )


if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
