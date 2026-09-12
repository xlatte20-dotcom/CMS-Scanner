# 1_get_china_domains.py
import time
import urllib.request

# 核心要拉取的 3 个国内开源数据源路径
RAW_PATHS = [
    "felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
    "Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
    "v2fly/domain-list-community/master/data/cn",
]

# 3 个国内 GitHub 加速镜像通道（主备轮询）
MIRROR_PREFIXES = [
    "https://ghfast.top/https://raw.githubusercontent.com/",
    "https://ghproxy.net/https://raw.githubusercontent.com/",
    "https://raw.bsproxy.cn/",
]

output_file = "filtered_domains.txt"
all_domains = set()

print("[+] 1/3 开始拉取 3 个国内基础域名库（开启防波动重试机制）...")


def fetch_with_retry(raw_path, max_retries=3):
    """尝试使用不同镜像源拉取数据，带重试逻辑"""
    for mirror in MIRROR_PREFIXES:
        url = mirror + raw_path
        mirror_name = mirror.split("//")[1].split("/")[0]

        for attempt in range(1, max_retries + 1):
            try:
                print(
                    f"[+] 尝试通过 [{mirror_name}] 拉取 (第 {attempt}/{max_retries} 次)..."
                )
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                    },
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        content = response.read().decode("utf-8", errors="ignore")
                        print(f"[✓] [{mirror_name}] 拉取成功！")
                        return content
            except Exception as e:
                print(f"[-] [{mirror_name}] 请求失败: {e}")
                time.sleep(2)

        print(f"[!] 镜像 [{mirror_name}] 不可用，正在尝试下一个备用镜像...")

    return None


for path in RAW_PATHS:
    target_name = path.split("/")[0]
    print(f"\n---> 开始拉取源: {target_name}")

    content = fetch_with_retry(path)
    if not content:
        print(
            f"[✕] 警告: 任务 {target_name} 所有镜像源均拉取失败，跳过该源！"
        )
        continue

    count_before = len(all_domains)
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue

        if "server=/" in line:
            domain = line.split("/")[1]
        elif ":" in line:
            domain = line.split(":")[-1]
        else:
            domain = line

        domain = domain.split("/")[0].strip().lower()

        # 排除静态规则与政企/教育 TLD
        if "." in domain and not domain.endswith(
            (".gov", ".gov.cn", ".edu", ".edu.cn")
        ):
            all_domains.add(domain)

    added = len(all_domains) - count_before
    print(f"[✓] {target_name} 解析完成，贡献独立域名: {added} 个")

# 导出汇总去重后的域名列表
with open(output_file, "w", encoding="utf-8") as f:
    for d in sorted(all_domains):
        f.write(d + "\n")

print("\n" + "=" * 50)
print(f"[✓] 第一阶段全部完成！最终聚合有效国内域名: {len(all_domains)} 个")
print(f"[✓] 结果已更新至: {output_file}")
print("=" * 50)
