# daily_run.py
import subprocess
import sys


def run_script(script_name):
    print(f"\n==================== 开始执行: {script_name} ====================")
    result = subprocess.run([sys.executable, script_name])
    if result.returncode != 0:
        print(f"[-] {script_name} 执行失败，流程中断！")
        sys.exit(1)


if __name__ == "__main__":
    run_script("1_get_china_domains.py")
    run_script("2_filter_china_ip.py")
    run_script("3_filter_chinese_web.py")

    print("\n" + "=" * 60)
    print(
        "[✓] 每日全流程自动提纯完成！最终成果已更新至: chinese_only_domains.txt"
    )
    print("=" * 60)
