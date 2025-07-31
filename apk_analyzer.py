import argparse
import os
import sys
import json
from androguard.core.bytecodes.apk import APK

def analyze_apk(apk_path):
    if not os.path.exists(apk_path):
        print(f"[!] File not found: {apk_path}")
        sys.exit(1)

    if not apk_path.endswith(".apk"):
        print(f"[!] File is not an .apk: {apk_path}")
        sys.exit(1)

    try:
        apk = APK(apk_path)
    except Exception as e:
        print(f"[!] Failed to parse APK: {e}")
        sys.exit(1)

    size_mb = os.path.getsize(apk_path) / (1024 * 1024)

    result = {
        "file": apk_path,
        "package_name": apk.get_package(),
        "version_name": apk.get_version_name(),
        "version_code": apk.get_version_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "apk_size_mb": round(size_mb, 2),
        "permissions": apk.get_permissions(),
        "activities": apk.get_activities(),
        "main_activity": apk.get_main_activity(),
    }

    return result

def print_human_readable(info):
    print("\nAPK Analyzer — Analysis of", os.path.basename(info['file']), "\n")
    print("Package Name    :", info['package_name'])
    print("Version Name    :", info['version_name'])
    print("Version Code    :", info['version_code'])
    print("Min SDK Version :", info['min_sdk'])
    print("Target SDK      :", info['target_sdk'])
    print("APK Size        :", f"{info['apk_size_mb']} MB")
    
    print("\nPermissions:")
    if info['permissions']:
        for perm in info['permissions']:
            print(" -", perm)
    else:
        print(" - None")

    print("\nActivities:")
    if info['activities']:
        for act in info['activities']:
            print(" -", act)
    else:
        print(" - None")

    print("\nMain Activity:", info['main_activity'] or "Not defined")
    print()

def save_output(info, output_path, as_json=False):
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            if as_json:
                json.dump(info, f, indent=4)
            else:
                orig_stdout = sys.stdout
                sys.stdout = f
                print_human_readable(info)
                sys.stdout = orig_stdout
        print(f"[+] Output saved to: {output_path}")
    except Exception as e:
        print(f"[!] Failed to save output: {e}")

def main():
    parser = argparse.ArgumentParser(description="📦 APK Analyzer — анализ .apk-файлов на Python")
    parser.add_argument("apk", help="Путь к .apk файлу")
    parser.add_argument("--output", "-o", help="Путь к файлу для сохранения результата")
    parser.add_argument("--json", action="store_true", help="Сохранить результат в JSON формате")

    args = parser.parse_args()

    info = analyze_apk(args.apk)
    print_human_readable(info)

    if args.output:
        save_output(info, args.output, as_json=args.json)

if __name__ == "__main__":
    main()