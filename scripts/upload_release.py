#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Upload ShadowProxy release artifacts to GitHub via REST API.
Automatically retrieves credentials from Git Credential Manager.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")

REPO_OWNER = "jnnmia"
REPO_NAME = "shadow-proxy"
TAG_NAME = "v0.1.2"
RELEASE_NAME = "ShadowProxy v0.1.2"

def get_github_token():
    input_data = "protocol=https\nhost=github.com\n\n"
    res = subprocess.run(
        ["git", "credential", "fill"],
        input=input_data,
        capture_output=True,
        text=True,
        check=True,
    )
    for line in res.stdout.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("未能从 Git 凭据管理器获取 GitHub 访问令牌")

def api_request(url, token, data=None, method=None, content_type="application/json"):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "ShadowProxy-Release-Uploader")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if content_type:
        req.add_header("Content-Type", content_type)
    return req

def main():
    root_dir = Path(__file__).resolve().parent.parent
    dist_dir = root_dir / "dist"

    artifacts = [
        dist_dir / f"ShadowProxy-Setup-{TAG_NAME}.exe",
        dist_dir / f"ShadowProxy-{TAG_NAME}-windows-portable.zip",
        dist_dir / "SHA256SUMS.txt",
    ]

    for art in artifacts:
        if not art.is_file():
            print(f"[错误] 发布文件不存在: {art}", file=sys.stderr)
            sys.exit(1)

    checksum_text = (dist_dir / "SHA256SUMS.txt").read_text(encoding="utf-8").strip()

    print("[1/4] 获取 GitHub 凭据...")
    token = get_github_token()
    print("  √ 凭据获取成功")

    base_api = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"

    # 1. 查询是否已存在该 Tag 的 Release
    print(f"\n[2/4] 检索发行版 ({TAG_NAME})...")
    get_rel_url = f"{base_api}/releases/tags/{TAG_NAME}"
    release = None

    try:
        req = api_request(get_rel_url, token)
        with urllib.request.urlopen(req) as resp:
            release = json.loads(resp.read().decode("utf-8"))
            print(f"  √ 找到已有 Release: ID {release['id']}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("  - 未发现已有 Release，准备创建新发行版...")
        else:
            raise

    release_body = (
        f"## ShadowProxy {TAG_NAME}\n\n"
        "Windows 进程级透明代理引擎，支持 32 位与 64 位双架构程序注入、DNS 严格防泄漏与 QUIC 降级阻断。\n\n"
        "### 新增特性与改进 (v0.1.2)\n"
        "- 从 GitHub 检查更新与一键安装：\n"
        "  - 应用启动后静默自检，发现新版本时在侧边栏显示呼吸光标；\n"
        "  - 侧边栏底部常驻“检查更新”按钮与当前版本号；\n"
        "  - 暗黑赛博风更新弹窗，展示新版发布时间与更新日志；\n"
        "  - 一键后台下载安装包并拉起安装向导，内置防刷频与并发下载互斥锁；\n"
        "- 核心稳定性与安全加固：\n"
        "  - 移除 cmd.exe 调用，重构为直接调用 Windows 原生 ShellExecuteW API，杜绝命令行参数注入漏洞；\n"
        "  - 安装包路径与文件名严密白名单清洗，杜绝路径穿越；\n"
        "  - 严格限制下载源仅放行 GitHub 官方发布源，curl.exe 设置超时断开；\n"
        "  - 系统休眠挂起与唤醒恢复 (WM_POWERBROADCAST) 自愈恢复机制；\n"
        "  - 遵循零 Emoji 规范。\n\n"
        "### 产物说明\n"
        f"- **ShadowProxy-Setup-{TAG_NAME}.exe**: 单文件独立安装包，内置图形化向导，自动配置桌面与开始菜单快捷方式，支持完整控制面板卸载。\n"
        f"- **ShadowProxy-{TAG_NAME}-windows-portable.zip**: 免安装绿色便携包，解压后双击 `start-gui.bat` 即可直接使用。\n"
        "- **SHA256SUMS.txt**: 发布文件哈希校验清单。\n\n"
        "### 校验和清单 (SHA-256)\n"
        "```text\n"
        f"{checksum_text}\n"
        "```\n"
    )

    if release is None:
        create_rel_url = f"{base_api}/releases"
        payload = json.dumps({
            "tag_name": TAG_NAME,
            "target_commitish": "master",
            "name": RELEASE_NAME,
            "body": release_body,
            "draft": False,
            "prerelease": False,
        }).encode("utf-8")

        req = api_request(create_rel_url, token, data=payload, method="POST")
        with urllib.request.urlopen(req) as resp:
            release = json.loads(resp.read().decode("utf-8"))
            print(f"  √ 发行版创建成功: ID {release['id']}, URL: {release['html_url']}")
    else:
        # 更新 release 正文
        update_rel_url = f"{base_api}/releases/{release['id']}"
        payload = json.dumps({
            "name": RELEASE_NAME,
            "body": release_body,
        }).encode("utf-8")
        req = api_request(update_rel_url, token, data=payload, method="PATCH")
        with urllib.request.urlopen(req) as resp:
            release = json.loads(resp.read().decode("utf-8"))
            print(f"  √ 发行版信息已同步更新: ID {release['id']}")

    # 3. 处理已有 assets (同名则先删除)
    existing_assets = {a["name"]: a["id"] for a in release.get("assets", [])}

    print(f"\n[3/4] 上传发行版二进制产物...")
    upload_url_template = release["upload_url"].split("{")[0]

    for art in artifacts:
        name = art.name
        if name in existing_assets:
            del_url = f"{base_api}/releases/assets/{existing_assets[name]}"
            print(f"  - 删除旧版本同名文件: {name} (ID: {existing_assets[name]})...")
            req = api_request(del_url, token, method="DELETE")
            with urllib.request.urlopen(req) as resp:
                pass

        size_mb = art.stat().st_size / (1024 * 1024)
        print(f"  -> 正在上传 {name} ({size_mb:.2f} MB)...")

        file_bytes = art.read_bytes()
        upload_url = f"{upload_url_template}?name={urllib.parse.quote(name)}"
        req = api_request(
            upload_url,
            token,
            data=file_bytes,
            method="POST",
            content_type="application/octet-stream",
        )
        with urllib.request.urlopen(req) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            print(f"     √ 上传完成: {res_data['browser_download_url']}")

    print("\n[4/4] 验证与发布完成！")
    print(f"发行版公开链接: {release['html_url']}")

if __name__ == "__main__":
    main()
