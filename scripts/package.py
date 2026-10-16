#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowProxy Release Packaging Script.
Automates staging, portable ZIP compression, installer script generation,
checksum calculation, and optional Inno Setup compilation.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")

APP_NAME = "ShadowProxy"
APP_VERSION = "0.2.1"
APP_DESCRIPTION = "Windows 进程级透明代理引擎"
PUBLISHER = "ShadowProxy Team"
HOMEPAGE = "https://github.com/jnnmia/shadow-proxy"

REQUIRED_BINARIES = [
    "shadow-gui.exe",
    "shadow-cli.exe",
    "shadow_hook.dll",
    "shadow_hook32.dll",
    "shadow-injector32.exe",
    "WebView2Loader.dll",
]

INSTALL_PS1_CONTENT = r'''# ShadowProxy 一键安装脚本
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$appName = "ShadowProxy"
$appVersion = "0.2.1"
$sourceDir = $PSScriptRoot
$installDir = Join-Path $env:LOCALAPPDATA "Programs\$appName"
$isZh = ([System.Globalization.CultureInfo]::CurrentUICulture.Name -like "zh*")

if ($isZh) {
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "       ShadowProxy 进程级透明代理引擎 - 正在安装..." -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "源文件路径: $sourceDir"
    Write-Host "目标安装路径: $installDir"
    Write-Host ""
} else {
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "   ShadowProxy Process-level Proxy Engine - Installing..." -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "Source directory: $sourceDir"
    Write-Host "Target directory: $installDir"
    Write-Host ""
}

# 1. 检查并终止正在运行的旧实例
$runningProcs = Get-Process -Name "shadow-gui", "shadow-cli" -ErrorAction SilentlyContinue
if ($runningProcs) {
    if ($isZh) {
        Write-Host "[1/5] 检测到正在运行的旧进程，正在安全退出..." -ForegroundColor Yellow
    } else {
        Write-Host "[1/5] Terminating running instances..." -ForegroundColor Yellow
    }
    $runningProcs | Stop-Process -Force
    Start-Sleep -Seconds 1
} else {
    if ($isZh) {
        Write-Host "[1/5] 无正在运行的冲突进程。" -ForegroundColor Green
    } else {
        Write-Host "[1/5] No conflicting processes found." -ForegroundColor Green
    }
}

# 2. 复制程序文件至目标目录
if ($isZh) {
    Write-Host "[2/5] 正在部署核心程序文件..." -ForegroundColor Cyan
} else {
    Write-Host "[2/5] Deploying program files..." -ForegroundColor Cyan
}
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

$itemsToCopy = @(
    "bin",
    "start-gui.bat",
    "start-gui.vbs",
    "start-cli.bat",
    "uninstall.bat",
    "uninstall.ps1",
    "README.md",
    "LICENSE"
)

foreach ($item in $itemsToCopy) {
    $srcPath = Join-Path $sourceDir $item
    if (Test-Path $srcPath) {
        Copy-Item -Path $srcPath -Destination $installDir -Recurse -Force
    }
}

# 3. 创建桌面快捷方式
if ($isZh) {
    Write-Host "[3/5] 正在创建桌面快捷方式..." -ForegroundColor Cyan
} else {
    Write-Host "[3/5] Creating desktop shortcut..." -ForegroundColor Cyan
}
$wsh = New-Object -ComObject WScript.Shell
$desktopDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
$desktopLnkPath = Join-Path $desktopDir "$appName.lnk"
$guiExePath = Join-Path $installDir "bin\shadow-gui.exe"
$vbsPath = Join-Path $installDir "start-gui.vbs"

$desktopShortcut = $wsh.CreateShortcut($desktopLnkPath)
$desktopShortcut.TargetPath = "$env:SystemRoot\System32\wscript.exe"
$desktopShortcut.Arguments = "`"$vbsPath`""
$desktopShortcut.WorkingDirectory = $installDir
$desktopShortcut.IconLocation = "$guiExePath,0"
$desktopShortcut.Description = "ShadowProxy - Transparent Proxy Engine"
$desktopShortcut.Save()

# 4. 创建开始菜单快捷方式
if ($isZh) {
    Write-Host "[4/5] 正在创建开始菜单快捷方式..." -ForegroundColor Cyan
} else {
    Write-Host "[4/5] Creating Start Menu shortcuts..." -ForegroundColor Cyan
}
$programsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
$menuDir = Join-Path $programsDir $appName
if (-not (Test-Path $menuDir)) {
    New-Item -ItemType Directory -Path $menuDir -Force | Out-Null
}

$menuLnkPath = Join-Path $menuDir "$appName.lnk"
$menuShortcut = $wsh.CreateShortcut($menuLnkPath)
$menuShortcut.TargetPath = "$env:SystemRoot\System32\wscript.exe"
$menuShortcut.Arguments = "`"$vbsPath`""
$menuShortcut.WorkingDirectory = $installDir
$menuShortcut.IconLocation = "$guiExePath,0"
$menuShortcut.Description = "ShadowProxy - Transparent Proxy Engine"
$menuShortcut.Save()

$uninstallBatPath = Join-Path $installDir "uninstall.bat"
$uninstLnkName = if ($isZh) { "卸载 $appName.lnk" } else { "Uninstall $appName.lnk" }
$uninstLnkPath = Join-Path $menuDir $uninstLnkName
$uninstShortcut = $wsh.CreateShortcut($uninstLnkPath)
$uninstShortcut.TargetPath = "$env:SystemRoot\System32\cmd.exe"
$uninstShortcut.Arguments = "/c `"$uninstallBatPath`""
$uninstShortcut.WorkingDirectory = $installDir
$uninstShortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,219"
$uninstShortcut.Description = "Uninstall ShadowProxy"
$uninstShortcut.Save()

# 5. 注册 Windows 卸载信息 (已安装的应用列表)
if ($isZh) {
    Write-Host "[5/5] 正在注册系统已安装应用信息..." -ForegroundColor Cyan
} else {
    Write-Host "[5/5] Registering Windows uninstall entry..." -ForegroundColor Cyan
}
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$appName"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

$displayTitle = if ($isZh) { "$appName (透明代理引擎)" } else { "$appName (Transparent Proxy Engine)" }
Set-ItemProperty -Path $regPath -Name "DisplayName" -Value $displayTitle
Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value $appVersion
Set-ItemProperty -Path $regPath -Name "Publisher" -Value "ShadowProxy Team"
Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value $installDir
Set-ItemProperty -Path $regPath -Name "DisplayIcon" -Value "$guiExePath,0"
Set-ItemProperty -Path $regPath -Name "UninstallString" -Value "`"$uninstallBatPath`""
Set-ItemProperty -Path $regPath -Name "NoModify" -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name "NoRepair" -Value 1 -Type DWord

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
if ($isZh) {
    Write-Host "            ShadowProxy 安装完成！" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "程序已成功安装至: $installDir"
    Write-Host "已在桌面与开始菜单生成快捷方式。"
    Write-Host ""
    $ans = Read-Host "是否立即启动 ShadowProxy? (Y/n)"
} else {
    Write-Host "         ShadowProxy Installation Completed!" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "Installed location: $installDir"
    Write-Host "Shortcuts created on Desktop and Start Menu."
    Write-Host ""
    $ans = Read-Host "Launch ShadowProxy now? (Y/n)"
}
if ($ans -eq "" -or $ans -match "^[Yy]") {
    Start-Process -FilePath "$env:SystemRoot\System32\wscript.exe" -ArgumentList "`"$vbsPath`"" -WorkingDirectory $installDir
}
'''

INSTALL_BAT_CONTENT = r'''@echo off
chcp 65001 >nul
title ShadowProxy 安装程序
setlocal EnableDelayedExpansion

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [错误] 安装过程中遇到异常，错误代码: %ERRORLEVEL%
    pause
    exit /b %ERRORLEVEL%
)
'''

UNINSTALL_PS1_CONTENT = r'''# ShadowProxy 一键卸载脚本
[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"
$appName = "ShadowProxy"
$installDir = Join-Path $env:LOCALAPPDATA "Programs\$appName"

Write-Host "========================================================" -ForegroundColor Yellow
Write-Host "          ShadowProxy - 正在卸载..." -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Yellow
Write-Host ""

# 1. 退出进程
Write-Host "[1/4] 正在终止相关进程..." -ForegroundColor Cyan
Get-Process -Name "shadow-gui", "shadow-cli" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# 2. 删除桌面快捷方式
Write-Host "[2/4] 正在清理桌面快捷方式..." -ForegroundColor Cyan
$desktopDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
$desktopLnk = Join-Path $desktopDir "$appName.lnk"
if (Test-Path $desktopLnk) {
    Remove-Item -Path $desktopLnk -Force -ErrorAction SilentlyContinue
}

# 3. 删除开始菜单快捷方式
Write-Host "[3/4] 正在清理开始菜单项..." -ForegroundColor Cyan
$programsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
$menuDir = Join-Path $programsDir $appName
if (Test-Path $menuDir) {
    Remove-Item -Path $menuDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 4. 清理卸载注册表
Write-Host "[4/4] 正在清理系统注册表信息..." -ForegroundColor Cyan
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$appName"
if (Test-Path $regPath) {
    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "[完成] ShadowProxy 快捷方式与系统登记已成功清理！" -ForegroundColor Green
'''

UNINSTALL_BAT_CONTENT = r'''@echo off
chcp 65001 >nul
title ShadowProxy 卸载程序
setlocal

echo ========================================================
echo              ShadowProxy 卸载确认
echo ========================================================
echo.
echo 将彻底清理 ShadowProxy 的桌面图标、开始菜单快捷方式与安装文件。
echo.
set /p CONFIRM="确定要继续卸载吗? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo [取消] 卸载已取消。
    pause
    exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"

set "TARGET_DIR=%~dp0"
:: 在后台延时删除安装目录本身，避免批处理锁定
start "" /b cmd /c "timeout /t 1 /nobreak >nul & rmdir /s /q \"%TARGET_DIR%\""

echo.
echo [提示] 卸载已完成，窗口将在 3 秒后关闭。
timeout /t 3 >nul
exit
'''

INNO_SETUP_TEMPLATE = r'''; ShadowProxy Inno Setup 脚本
#define MyAppName "ShadowProxy"
#define MyAppVersion "0.2.1"
#define MyAppPublisher "ShadowProxy Team"
#define MyAppURL "https://github.com/jnnmia/shadow-proxy"
#define MyAppExeName "bin\shadow-gui.exe"

[Setup]
AppId={{5E28B02F-8AC4-4C7E-9781-B1FF2579040D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=ShadowProxy-Setup-v{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
AppMutex=Global\ShadowProxy_App_Mutex_2026,ShadowProxy_App_Mutex_2026
CloseApplications=yes
RestartApplications=no
CloseApplicationsFilter=*.exe,*.dll
ShowLanguageDialog=auto

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Default.isl,ChineseSimplified.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
chinesesimplified.CreateDesktopIcon=创建桌面快捷方式(&D)
en.CreateDesktopIcon=Create a &desktop shortcut
chinesesimplified.AdditionalIcons=附加图标:
en.AdditionalIcons=Additional shortcuts:
chinesesimplified.LaunchProgram=启动 %1
en.LaunchProgram=Launch %1
chinesesimplified.UninstallProgram=卸载 %1
en.UninstallProgram=Uninstall %1

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "ShadowProxy\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}\{#MyAppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\start-gui.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autoprograms}\{#MyAppName}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\start-gui.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{app}\start-gui.vbs"""; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/f /im shadow-gui.exe /im shadow-cli.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
  Result := '';
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/f /im shadow-gui.exe /im shadow-cli.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
  Result := True;
end;
'''

def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def find_iscc():
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        shutil.which("iscc"),
        os.path.join(local_app_data, r"Programs\Inno Setup 6\ISCC.exe") if local_app_data else None,
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None



def build_binaries(root_dir: Path, bin_dir: Path):
    import tempfile
    print("\n[步骤 0/5] 开始自动化多架构编译构建 (--build)...")
    target_dir_str = os.environ.get("CARGO_TARGET_DIR")
    if not target_dir_str:
        target_dir_str = str(Path(tempfile.gettempdir()) / "shadow-target")
        os.environ["CARGO_TARGET_DIR"] = target_dir_str
    target_dir = Path(target_dir_str)
    print(f"  √ Cargo 临时构建目录: {target_dir}")

    bin_dir.mkdir(parents=True, exist_ok=True)

    # 1. 编译 64 位全量组件
    print("  -> 正在编译 64 位核心组件 (x86_64)...")
    cmd_x64 = ["cargo", "build", "--release", "--workspace"]
    res = subprocess.run(cmd_x64, cwd=root_dir)
    if res.returncode != 0:
        print(f"[错误] 64 位编译失败，退出码: {res.returncode}", file=sys.stderr)
        sys.exit(res.returncode)

    # 2. 编译 32 位兼容组件 (shadow-hook, shadow-injector)
    print("  -> 正在编译 32 位兼容组件 (i686-pc-windows-gnu)...")
    cmd_x86 = ["cargo", "build", "--release", "--target", "i686-pc-windows-gnu", "-p", "shadow-hook", "-p", "shadow-injector"]
    res = subprocess.run(cmd_x86, cwd=root_dir)
    if res.returncode != 0:
        print(f"[错误] 32 位编译失败，退出码: {res.returncode}", file=sys.stderr)
        sys.exit(res.returncode)

    # 3. 产物拷贝与名称对齐
    artifacts_map = [
        (target_dir / "release" / "shadow-gui.exe", bin_dir / "shadow-gui.exe"),
        (target_dir / "release" / "shadow-cli.exe", bin_dir / "shadow-cli.exe"),
        (target_dir / "release" / "shadow_hook.dll", bin_dir / "shadow_hook.dll"),
        (target_dir / "i686-pc-windows-gnu" / "release" / "shadow_hook.dll", bin_dir / "shadow_hook32.dll"),
        (target_dir / "i686-pc-windows-gnu" / "release" / "shadow-injector.exe", bin_dir / "shadow-injector32.exe"),
    ]

    for src, dst in artifacts_map:
        if src.is_file():
            shutil.copy2(src, dst)
            print(f"  √ 归档构建产物: {src.name} -> {dst.name}")
        else:
            print(f"[警告] 未找到构建产物: {src}", file=sys.stderr)

    # 查找并归档 WebView2Loader.dll
    wv2_found = False
    for p in target_dir.glob("**/out/x64/WebView2Loader.dll"):
        if p.is_file():
            shutil.copy2(p, bin_dir / "WebView2Loader.dll")
            print(f"  √ 自动归档 WebView2Loader.dll: {p}")
            wv2_found = True
            break
    if not wv2_found and not (bin_dir / "WebView2Loader.dll").is_file():
        for p in (root_dir / "target").glob("**/out/x64/WebView2Loader.dll"):
            if p.is_file():
                shutil.copy2(p, bin_dir / "WebView2Loader.dll")
                print(f"  √ 自动归档 WebView2Loader.dll: {p}")
                wv2_found = True
                break

    print("  √ 多架构构建与产物归档完成！\n")


def main():
    root_dir = Path(__file__).resolve().parent.parent
    bin_dir = root_dir / "bin"
    dist_dir = root_dir / "dist"
    stage_dir = dist_dir / APP_NAME
    stage_bin_dir = stage_dir / "bin"

    print(f"=== {APP_NAME} v{APP_VERSION} 打包发布流程 ===")
    print(f"工作区根目录: {root_dir}")

    if "--build" in sys.argv:
        build_binaries(root_dir, bin_dir)

    # 1. 检查必备二进制产物
    print("\n[步骤 1/5] 校验构建产物完整性...")
    missing = []
    for b in REQUIRED_BINARIES:
        p = bin_dir / b
        if not p.is_file():
            missing.append(b)
        else:
            size_kb = p.stat().st_size / 1024
            print(f"  √ {b} ({size_kb:.1f} KB)")
    
    if missing:
        print(f"\n[错误] 缺少以下关键产物: {missing}", file=sys.stderr)
        print("请先执行编译后再执行打包脚本。", file=sys.stderr)
        sys.exit(1)

    # 2. 准备暂存发布目录
    print("\n[步骤 2/5] 组织临时发布目录结构...")
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_bin_dir.mkdir(parents=True, exist_ok=True)

    # 复制核心二进制
    for b in REQUIRED_BINARIES:
        shutil.copy2(bin_dir / b, stage_bin_dir / b)

    # 复制启动脚本
    for s in ["start-gui.bat", "start-gui.vbs", "start-cli.bat"]:
        src = root_dir / s
        if src.is_file():
            shutil.copy2(src, stage_dir / s)
            print(f"  √ 包含启动器: {s}")

    # 复制说明文档
    for doc in ["README.md", "LICENSE"]:
        src = root_dir / doc
        if src.is_file():
            shutil.copy2(src, stage_dir / doc)
            print(f"  √ 包含文档: {doc}")

    # 生成安装与卸载脚本
    (stage_dir / "install.ps1").write_text(INSTALL_PS1_CONTENT, encoding="utf-8")
    (stage_dir / "install.bat").write_text(INSTALL_BAT_CONTENT, encoding="utf-8")
    (stage_dir / "uninstall.ps1").write_text(UNINSTALL_PS1_CONTENT, encoding="utf-8")
    (stage_dir / "uninstall.bat").write_text(UNINSTALL_BAT_CONTENT, encoding="utf-8")
    print("  √ 生成一键安装/卸载脚本 (install.bat / uninstall.bat)")

    # 3. 生成 Inno Setup 脚本
    print("\n[步骤 3/5] 生成 Inno Setup 安装包工程配置...")
    scripts_dir = root_dir / "scripts"
    iss_path = scripts_dir / "setup.iss"
    iss_path.write_text(INNO_SETUP_TEMPLATE, encoding="utf-8")
    (dist_dir / "setup.iss").write_text(INNO_SETUP_TEMPLATE, encoding="utf-8")
    isl_file = scripts_dir / "ChineseSimplified.isl"
    if isl_file.is_file():
        shutil.copy2(isl_file, dist_dir / "ChineseSimplified.isl")
    print(f"  √ 已生成 Inno Setup 配置文件: {iss_path}")

    # 尝试编译 Inno Setup 安装包
    iscc = find_iscc()
    setup_exe = None
    if iscc:
        print(f"  √ 发现 Inno Setup 编译器: {iscc}，正在编译独立安装包...")
        import tempfile
        temp_out = Path(tempfile.gettempdir()) / "sp_iscc_out"
        temp_out.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            [iscc, f"/O{temp_out}", "setup.iss"],
            cwd=dist_dir,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode == 0:
            built_exe = temp_out / f"ShadowProxy-Setup-v{APP_VERSION}.exe"
            target_exe = dist_dir / f"ShadowProxy-Setup-v{APP_VERSION}.exe"
            if built_exe.is_file():
                try:
                    shutil.copy2(built_exe, target_exe)
                    setup_exe = target_exe
                    print(f"  √ 独立安装包构建成功: {target_exe.name}")
                except PermissionError:
                    if target_exe.is_file():
                        setup_exe = target_exe
                        print(f"  √ 现有安装包已被系统使用，保留有效安装包: {target_exe.name}")
        else:
            print(f"  ! Inno Setup 编译失败 (代码 {res.returncode}):\n{res.stdout}\n{res.stderr}")
    else:
        print("  - 未检测到 Inno Setup (ISCC.exe)，跳过编译单一 Setup.exe 安装包。")

    # 4. 生成便携式 ZIP 压缩包
    print("\n[步骤 4/5] 生成便携式分发 ZIP 压缩包...")
    zip_name = f"{APP_NAME}-v{APP_VERSION}-windows-portable.zip"
    zip_path = dist_dir / zip_name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, _, files in os.walk(stage_dir):
            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(dist_dir)
                zf.write(full_path, arcname=str(rel_path))
    
    zip_size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"  √ 绿色便携压缩包生成完成: {zip_name} ({zip_size_mb:.2f} MB)")

    # 5. 计算校验和并生成清单
    print("\n[步骤 5/5] 生成 SHA-256 完整性校验清单...")
    checksum_lines = []
    artifacts = [zip_path]
    if setup_exe and setup_exe.is_file():
        artifacts.append(setup_exe)

    for art in artifacts:
        sha = calculate_sha256(art)
        checksum_lines.append(f"{sha}  {art.name}")
        print(f"  {art.name}: {sha}")

    (dist_dir / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    print("  √ 校验清单已保存至 dist/SHA256SUMS.txt")

    print("\n================ 打包交付成功 ================")
    print(f"分发目录: {dist_dir}")
    print(f"1. 免安装绿色目录: dist/{APP_NAME}/ (双击 start-gui.bat 或运行 install.bat 安装)")
    print(f"2. 绿色便携压缩包: dist/{zip_name}")
    if setup_exe:
        print(f"3. 独立安装安装包: dist/{setup_exe.name}")
    print(f"4. 完整性校验文件: dist/SHA256SUMS.txt")
    print("==============================================")

if __name__ == "__main__":
    main()
