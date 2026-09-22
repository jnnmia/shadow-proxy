# Errors

## [ERR-20260920-001] codegraph init -i

- **Command**: `codegraph init -i`
- **Summary**: Windows 环境下 codegraph 初始化索引完成后在遥测线程退出时触发 libuv 断言错误。
- **Error**: `Assertion failed: uv__has_active_reqs((loop)), file src\win\tcp.c, line 1270`
- **Context**: 仓库文件扫描解析已完成（生成 `.codegraph/codegraph.db`），但在退出事件循环时因遥测网络请求未完全释放导致崩溃。
- **Fix**: 设置环境变量 `CODEGRAPH_TELEMETRY=0` 或执行 `codegraph telemetry off` 关闭匿名遥测上报。

## [ERR-20260920-002] cargo check (MSVC linker missing)

- **Command**: `cargo check`
- **Summary**: 未安装 Visual Studio C++ Build Tools 时，rustc 调用 link.exe 命中 Git/usr/bin/link.exe 导致构建脚本链接失败。
- **Error**: `link: extra operand ... Try 'link --help' for more information.`
- **Context**: Windows 环境使用 MSVC toolchain 编译 build script（proc-macro2 等）必须依赖 MSVC link.exe 与 Windows SDK。
- **Fix**: 通过 winget 安装 `Microsoft.VisualStudio.2022.BuildTools` 并包含 `Microsoft.VisualStudio.Workload.VCTools` 工作负载。

## [ERR-20260920-003] MinGW ld.exe cannot find rlib on non-ASCII path

- **Command**: `cargo test`
- **Summary**: 当项目位于包含中文字符的路径或网络映射盘时，MinGW ld.exe 解析依赖库 rlib 路径失败。
- **Error**: `collect2.exe: error: ld returned 1 exit status / cannot find ...libparking_lot...rlib: No such file or directory`
- **Context**: Windows 下 GNU ld.exe 对包含中文或特殊字符的映射盘 UNC 路径支持有限。
- **Fix**: 设置环境变量 `CARGO_TARGET_DIR` 指向纯 ASCII 本地缓存路径（如 `C:\Users\<user>\.cargo_target\<project>`），绕过中文路径链接瓶颈。
