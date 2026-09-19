# update/latest.json

应用内自动更新读的就是这一个文件,地址是 `https://ghostproxifier.com/update/latest.json`。

JSON 里放不下注释,所以约定写在这里。

## 字段

```json
{
  "version":  "1.2.0",
  "url":      "https://.../GhostProxifier-Pro-Installer.msi",
  "sha256":   "<64 位小写十六进制>",
  "notesUrl": "https://..."
}
```

四个字段**全部会被客户端校验**,任何一条不满足,整份清单作废(不存在「部分可用的清单」),客户端退回到只通知不安装的兜底模式:

| 字段 | 规则 | 不满足会怎样 |
|---|---|---|
| `version` | 三段纯数字,可带 `v` 前缀。后缀(`-dev.x`/`-SNAPSHOT.x`)会被解析后丢弃 | 清单作废 |
| `url` | **必须 https**,且主机必须在客户端编译期写死的白名单里:`ghostproxifier.com`、`www.ghostproxifier.com`、`github.com`、`objects.githubusercontent.com` | 清单作废 |
| `sha256` | **恰好 64 位小写十六进制**。大写不行,长短不行 | 清单作废 |
| `notesUrl` | 可选,必须 https | 该字段被丢弃,清单其余部分仍然有效 |

`sha256` 是**强制**的,没有任何开关能关掉它。下载下来的字节必须逐位等于这个值,否则文件被删除、安装中止。这是目前唯一挡在「一个错误的文件」和「以管理员身份运行 msiexec」之间的东西——因为 MSI 目前**没有 Authenticode 签名**(实测:release 资产里没有 `DigitalSignature` 流,整个文件里也没有任何 PKCS#7 结构)。

客户端的兜底源是 GitHub 的 releases 接口。那个接口不发布校验和,所以**从兜底源发现的新版本只能通知、不能安装**——用户点到的是下载页链接。想让「缺校验和就跳过校验」是不行的:能把字段拿掉的人,也就能把校验跳过。

## 发版时要做什么

提升版本发布之后,改这个文件的三个字段:

```bash
# 1. 算 MSI 的 sha256(和客户端算的是同一个东西)
certutil -hashfile GhostProxifier-Pro-Installer.msi SHA256

# 2. 改 version / url / sha256 / notesUrl,提交推送
```

推到 master 即生效,GitHub Pages 没有构建步骤。

⚠️ **改完请自己 `curl` 一下确认 200 且 JSON 合法。** 这个文件 404 或者格式坏掉,表现不是报错,而是**所有用户静默退回兜底模式**——他们仍然会被通知有新版本,但从此只能手动下载,而你在客户端这边看不到任何异常。

## 安装包托管在哪

现在 `url` 指向 GitHub Release。这对国内用户是薄弱环节:GitHub 的下载域在国内经常不可达,而自动更新的**主要服务对象恰好就是这批用户**。

把 MSI 一并放进本仓库(约 4.4 MB/版本),`url` 改指 `https://ghostproxifier.com/dl/...`,就能把 GitHub 从关键路径上摘掉——白名单里已经包含本站域名,客户端不需要改动。代价是仓库每发一版涨 4 MB 左右(当前 `.git` 约 10 MB)。
