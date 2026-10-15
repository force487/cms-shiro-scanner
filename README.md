# CMS 指纹识别 + Shiro 探测 + 端口服务扫描器

一个用 **纯 Python 标准库**写成的轻量级 Web 安全扫描器（教学 / 授权测试用途），
当前实现三个功能模块：

| 模块 | 作用 | 核心手段 |
| --- | --- | --- |
| `cms` | 识别目标站点的建站系统（CMS / 框架 / 服务器） | 字典匹配响应特征：HTML 关键字、响应头、正则、Set-Cookie、响应路径二次确认 |
| `shiro` | 判断后端是否使用 Apache Shiro | 发送 `rememberMe=deleteMe` 观察响应回显 + 目录路径字典探测 |
| `ports` | 探测开放端口并识别服务类型 | 对端口做 TCP 连接，发协议探测包，用正则匹配返回的 banner |

> ⚠️ **免责声明**：本项目仅用于安全学习、CTF 与**已获授权**的渗透测试。
> 请勿对未授权的目标使用，由此产生的一切后果由使用者自行承担。

---

## 功能特性

- **零第三方依赖**：只用 `urllib` / `json` / `re` / `ssl` / `http.server`，`pip install` 都不用跑。
- **字典驱动**：指纹全部写在 `scanner/dicts/cms_rules.json`，加规则不用改代码。
- **可解释的结果**：每条结论都会列出命中的证据（哪一行响应头、哪个关键字），不是黑盒打分。
- **加权打分 + 置信度**：区分“硬特征”（响应头 / Cookie）和“软特征”（正文关键字），输出 high / medium / low。
- **二次确认**：指纹在首页命中后，会再请求该 CMS 的特征路径（如 `/wp-login.php`）复核，降低误报。
- **端口 / 服务探测**：TCP 连接 + 协议探测包 + 正则识别 banner，覆盖 SSH / HTTP(S) / FTP / SMTP / Redis / MySQL 等常见服务。
- **可扩展**：新增模块只需要写一个 `run(client, base_url, ...)` 函数。

---

## 目录结构

```
cms_shiro_scanner/
├── main.py                     # 命令行入口：解析参数、调度模块、输出结果
├── requirements.txt            # 无第三方依赖（纯标准库）
├── README.md
├── .vscode/
│   └── launch.json             # VS Code 一键运行 / 调试配置（4 个配置项）
├── scanner/                    # 扫描器主体
│   ├── __init__.py
│   ├── models.py               # HttpResponse / Finding 数据模型
│   ├── http_client.py          # HTTP 客户端（urllib 封装）
│   ├── fingerprint.py          # ★ 核心：字典匹配引擎
│   ├── cms.py                  # CMS 指纹识别模块
│   ├── shiro.py                # Shiro 探测模块
│   ├── ports.py                # 端口与服务探测模块
│   └── dicts/
│       ├── cms_rules.json      # CMS 指纹字典（24 条规则）
│       ├── shiro_paths.txt     # Shiro 目录路径字典（16 条路径）
│       └── service_probes.json # 服务探测字典（端口 + 探测包 + 正则）
├── tests/
│   └── mock_target.py          # 本地模拟靶机，用于安全地验证扫描效果
└── backups/
    └── cms_shiro_scanner_20261014.zip  # 完整项目备份（不打进自身压缩包）
```

---

## 环境要求

- Python **3.8+**（本项目在 Python 3.12 上开发）
- 无需安装任何第三方库
- VS Code + Python 扩展（推荐 `ms-python.python`）即可运行 / 调试

验证环境：

```bash
python --version        # 例如 Python 3.12.10
```

---

## 快速开始

### 方式一：VS Code 里一键运行（推荐）

1. 用 VS Code 打开 `cms_shiro_scanner` 文件夹；
2. 按 `F5`，在下拉框里选择配置：
   - `启动本地模拟靶机` —— 先跑这个，把本地靶机起在 `http://127.0.0.1:8080`
   - `扫描目标（全部模块）` —— 再跑这个，扫描本地靶机（CMS + Shiro + 端口）
   - `只跑 CMS 指纹识别` / `只跑 Shiro 探测` / `只跑端口与服务探测` —— 单独跑某个模块
3. 想扫真实目标，只要改 `.vscode/launch.json` 里 `args` 的 `-u` 后面的地址即可。

### 方式二：命令行

```bash
cd cms_shiro_scanner

# 1) 启动本地模拟靶机（另开一个终端）
python tests/mock_target.py

# 2) 扫描
python main.py -u http://127.0.0.1:8080 -v
```

### 常用参数

```bash
python main.py -h                                  # 查看全部参数

python main.py -u http://target.com                # 扫描单个目标
python main.py -u http://a.com -u http://b.com     # 扫描多个目标
python main.py -f urls.txt                         # 从文件批量读取目标
python main.py -u http://target.com -m cms         # 只跑 CMS 模块
python main.py -u http://target.com -m shiro       # 只跑 Shiro 模块
python main.py -u http://target.com -m ports       # 只跑端口/服务探测（默认常见端口）
python main.py -u http://target.com -m ports -p 80,443,3306   # 指定端口
python main.py -u http://target.com -m ports -p 1-1000 --port-threads 300
python main.py -u http://target.com -v             # 打印每一步探测过程
python main.py -u http://target.com -o result.json # 结果额外保存为 JSON
python main.py -u http://target.com -o report.html # 生成 HTML 网页报告（浏览器打开）
python main.py -u http://target.com --cms-dict my.json   # 换自己的指纹字典
python main.py -u http://target.com --min-score 4        # 提高输出阈值，减少误报
```

---

## 运行效果

对本地模拟靶机（`tests/mock_target.py`）扫描的输出：

```
==============================================================
  CMS 指纹识别 + Apache Shiro 探测扫描器  v1.0.0
  目标数量：1    模块：cms, shiro
==============================================================
[*] 已加载 CMS 指纹规则 24 条
[*] 已加载 Shiro 探测路径 16 条

[*] 目标：http://127.0.0.1:8080
  [CMS 指纹识别]
    [+] WordPress（CMS）   [置信度: high / 分数: 9]
          · [body] 正文含关键字 “wp-content”
          · [body] 正文含关键字 “wp-includes”
          · [body] 正文含关键字 “/wp-json/”
          · [regex] 正文匹配正则 <meta name="generator" content="WordPress
          · [path] 特征路径 /wp-login.php 命中 “wp-submit”
          · [path] 特征路径 /wp-login.php 命中 “user_login”
    [+] Nginx（服务器）   [置信度: medium / 分数: 3]
          · [header] 响应头 server: nginx/1.24.0
  [Shiro 探测]
    [+] Apache Shiro（rememberMe=deleteMe 回显确认）   [置信度: high / 分数: 10]
          · 探测路径 /login 回显 rememberMe=deleteMe（HTTP 302）
          · 探测路径 /admin/login 回显 rememberMe=deleteMe（HTTP 302）
          · 探测路径 /doLogin 回显 rememberMe=deleteMe（HTTP 302）
          · 探测路径 /user/login 回显 rememberMe=deleteMe（HTTP 302）
  [完成] 用时 0.10s

[*] 扫描结束。
```

（上面是本地靶机的真实运行结果，加 `-v` 还能看到每一步请求的 URL 与状态码。）

---

## 工作原理

### 1. 核心函数：`match_response()`

整个扫描器的“发动机”在 [scanner/fingerprint.py](scanner/fingerprint.py)，
它把**一条字典规则**和**一条 HTTP 响应**做比对，返回所有命中的证据：

```python
evidence = match_response(rule, response)   # -> [("body", "正文含关键字 “wp-content”", 1), ...]
score    = score_of(evidence)               # 权重求和
level    = confidence_of(score)             # high / medium / low
```

支持 5 种匹配维度，权重如下（越“硬”的特征权重越高）：

| 匹配维度 | 权重 | 说明 | 例子 |
| --- | --- | --- | --- |
| `headers` | 3 | 响应头特征最不容易伪造 | `Server: nginx`、`X-Powered-By: ThinkPHP` |
| `cookies` | 3 | Set-Cookie 名称/值特征 | `wordpress_*`、`_gitlab_session` |
| `regex` | 2 | 正文正则，比关键字精确 | `<meta name="generator" content="WordPress` |
| `path` | 2 | 特征路径二次确认命中 | `/wp-login.php` 里出现 `wp-submit` |
| `body` | 1 | 正文关键字，最易误报 | `wp-content` |

置信度换算：总分 `>=5` 为 `high`，`>=3` 为 `medium`，`>=1` 为 `low`；
CMS 模块默认丢弃总分 `< 2` 的结果（可用 `--min-score` 调整）。

### 2. CMS 指纹识别流程

1. 请求首页，拿到 `HttpResponse`（状态码 / 响应头 / Set-Cookie / 正文）；
2. 把字典里每条规则都跑一遍 `match_response()`；
3. 对**已命中**且带 `path` 字段的规则，再请求一次特征路径做二次确认；
4. 按分数排序输出。

### 3. Shiro 探测流程

1. **deleteMe 主动探测**（最关键的一步）：
   请求 `GET /`，带上 `Cookie: rememberMe=deleteMe`。
   若响应头 `Set-Cookie` 里回显了 `rememberMe=deleteMe`，
   说明后端确实在用 Shiro —— 这是置信度最高的判断依据。
2. **路径字典探测**：对 `shiro_paths.txt` 中的每条路径重复上面的动作，
   观察每一跳是否有 Shiro 特征（`302` + `deleteMe` 回显最常见）。
3. **被动特征匹配**：在上面的响应里搜 `org.apache.shiro`、`ShiroFilter`、
   `DelegatingFilterProxy`、`rememberMe` 等关键字。

> 为什么 `rememberMe=deleteMe` 能判断？
> 因为 Shiro 的 `CookieRememberMeManager` 在处理 `rememberMe` Cookie 时，
> 如果解密失败会把 Cookie 置为 `deleteMe` 并写回响应头。
> 所以只要我们能“诱使”它回写 `deleteMe`，就等于确认了 Shiro 的存在。

### 4. 端口与服务探测流程

1. 从目标 URL 提取主机名，决定要扫的端口（默认扫常见端口，或 `-p` 指定）；
2. 对每个端口做 TCP 连接（多线程并发），连不上直接跳过，连上继续；
3. 按该端口对应的协议发探测包——有的服务（SSH / FTP / SMTP）一连上就自己报
   banner，这时只读不发；有的（HTTP / Redis / Memcached）要先发包才会回；
   HTTPS 类端口先做 TLS 握手再发包；
4. 用正则匹配返回数据识别服务类型，并把原始 banner 作为证据列出。

---

## 自定义字典

### 新增一条 CMS 指纹

编辑 `scanner/dicts/cms_rules.json`，追加一个对象即可（字段都是可选的，
缺哪个就不按哪个维度匹配），**不需要改任何代码**：

```json
{
  "id": "my-cms",
  "name": "我的CMS",
  "category": "CMS",
  "match": {
    "body":    ["特征关键字1", "特征关键字2"],
    "regex":   ["<meta name=\"generator\" content=\"我的CMS"],
    "headers": { "x-powered-by": "MyCMS" },
    "cookies": ["mycms_session"],
    "status":  [200]
  },
  "path": "/admin/login.php",
  "path_body": ["mycms"]
}
```

### 新增 Shiro 探测路径

直接往 `scanner/dicts/shiro_paths.txt` 里加行，`#` 开头为注释：

```
/后台
/admin/index.php
```

### 新增一条服务探测规则

编辑 `scanner/dicts/service_probes.json`，追加一个对象即可，**不需要改代码**：

```json
{
  "id": "my-service",
  "name": "我的服务",
  "ports": [7777],
  "probe": "PING\r\n",
  "ssl": false,
  "regex": ["^PONG"],
  "note": "我的服务（PING 回 PONG）"
}
```

- `probe`：主动探测包，`null` 表示只被动读 banner；支持 `\r\n`、`\xNN` 转义。
- `ssl`：是否先做 TLS 握手（HTTPS 类端口用）。
- `regex`：对返回数据做的正则（不区分大小写），任一命中即识别为 `name`。

---

## 开发步骤与变更记录

> 记录每一步**新增了什么**、**修正了什么**。每一步都保持“可运行”。

**Step 1 —— 搭框架**
- 新增：`main.py` 入口（argparse 命令行）、`scanner/` 包、`models.py` 数据模型
  （`HttpResponse` / `Finding`）、`requirements.txt`、`.vscode/launch.json`。
- 目标：先把“参数解析 → 加载字典 → 逐目标调度模块 → 汇总输出”的主干跑通。

**Step 2 —— HTTP 客户端**
- 新增：`http_client.py`，封装 `urllib`，统一超时 / UA / TLS 校验开关；
  提供 `normalize_url()`、`join_url()`、`decode_body()` 三个工具函数。
- 修正：默认**关闭 TLS 校验**（目标常用自签名证书，否则直接报错）；
  提供“禁止自动跟随跳转”的 opener，这样才能拿到 `3xx` 的 `Location` 和
  `Set-Cookie` —— 这是后面 Shiro 判断的关键；
  正文解码按 `Content-Type` 尝试 `utf-8/gbk/latin-1`，避免中文站点乱码后关键字匹配失败。

**Step 3 —— 核心匹配引擎 + CMS 字典**
- 新增：`fingerprint.py`（`load_rules` / `load_wordlist` / `match_response` /
  `score_of` / `confidence_of` / `describe`），实现 5 个匹配维度与加权打分；
  新增 `dicts/cms_rules.json`（24 条指纹：CMS / 框架 / 服务器 / 应用）。
- 设计理由：把“怎么匹配”和“匹配什么”分离，字典驱动，加指纹零改代码。

**Step 4 —— CMS 模块**
- 新增：`cms.py`，串起“首页匹配 → 特征路径二次确认 → 排序输出”。
- 修正：加入 `min_score` 阈值（默认 2），解决“正文偶然出现一个关键字就报 CMS”
  的误报问题；对带 `path` 的规则做二次请求复核。

**Step 5 —— Shiro 模块**
- 新增：`shiro.py`（`detect_deleteme` / `probe_paths` / `run`）+
  `dicts/shiro_paths.txt`（16 条常见后台路径）。
- 设计理由：先用 deleteMe 回显做一次高置信度判定，再用路径字典扩大覆盖面；
  两者结果按分数合并排序。

**Step 6 —— 本地靶机与联调修正**
- 新增：`tests/mock_target.py`，用标准库伪造出一台“WordPress + Shiro”的靶机，
  让扫描器可以在本地安全地验证。
- 修正：`HttpClient._build()` 里同名响应头原来会被后者覆盖，导致多个
  `Set-Cookie` 只剩下一条 —— 改为**合并**，Shiro 的 deleteMe 判断才稳定。

**Step 7 —— 实测回归中修掉的三个问题**
- 修正 1（准确性）：Shiro 探测原来会跟随 `302` 跳转，
  导致跳转前那一跳上的 `Set-Cookie: rememberMe=deleteMe` 被丢掉，真实站点会漏报。
  改为给 `HttpClient.get()` 增加 `follow_redirect` 参数，Shiro 模块统一**不跟随跳转**。
- 修正 2（可读性）：字典里多条路径同时命中时，原来会重复打印 4 条一模一样的结论。
  改为在 `shiro.run()` 里把所有 deleteMe 回显证据**聚合成一条**高置信度结论，
  各命中路径作为证据列出。
- 修正 3（效率）：目标不可达时仍会把整个路径字典跑一遍（17 次请求白等）。
  改为首页探测失败就**短路返回**，直接提示“目标不可达，跳过路径字典探测”。

**Step 8 —— 端口与服务探测模块**
- 新增：`ports.py`（TCP 连接 + 协议探测包 + 正则识别）+ `dicts/service_probes.json`
  （16 条探测规则：SSH/HTTP/Redis/MySQL 等）；`main.py` 增加 `-p` / `--port-threads`
  / `--service-dict` 参数，报告新增“端口与服务探测”区块。
- 设计理由：端口探测和 CMS/Shiro 走同一套“可解释结论”输出；识别靠“发对应协议
  探测包 + 正则匹配 banner”，并对没有专属规则的端口做通用 HTTP 探测兜底。

---

## 备份

完整项目已打包备份为
`backups/cms_shiro_scanner_20261014.zip`（22.8 KB，13 个文件，含 `.vscode` 配置），
解压后即可直接运行。`backups/` 目录本身不打进压缩包，避免自我包含。

打包命令（PowerShell）：

```powershell
$root = "cms_shiro_scanner"
New-Item -ItemType Directory -Force "$root\backups" | Out-Null
$items = Get-ChildItem $root -Force -Exclude "backups"
Compress-Archive -Path $items.FullName `
  -DestinationPath "$root\backups\cms_shiro_scanner_20261014.zip" -Force
```

---

## 后续可以扩展的方向

- 指纹库扩充 + 引入 favicon hash、`robots.txt`、`/readme.html` 等更多维度的特征；
- Shiro 模块增加 AES 密钥爆破（`kPH+bIxk5D2deZiIxcaaaA==` 等常见 key）与
  gadget 检测；
- 加 `--threads` 并发与请求速率限制；
- 增加 HTML / JSON 报告导出。
