> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [xz.aliyun.com](https://xz.aliyun.com/news/18664)

> 先知社区是一个安全技术社区，旨在为安全技术研究人员提供一个自由、开放、平等的交流平台。

  
Nuclei 完整学习指南 - 从入门到精通  
  
目录导航  
  
●快速开始  
  
●核心概念  
  
●安装配置  
  
●基础使用  
  
●模板编写  
  
●内置功能  
  
●高级技巧  
  
●最佳实践  
  
●故障排除  
  
🎯 快速开始  
  
什么是 Nuclei？  
  
Nuclei 是由 ProjectDiscovery 开发的基于 YAML 模板的现代漏洞扫描器，具有以下特点：  
  
● 高性能：支持大规模并发扫描  
● 精准检测：基于社区验证的模板库  
● 持续更新：活跃的开源社区维护  
● 易于扩展：简单的 YAML 语法编写自定义检测  
🎯 核心概念  
  
架构原理  
  
![](https://xz.aliyun.com/api/v2/files/6939bc83-55be-3552-b9e2-7280d5d9fa12)  
  
核心组件  
  
<table><colgroup><col width="250"><col width="250"><col width="249"></colgroup><tbody><tr><td data-col="0"><ne-p data-lake-id="ue5176ad7"><ne-text>组件</ne-text><br></ne-p></td><td data-col="1"><ne-p data-lake-id="ud8c625ef"><ne-text>功能</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u711a5033"><ne-text>示例</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u75503ed9"><ne-text ne-bold="true">模板</ne-text><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u77f3984e"><ne-text>定义检测逻辑</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="ucb58507a"><ne-code><ne-code-content><ne-text>cves/2023/CVE-2023-1234.yaml</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="udc126190"><ne-text ne-bold="true">匹配器</ne-text><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u574f5d4d"><ne-text>验证漏洞特征</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u51b9de99"><ne-code><ne-code-content><ne-text>status: 200</ne-text></ne-code-content></ne-code><ne-text> + </ne-text><ne-code><ne-code-content><ne-text>words: "admin"</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u0525bdcc"><ne-text ne-bold="true">提取器</ne-text><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u82533938"><ne-text>获取关键信息</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u053310f6"><ne-text>提取 session ID、版本号</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u5ba87a44"><ne-text ne-bold="true">变量</ne-text><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u7ad7749e"><ne-text>动态内容替换</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u7727b88d"><ne-code><ne-code-content><ne-text>{{BaseURL}}</ne-text></ne-code-content></ne-code><ne-text>、</ne-text><ne-code><ne-code-content><ne-text>{{Hostname}}</ne-text></ne-code-content></ne-code><br></ne-p></td></tr></tbody></table>  
🎯 安装配置  
  
多种安装方式  
  
方式一：Go 安装（推荐）  
  
​

912345# 安装最新版本go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  
# 验证安装nuclei -version 方式二：预编译二进制  
​

91234567# Linux AMD64wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.0.0_linux_amd64.zipunzip nuclei_3.0.0_linux_amd64.zipsudo mv nuclei /usr/local/bin/  
# macOSbrew install nuclei 方式三：Docker 容器  
​

912345# 拉取镜像docker pull projectdiscovery/nuclei:latest  
# 运行扫描docker run --rm projectdiscovery/nuclei -u https://example.com 环境配置  
初始化配置  
  
​

912345678# 创建配置目录mkdir -p ~/.config/nuclei  
# 更新模板库（约 4000 + 模板）nuclei -update-templates  
# 生成配置文件nuclei -config-generate 配置文件示例  
​

9123456789# ~/.config/nuclei/config.yamltemplates-directory: "~/nuclei-templates"output: "results"severity: "critical,high,medium"concurrent: 25rate-limit: 150timeout: 10retries: 1verbose: true🎯 基础使用  
  
基本命令结构  
  
​

91nuclei [全局选项] -target [目标] -templates [模板] [输出选项] 目标指定方式  
​

991234567891011121314# 单个 URLnuclei -u https://example.com  
# 多目标文件nuclei -l targets.txt  
# 从 stdin 读取echo "https://example.com" | nuclei  
# IP 段扫描nuclei -u 192.168.1.1/24  
# 端口范围nuclei -u example.com -p 80,443,8080-8090 模板选择策略  
​

991234567891011121314# 按严重程度nuclei -u target -severity critical,high  
# 按漏洞类型nuclei -u target -tags sqli,xss,rce  
# 指定模板目录nuclei -u target -t cves/2023/  
# 排除特定模板nuclei -u target -exclude-templates dos/  
# 自定义模板nuclei -u target -t my-custom-template.yaml 实用参数组合  
快速扫描  
  
​

91nuclei -u target -tags cve -severity critical -c 50 -rate-limit 100 深度扫描  
​

91nuclei -u target -tags vuln,exposure -timeout 15 -retries 2 -verbose 静默扫描  
​

91nuclei -u target -silent -json -o results.json🎯 模板编写  
  
基础模板结构  
  
​

991234567891011121314151617181920212223id: unique-template-id  
info: name: "漏洞名称" author: "作者" severity: critical|high|medium|low|info description: "详细描述" tags: "tag1,tag2,tag3" reference: - "https://reference-url.com"  
requests: - method: GET|POST|PUT|DELETE path: - "{{BaseURL}}/endpoint" matchers: - type: status|word|regex|dsl # 匹配条件 extractors: - type: regex|xpath|json # 提取规则实际模板示例  
  
简单 GET 请求检测  
  
​

9912345678910111213141516171819202122232425262728293031id: admin-panel-detection  
info: name: "Admin Panel Detection" author: "security-team" severity: info description: "检测常见的管理员面板" tags: "panel,admin,exposure"  
requests: - method: GET path: - "{{BaseURL}}/admin" - "{{BaseURL}}/admin.php" - "{{BaseURL}}/administrator" - "{{BaseURL}}/wp-admin" matchers-condition: and matchers: - type: status status: - 200 - type: word part: body words: - "admin" - "login" - "dashboard" condition: or case-insensitive: truePOST 请求 with 负载  
  
​

99123456789101112131415161718192021222324252627282930313233343536373839id: login-bypass-attempt  
info: name: "SQL Injection Login Bypass" author: "pentest-team" severity: high description: "尝试通过 SQL 注入绕过登录验证" tags: "sqli,auth-bypass,login"  
requests: - method: POST path: - "{{BaseURL}}/login" - "{{BaseURL}}/admin/login.php" headers: Content-Type: "application/x-www-form-urlencoded" X-Forwarded-For: "127.0.0.1" body: | username={{username}}&password={{password}} payloads: username: - "admin' OR '1'='1' --" - "admin' OR 1=1#" - "'OR'x'='x" password: - "anything" attack: pitchfork matchers: - type: word words: - "welcome" - "dashboard" - "logged in successfully" condition: or 匹配器详解  
状态码匹配  
  
​

9123456matchers: - type: status status: - 200 - 302 condition: or 字符串匹配  
​

912345678matchers: - type: word part: body|header|all words: - "error message" - "exception" condition: and|or case-insensitive: true 正则表达式匹配  
​

9123456matchers: - type: regex part: body regex: - "version\s+([0-9]+\.[0-9]+\.[0-9]+)" - "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"DSL 表达式匹配  
  
​

91234567matchers: - type: dsl dsl: - "status_code == 200" - "len(body) > 1000" - "contains(tolower(body),'admin')" condition: and🎯 内置功能  
  
变量系统  
  
内置变量  
  
<table><colgroup><col width="250"><col width="250"><col width="249"></colgroup><tbody><tr><td data-col="0"><ne-p data-lake-id="u32cd29ec"><ne-text>变量</ne-text><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u189c0ebb"><ne-text>描述</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="ua4eae6c8"><ne-text>示例值</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="ub30556cb"><ne-code><ne-code-content><ne-text>{{BaseURL}}</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u6469e488"><ne-text>完整基础 URL</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u68fd09c6"><ne-code><ne-code-content><ne-text>https://example.com</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="udc9602da"><ne-code><ne-code-content><ne-text>{{RootURL}}</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u7e1d4e0d"><ne-text>根 URL</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u09bfcc77"><ne-code><ne-code-content><ne-text>https://example.com</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u393fb80e"><ne-code><ne-code-content><ne-text>{{Hostname}}</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="ue7ee936f"><ne-text>主机名</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u113fd0cc"><ne-code><ne-code-content><ne-text>example.com</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u66c635c2"><ne-code><ne-code-content><ne-text>{{Host}}</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u229dca14"><ne-text>主机地址</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="ub72f730f"><ne-code><ne-code-content><ne-text>example.com:443</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u349aeb26"><ne-code><ne-code-content><ne-text>{{Port}}</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u0bcc1d2a"><ne-text>端口号</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u533effd1"><ne-code><ne-code-content><ne-text>443</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u8ed869f5"><ne-code><ne-code-content><ne-text>{{Path}}</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u9d043d73"><ne-text>路径部分</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u93231020"><ne-code><ne-code-content><ne-text>/api/v1</ne-text></ne-code-content></ne-code><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u521a908a"><ne-code><ne-code-content><ne-text>{{Scheme}}</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="ubf5cac03"><ne-text>协议</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u873b5970"><ne-code><ne-code-content><ne-text>https</ne-text></ne-code-content></ne-code><br></ne-p></td></tr></tbody></table>  
自定义变量  
  
​

991234567891011variables: api_key: "sk-1234567890abcdef" endpoint: "/api/v2/users" user_id: "12345"  
requests: - method: GET path: - "{{BaseURL}}{{endpoint}}/{{user_id}}" headers: Authorization: "Bearer {{api_key}}" 内置函数库  
Nuclei 提供了丰富的内置函数，支持编码、字符串处理、随机生成等功能。以下是常用函数的简要介绍：  
  
编码解码函数  
  
​

9123456{{url_encode("hello world")}} # hello%20world{{base64("admin:password")}} # YWRtaW46cGFzc3dvcmQ={{base64_decode("dGVzdA==")}} # test{{html_escape("<script>")}} # &lt;script&gt;{{md5("password")}} # 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8{{sha256("password")}} # ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f 字符串处理函数  
​

91234567{{to_lower("HELLO")}} # hello{{to_upper("hello")}} # HELLO{{trim("hello")}} # hello{{replace("hello world", "world", "nuclei")}} # hello nuclei{{substr("testing", 0, 4)}} # test{{len("hello")}} # 5{{contains("testing", "test")}} # true 随机生成函数  
​

912345{{rand_char(10)}} # 随机 10 个字符{{rand_int(1, 100)}} # 1-100 随机整数{{rand_text_alpha(8)}} # 8 位随机字母{{rand_base64(16)}} # 16 字节随机 base64{{rand_uuid()}} # 随机 UUID 时间函数  
​

9123{{unix_time()}} # Unix 时间戳{{date_time("%Y-%m-%d")}} # 格式化当前时间{{year()}} # 当前年份完整函数参考：访问 [Nuclei 官方文档 - Helper Functions](https://docs.projectdiscovery.io/) 查看所有可用函数的详细说明  
  
条件逻辑和循环  
  
条件判断  
  
​

991234567891011121314151617181920# 简单条件{{if eq .status_code 200}} 请求成功{{else}} 请求失败{{end}}  
# 复杂条件{{if and (eq .status_code 200) (contains .body "success")}} 成功且包含 success{{else if eq .status_code 404}} 页面不存在{{else}} 其他情况{{end}}  
# 比较操作符{{if gt .status_code 400}} 错误状态 {{end}} # 大于{{if lt .content_length 1000}} 内容较少 {{end}} # 小于{{if ne .method "GET"}} 非 GET 请求 {{end}} # 不等于循环结构  
  
​

9123456789# 遍历数组{{range .headers}} {{.name}}: {{.value}}{{end}}  
# 带索引的遍历{{range $i, $header := .headers}} [{{$i}}] {{$header.name}}: {{$header.value}}{{end}}🎯 高级技巧  
  
多步骤攻击链  
  
模拟真实的渗透测试流程，通过多个请求步骤完成复杂的漏洞检测：  
  
​

99910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273requests: # 步骤 1：获取登录页面和 CSRF Token - method: GET path: - "{{BaseURL}}/login" extractors: - type: regex name: csrf_token part: body internal: true group: 1 regex: - '([a-zA-Z0-9]+)"' - type: regex name: session_id part: header internal: true group: 1 regex: - 'PHPSESSID=([A-Za-z0-9]+)'  
# 步骤 2：尝试登录并获取用户权限 - method: POST path: - "{{BaseURL}}/login" headers: Content-Type: "application/x-www-form-urlencoded" Cookie: "PHPSESSID={{session_id}}" body: | username=admin&password=admin123&csrf_token={{csrf_token}} extractors: - type: regex name: auth_token part: body internal: true group: 1 regex: - '"auth_token":"([a-zA-Z0-9]+)"' matchers: - type: word words: - "login successful" - "dashboard"  
# 步骤 3：访问管理员功能 - method: GET path: - "{{BaseURL}}/admin/users" headers: Authorization: "Bearer {{auth_token}}" Cookie: "PHPSESSID={{session_id}}" matchers: - type: word words: - "user management" - "admin panel" condition: or 负载攻击模式  
Nuclei 支持四种攻击模式来处理多个负载：  
  
Batteringram 模式  
  
使用同一个负载填充所有位置：  
  
​

9123456payloads: payload: ["admin", "root", "test"]  
attack: batteringram # admin/admin, root/root, test/test  
body: "username={{payload}}&password={{payload}}"Pitchfork 模式  
  
按位置顺序配对使用负载：  
  
​

91234567payloads: usernames: ["admin", "root", "guest"] passwords: ["admin123", "rootpass", "guest123"]  
attack: pitchfork # admin/admin123, root/rootpass, guest/guest123  
body: "username={{usernames}}&password={{passwords}}"Clusterbomb 模式  
  
所有负载的笛卡尔积组合：  
  
​

91234567payloads: usernames: ["admin", "root"] passwords: ["123", "pass", "admin"]  
attack: clusterbomb # 2×3=6 种组合  
body: "username={{usernames}}&password={{passwords}}" 外部交互检测（OAST）  
检测盲注、SSRF 等需要外部交互确认的漏洞：  
  
原始请求模板  
  
对于需要精确控制 HTTP 请求格式的场景：  
  
条件执行控制  
  
根据前置条件控制后续请求的执行：  
  
🎯 最佳实践  
  
1. 模板编写规范  
  
命名约定  
  
完整的信息字段  
  
2. 性能优化策略  
  
智能请求控制  
  
优化匹配器性能  
  
批量扫描优化  
  
3. 安全和道德考虑  
  
负责任的漏洞检测  
  
避免破坏性测试  
  
4. 错误处理和调试  
  
调试模式使用  
  
错误处理最佳实践  
  
5. 模板组织和管理  
  
目录结构建议  
  
Git 工作流程  
  
6. 集成和自动化  
  
CI/CD 集成示例（GitHub Actions）  
  
Docker 容器化扫描  
  
🎯 故障排除  
  
常见问题诊断  
  
1. 模板语法错误  
  
2. 网络连接问题  
  
3. 性能和内存问题  
  
4. 结果输出问题  
  
调试技巧  
  
模板调试流程  
  
性能分析  
  
错误代码和解决方案  
  
<table><colgroup><col width="250"><col width="250"><col width="249"></colgroup><tbody><tr><td data-col="0"><ne-p data-lake-id="uf85ca733"><ne-text>错误类型</ne-text><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u11e4c7f1"><ne-text>原因</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="ub08e8e76"><ne-text>解决方案</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u7e4dcbd8"><ne-code><ne-code-content><ne-text>template not found</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="uca68da9c"><ne-text>模板路径错误</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u30858a1e"><ne-text>检查</ne-text><ne-code><ne-code-content><ne-text> -t</ne-text></ne-code-content></ne-code><ne-text> 参数路径</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u4055eb4e"><ne-code><ne-code-content><ne-text>invalid yaml</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u03d408f5"><ne-text>YAML 语法错误</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="uf550660a"><ne-text>使用</ne-text><ne-code><ne-code-content><ne-text> -validate</ne-text></ne-code-content></ne-code><ne-text> 检查</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="ufd6e079f"><ne-code><ne-code-content><ne-text>connection timeout</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u0b863aea"><ne-text>网络连接超时</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u268df885"><ne-text>增加</ne-text><ne-code><ne-code-content><ne-text> -timeout</ne-text></ne-code-content></ne-code><ne-text> 值</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u6b55dc7f"><ne-code><ne-code-content><ne-text>too many requests</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u618997d0"><ne-text>速率限制触发</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="uf50899e8"><ne-text>降低</ne-text><ne-code><ne-code-content><ne-text> -rate-limit</ne-text></ne-code-content></ne-code><ne-text> 值</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u6117853b"><ne-code><ne-code-content><ne-text>memory allocation</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u4c91f3de"><ne-text>内存不足</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="ubc55a68f"><ne-text>减少</ne-text><ne-code><ne-code-content><ne-text> -c</ne-text></ne-code-content></ne-code><ne-text> 并发数</ne-text><br></ne-p></td></tr><tr><td data-col="0"><ne-p data-lake-id="u5b20e2e2"><ne-code><ne-code-content><ne-text>template execution failed</ne-text></ne-code-content></ne-code><br></ne-p></td><td data-col="1"><ne-p data-lake-id="u04047b97"><ne-text>模板执行错误</ne-text><br></ne-p></td><td data-col="2"><ne-p data-lake-id="u7e4d018d"><ne-text>检查模板逻辑和语法</ne-text><br></ne-p></td></tr></tbody></table>  
总结  
  
Nuclei 作为现代化的漏洞扫描器，通过其强大的模板系统为安全测试提供了极大的便利。掌握 Nuclei 需要：  
  
核心能力  
  
● ✅ 模板语法精通：熟练编写 YAML 检测模板  
● ✅ 函数库应用：善用内置函数和表达式  
● ✅ 性能优化：合理配置参数和并发策略  
● ✅ 实战经验：在真实环境中积累使用技巧  
进阶技能  
  
● 多协议支持：HTTP、DNS、TCP 等协议检测  
● 自动化集成：CI/CD 流程和监控告警  
● 社区贡献：编写高质量模板回馈社区  
● 安全意识：负责任的漏洞披露和道德使用