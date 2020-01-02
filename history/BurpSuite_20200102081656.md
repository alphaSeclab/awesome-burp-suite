# 所有收集类项目:
- [收集的所有开源工具: sec-tool-list](https://github.com/alphaSeclab/sec-tool-list): 超过18K, 包括Markdown和Json两种格式
- [全平台逆向资源: awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering):
    - Windows平台安全: PE/DLL/DLL-Injection/Dll-Hijack/Dll-Load/UAC-Bypass/Sysmon/AppLocker/ETW/WSL/.NET/Process-Injection/Code-Injection/DEP/Kernel/...
    - Linux安全: ELF/...
    - macOS/iXxx安全: Mach-O/越狱/LLDB/XCode/...
    - Android安全: HotFix/XPosed/Pack/Unpack/Emulator/Obfuscate
    - 知名工具: IDA/Ghidra/x64dbg/OllDbg/WinDBG/CuckooSandbox/Radare2/BinaryNinja/DynamoRIO/IntelPin/Frida/QEMU/...
- [攻击性网络安全资源: awesome-cyber-security](https://github.com/alphaSeclab/awesome-cyber-security): 漏洞/渗透/物联网安全/数据渗透/Metasploit/BurpSuite/KaliLinux/C&C/OWASP/免杀/CobaltStrike/侦查/OSINT/社工/密码/凭证/威胁狩猎/Payload/WifiHacking/无线攻击/后渗透/提权/UAC绕过/...
- [网络相关的安全资源: awesome-network-stuff](https://github.com/alphaSeclab/awesome-network-stuff): 
    - 网络通信: 代理/SS/V2ray/GFW/反向代理/隧道/VPN/Tor/I2P/...
    - 网络攻击: 中间人/PortKnocking/...
    - 网络分析: 嗅探/协议分析/网络可视化/网络分析/网络诊断等
- [开源远控和恶意远控分析报告: awesome-rat](https://github.com/alphaSeclab/awesome-rat): 开源远控工具: Windows/Linux/macOS/Android; 远控类恶意恶意代码的分析报告等
- [Webshell工具和分析/使用文章: awesome-webshell](https://github.com/alphaSeclab/awesome-webshell): Webshell资源收集, 包括150个Github项目, 200个左右文章
- [取证相关工具和文章: awesome-forensics](https://github.com/alphaSeclab/awesome-forensics): 近300个取开源取证工具，近600与取证相关文章
- [蜜罐资源: awesome-honeypot](https://github.com/alphaSeclab/awesome-honeypot): 250+个开源蜜罐工具，350+与蜜罐相关文章
- [Burp Suite资源: awesome-burp-suite](https://github.com/alphaSeclab/awesome-burp-suite): 400+个开源Burp插件，500+与Burp相关文章




# BurpSuite


- 400+ 开源Burp插件，500+文章和视频。
- [English Version](https://github.com/alphaSeclab/awesome-burp-suite/blob/master/Readme_en.md)


# 目录
- [工具](#39e9a0fe929fffe5721f7d7bb2dae547)
    - [(8) 收集](#6366edc293f25b57bf688570b11d6584)
    - [(89) 新添加](#5b761419863bc686be12c76451f49532)
    - [(170) 插件&&扩展](#6e42023365c5bdb7dc947efe3d7584ef)
    - [(51) 漏洞&&扫描](#90339d9a130e105e1617bff2c2ca9721)
    - [(24) 代理](#280b7fad90dd1238909425140c788365)
    - [(9) 日志](#19f0f074fc013e6060e96568076b7c9a)
    - [(11) XSS](#7a78bdcffe72cd39b193d93aaec80289)
    - [(8) Collaborator](#e0b6358d9096e96238b76258482a1c2f)
    - [(11) Fuzz](#e9a969fc073afb5add0b75607e43def0)
    - [(15) Payload](#fc5f535e219ba9694bb72df4c11b32bd)
    - [(10) SQL](#0481f52a7f7ee969fa5834227e49412e)
    - [(2) Android](#33431f1a7baa0f6193334ef4d74ff82c)
    - [(12) 其他](#01a878dcb14c47e0a1d05dc36ab95bfc)
- [文章](#dab83e734c8176aae854176552bff628)
    - [(522) 新添加](#ad95cb0314046788911641086ec4d674)


# <a id="39e9a0fe929fffe5721f7d7bb2dae547"></a>工具


***


## <a id="6366edc293f25b57bf688570b11d6584"></a>收集


- [**1982**星][1y] [BitBake] [1n3/intruderpayloads](https://github.com/1n3/intruderpayloads) BurpSuite Intruder Payload收集
- [**1112**星][1y] [Py] [bugcrowd/hunt](https://github.com/bugcrowd/HUNT) Burp和ZAP的扩展收集
- [**1108**星][2m] [snoopysecurity/awesome-burp-extensions](https://github.com/snoopysecurity/awesome-burp-extensions) Burp扩展收集
- [**917**星][15d] [Batchfile] [mr-xn/burpsuite-collections](https://github.com/mr-xn/burpsuite-collections) BurpSuite收集：包括不限于 Burp 文章、破解版、插件(非BApp Store)、汉化等相关教程
- [**96**星][2y] [Java] [jgillam/burp-co2](https://github.com/jgillam/burp-co2) A collection of enhancements for Portswigger's popular Burp Suite web penetration testing tool.
- [**87**星][9m] [Py] [laconicwolf/burp-extensions](https://github.com/laconicwolf/burp-extensions) A collection of scripts to extend Burp Suite
- [**58**星][22d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构
- [**22**星][4y] [Java] [ernw/burpsuite-extensions](https://github.com/ernw/burpsuite-extensions) A collection of Burp Suite extensions


***


## <a id="5b761419863bc686be12c76451f49532"></a>新添加


- [**378**星][3m] [Java] [nccgroup/autorepeater](https://github.com/nccgroup/autorepeater) Automated HTTP Request Repeating With Burp Suite
- [**376**星][2y] [Py] [0x4d31/burpa](https://github.com/0x4d31/burpa) A Burp Suite Automation Tool with Slack Integration. It can be used with Jenkins and Selenium to automate Dynamic Application Security Testing (DAST).
- [**371**星][4y] [JS] [allfro/burpkit](https://github.com/allfro/burpkit) Next-gen BurpSuite penetration testing tool
- [**299**星][1y] [Java] [vmware/burp-rest-api](https://github.com/vmware/burp-rest-api) REST/JSON API to the Burp Suite security tool.
- [**265**星][3y] [Java] [codewatchorg/bypasswaf](https://github.com/codewatchorg/bypasswaf) Add headers to all Burp requests to bypass some WAF products
- [**147**星][4m] [Java] [netsoss/headless-burp](https://github.com/netsoss/headless-burp) Automate security tests using Burp Suite.
- [**141**星][1y] [Java] [tomsteele/burpbuddy](https://github.com/tomsteele/burpbuddy) burpbuddy exposes Burp Suites's extender API over the network through various mediums, with the goal of enabling development in any language without the restrictions of the JVM
- [**118**星][1m] [Java] [nccgroup/decoder-improved](https://github.com/nccgroup/decoder-improved) Improved decoder for Burp Suite
- [**111**星][22d] [Java] [ozzi-/jwt4b](https://github.com/ozzi-/JWT4B) JWT Support for Burp
- [**110**星][2y] [Java] [x-ai/burpunlimitedre](https://github.com/x-ai/burpunlimitedre) This project !replace! BurpUnlimited of depend (BurpSutie version 1.7.27). It is NOT intended to replace them!
- [**103**星][7m] [Py] [kibodwapon/noeye](https://github.com/kibodwapon/noeye) A blind mode exploit framework (a dns server and a web app) that like wvs's AcuMonitor Service or burpsuite's collabrator or cloudeye
- [**99**星][4y] [Java] [summitt/burp-ysoserial](https://github.com/summitt/burp-ysoserial) YSOSERIAL Integration with burp suite
- [**84**星][2y] [Java] [yandex/burp-molly-pack](https://github.com/yandex/burp-molly-pack) Security checks pack for Burp Suite
- [**82**星][6y] [Py] [mwielgoszewski/burp-protobuf-decoder](https://github.com/mwielgoszewski/burp-protobuf-decoder) A simple Google Protobuf Decoder for Burp
- [**81**星][8m] [Py] [leoid/matchandreplace](https://github.com/leoid/matchandreplace) Match and Replace script used to automatically generate JSON option file to BurpSuite
- [**70**星][6y] [Java] [irsdl/burpsuitejsbeautifier](https://github.com/irsdl/burpsuitejsbeautifier) Burp Suite JS Beautifier
- [**70**星][2m] [Py] [ziirish/burp-ui](https://github.com/ziirish/burp-ui) a web-ui for burp backup written in python with Flask and jQuery/Bootstrap
- [**68**星][3y] [Py] [stayliv3/burpsuite-changeu](https://github.com/stayliv3/burpsuite-changeu) burpsuite 插件。将返回值中的unicode明文
- [**59**星][5y] [Ruby] [tduehr/buby](https://github.com/tduehr/buby) A JRuby implementation of the BurpExtender interface for PortSwigger Burp Suite.
- [**53**星][2m] [Java] [coreyd97/stepper](https://github.com/coreyd97/stepper) A natural evolution of Burp Suite's Repeater tool
- [**52**星][5y] [Py] [jfoote/burp-git-bridge](https://github.com/jfoote/burp-git-bridge) Store Burp data and collaborate via git
- [**50**星][2m] [Java] [portswigger/stepper](https://github.com/portswigger/stepper) A natural evolution of Burp Suite's Repeater tool
- [**48**星][1y] [java] [anbai-inc/burpstart](https://github.com/anbai-inc/burpstart) Burp 启动加载器
- [**46**星][2m] [Py] [hvqzao/report-ng](https://github.com/hvqzao/report-ng) Generate MS Word template-based reports with HP WebInspect / Burp Suite Pro input, own custom data and knowledge base.
- [**45**星][1y] [Ruby] [pentestgeek/burpcommander](https://github.com/pentestgeek/burpcommander) Ruby command-line interface to Burp Suite's REST API
- [**42**星][11m] [Java] [secdec/attack-surface-detector-burp](https://github.com/secdec/attack-surface-detector-burp) The Attack Surface Detector uses static code analyses to identify web app endpoints by parsing routes and identifying parameters
- [**41**星][12m] [Py] [zynga/hiccup](https://github.com/zynga/hiccup) [DEPRECATED] Hiccup is a framework that allows the Burp Suite (a web application security testing tool,
- [**41**星][6y] [PHP] [spiderlabs/upnp-request-generator](https://github.com/spiderlabs/upnp-request-generator) A tool to parse UPnP descriptor XML files and generate SOAP control requests for use with Burp Suite or netcat
- [**40**星][11m] [Go] [joanbono/gurp](https://github.com/joanbono/gurp) Burp Commander written in Go
- [**39**星][8m] [Dockerfile] [marco-lancini/docker_burp](https://github.com/marco-lancini/docker_burp) Burp Pro as a Docker Container
- [**38**星][2m] [Py] [zephrfish/burpfeed](https://github.com/zephrfish/burpfeed) Hacked together script for feeding urls into Burp's Sitemap
- [**36**星][8y] [Py] [gdssecurity/burpee](https://github.com/gdssecurity/burpee) Python object interface to requests/responses recorded by Burp Suite
- [**36**星][8y] [C#] [gdssecurity/wcf-binary-soap-plug-in](https://github.com/gdssecurity/wcf-binary-soap-plug-in) a Burp Suite plug-in designed to encode and decode WCF Binary Soap request and response data ("Content-Type: application/soap+msbin1)
- [**35**星][7y] [Java] [continuumsecurity/resty-burp](https://github.com/continuumsecurity/resty-burp) REST/JSON interface to Burp Suite
- [**35**星][1y] [Java] [bit4woo/resign](https://github.com/bit4woo/ReSign) A burp extender that recalculate signature value automatically after you modified request parameter value.
- [**33**星][3y] [Go] [tomsteele/burpstaticscan](https://github.com/tomsteele/burpstaticscan) Use burp's JS static code analysis on code from your local system.
- [**32**星][10m] [twelvesec/bearerauthtoken](https://github.com/twelvesec/bearerauthtoken) This burpsuite extender provides a solution on testing Enterprise applications that involve security Authorization tokens into every HTTP requests.Furthermore, this solution provides a better approach to solve the problem of Burp suite automated scanning failures when Authorization tokens exist.
- [**28**星][2y] [Java] [bit4woo/gui_burp_extender_para_encrypter](https://github.com/bit4woo/gui_burp_extender_para_encrypter) Burp_Extender_para_encrypter
- [**28**星][4y] [Java] [burp-hash/burp-hash](https://github.com/burp-hash/burp-hash) a Burp Suite plugin.
- [**28**星][4y] [Py] [smeegesec/burp-importer](https://github.com/smeegesec/burp-importer) Burp Suite Importer - Connect to multiple web servers while populating the sitemap.
- [**28**星][6m] [Java] [bit4woo/burp-api-drops](https://github.com/bit4woo/burp-api-drops) burp suite API 处理http请求和响应的基本流程
- [**25**星][3y] [Java] [pokeolaf/pokemongodecoderforburp](https://github.com/pokeolaf/pokemongodecoderforburp) A simpe decoder to decode requests/responses made by PokemonGo in burp
- [**22**星][7m] [Java] [ettic-team/endpointfinder-burp](https://github.com/ettic-team/endpointfinder-burp) burp plugin to find endpoint
- [**22**星][2y] [Java] [silentsignal/burp-uuid](https://github.com/silentsignal/burp-uuid) UUID issues for Burp Suite
- [**21**星][5y] [Java] [khai-tran/burpjdser](https://github.com/khai-tran/burpjdser) a Burp plugin that will deserialze/serialize Java request and response to and from XML with the use of Xtream library
- [**21**星][2m] [Java] [portswigger/json-web-tokens](https://github.com/portswigger/json-web-tokens) JWT Support for Burp
- [**18**星][7y] [Java] [omercnet/burpjdser-ng](https://github.com/omercnet/burpjdser-ng) BurpJDSer-ng
- [**18**星][2m] [Java] [silentsignal/burp-json-jtree](https://github.com/silentsignal/burp-json-jtree) JSON JTree viewer for Burp Suite
- [**18**星][2m] [Py] [xscorp/burpee](https://github.com/xscorp/burpee) A python module that accepts an HTTP request file and returns a dictionary of headers and post data
- [**17**星][3m] [BitBake] [sy3omda/burp-bounty](https://github.com/sy3omda/burp-bounty)  is extension of Burp Suite that improve Burp scanner.
- [**16**星][2y] [Visual Basic .NET] [xcanwin/xburpcrack](https://github.com/xcanwin/xburpcrack) This is a tool to bypass the cracked version of the burpsuite_pro(Larry_Lau) certification deadline through time reversal.
- [**15**星][11m] [Java] [portswigger/auto-repeater](https://github.com/portswigger/auto-repeater) Automated HTTP Request Repeating With Burp Suite
- [**14**星][7m] [Java] [portswigger/openapi-parser](https://github.com/portswigger/openapi-parser) Parse OpenAPI specifications, previously known as Swagger specifications, into the BurpSuite for automating RESTful API testing – approved by Burp for inclusion in their official BApp Store.
- [**13**星][14d] [Java] [ankokuty/belle](https://github.com/ankokuty/belle) Belle (Burp Suite 非公式日本語化ツール)
- [**13**星][6y] [Java] [ioactive/burpjdser-ng](https://github.com/ioactive/burpjdser-ng) Allows you to deserialize java objects to XML and lets you dynamically load classes/jars as needed
- [**13**星][2y] [Java] [netspi/jsonbeautifier](https://github.com/netspi/jsonbeautifier) JSON Beautifier for Burp written in Java
- [**12**星][2y] [Java] [portswigger/json-beautifier](https://github.com/portswigger/json-beautifier) JSON Beautifier for Burp written in Java
- [**11**星][9m] [Py] [anandtiwarics/python-burp-rest-api](https://github.com/anandtiwarics/python-burp-rest-api) Python Package for burprestapi
- [**11**星][2y] [Java] [gozo-mt/burplist](https://github.com/gozo-mt/burplist) A jython wordlist creator in-line with Burp-suite
- [**10**星][3y] [Java] [portswigger/bypass-waf](https://github.com/portswigger/bypass-waf) Add headers to all Burp requests to bypass some WAF products
- [**10**星][2y] [Py] [sahildhar/burpextenderpractise](https://github.com/sahildhar/BurpExtenderPractise) burp extender practise
- [**8**星][3y] [Java] [silentsignal/burp-cfurl-cache](https://github.com/silentsignal/burp-cfurl-cache) CFURL Cache inspector for Burp Suite
- [**7**星][2y] [Java] [jgillam/serphper](https://github.com/jgillam/serphper) Serialized PHP toolkit for Burp Suite
- [**6**星][10m] [raspberrypilearning/burping-jelly-baby](https://github.com/raspberrypilearning/burping-jelly-baby) Make a Jelly Baby burp by pressing it!
- [**6**星][11m] [chef-koch/windows-redstone-4-1803-data-analysis](https://github.com/chef-koch/windows-redstone-4-1803-data-analysis) Explains the telemetry, opt-out methods and provides some Whireshark/Burp dumps in order to see what MS really transmit
- [**5**星][4y] [Py] [cyberdefenseinstitute/burp-msgpack](https://github.com/cyberdefenseinstitute/burp-msgpack) MessagePack converter
- [**5**星][2y] [Java] [silentsignal/burp-commentator](https://github.com/silentsignal/burp-commentator) Generates comments for selected request(s) based on regular expressions
- [**4**星][7y] [Py] [dnet/burp-gwt-wrapper](https://github.com/dnet/burp-gwt-wrapper) Burp Suite GWT wrapper
- [**4**星][2y] [Ruby] [geoffwalton/burp-command](https://github.com/geoffwalton/burp-command) 
- [**4**星][2y] [Java] [silentsignal/burp-git-version](https://github.com/silentsignal/burp-git-version) 
- [**4**星][6m] [Java] [virusdefender/burptime](https://github.com/virusdefender/burptime) Burp Show Response Time
- [**4**星][12d] [Java] [gdgd009xcd/automacrobuilder](https://github.com/gdgd009xcd/automacrobuilder) multi step request sequencer AutoMacroBuilder for burpsuite
- [**3**星][6y] [Java] [directdefense/noncetracker](https://github.com/directdefense/noncetracker) A Burp extender module that tracks and updates nonce values per a specific application action.
- [**3**星][3y] [Batchfile] [jas502n/burpsuite_pro_v1.7.11-crack](https://github.com/jas502n/burpsuite_pro_v1.7.11-crack) BurpSuite_pro_v1.7.11-Crack 破解版 抓包神器
- [**3**星][2y] [Py] [niemand-sec/burp-scan-them-all](https://github.com/niemand-sec/burp-scan-them-all) Small script for automatizing Burp with Carbonator and slack
- [**2**星][1y] [Py] [bao7uo/burpelfish](https://github.com/bao7uo/burpelfish) BurpelFish - Adds Google Translate to Burp's Context Menu. "Babel Fish" language translation for app-sec testing in other languages.
- [**2**星][2y] [Java] [cornerpirate/demoextender](https://github.com/cornerpirate/demoextender) Code used for a tutorial to get Netbeans GUI editor to work with a Burp Suite Extender
- [**2**星][2y] [Py] [dnet/burp-scripts](https://github.com/dnet/burp-scripts) Scripts I wrote to extend Burp Suite functionality
- [**2**星][5y] [Shell] [evilpacket/bower-burp-static-analysis](https://github.com/evilpacket/bower-burp-static-analysis) Nov 2014 scan of bower using burp suite static analysis engine
- [**2**星][6y] [Py] [meatballs1/burp_wicket_handler](https://github.com/meatballs1/burp_wicket_handler) 
- [**2**星][4y] [Py] [mwielgoszewski/burp-jython-tab](https://github.com/mwielgoszewski/burp-jython-tab) 
- [**2**星][1y] [Java] [peachtech/peachapisec-burp](https://github.com/peachtech/peachapisec-burp) Peach API Security Burp Integration
- [**1**星][2y] [Java] [sampsonc/perfmon](https://github.com/sampsonc/perfmon) Performance metrics for Burp Suite
- [**1**星][30d] [Java] [bytebutcher/burp-send-to](https://github.com/bytebutcher/burp-send-to) Adds a customizable "Send to..."-context-menu to your BurpSuite.
- [**0**星][2y] [Java] [adityachaudhary/phantom-cryptor](https://github.com/adityachaudhary/phantom-cryptor) Burp Suite extender to encrypt requests and decrypt response.
- [**0**星][1y] [jgamblin/burptest](https://github.com/jgamblin/burptest) 
- [**0**星][2y] [kkirsche/burp_suite_lists](https://github.com/kkirsche/burp_suite_lists) Lists to use with Burp Suite
- [**0**星][3y] [Java] [luj1985/albatross](https://github.com/luj1985/albatross) XML Fast Infoset decoder for Burp Suite
- [**0**星][2y] [Java] [silentsignal/burp-asn1](https://github.com/silentsignal/burp-asn1) ASN.1 toolbox for Burp Suite


***


## <a id="6e42023365c5bdb7dc947efe3d7584ef"></a>插件&&扩展


- [**730**星][2y] [JS] [xl7dev/burpsuite](https://github.com/xl7dev/burpsuite) BurpSuite using the document and some extensions
- [**715**星][1y] [Java] [d3vilbug/hackbar](https://github.com/d3vilbug/hackbar) HackBar plugin for Burpsuite
- [**605**星][10m] [Java] [c0ny1/chunked-coding-converter](https://github.com/c0ny1/chunked-coding-converter) Burp suite 分块传输辅助插件
- [**445**星][7m] [Py] [albinowax/activescanplusplus](https://github.com/albinowax/activescanplusplus) ActiveScan++ Burp Suite Plugin
- [**410**星][8m] [Java] [nccgroup/burpsuitehttpsmuggler](https://github.com/nccgroup/burpsuitehttpsmuggler) A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
- [**366**星][23d] [Java] [portswigger/http-request-smuggler](https://github.com/PortSwigger/http-request-smuggler) an extension for Burp Suite designed to help you launch HTTP Request Smuggling attack
- [**364**星][14d] [Kotlin] [portswigger/turbo-intruder](https://github.com/portswigger/turbo-intruder) a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.
- [**359**星][5m] [Java] [bit4woo/domain_hunter](https://github.com/bit4woo/domain_hunter) 利用burp收集整个企业、组织的域名（不仅仅是单个主域名）的插件
- [**341**星][2y] [Py] [securityinnovation/authmatrix](https://github.com/securityinnovation/authmatrix) AuthMatrix is a Burp Suite extension that provides a simple way to test authorization in web applications and web services.
- [**340**星][2y] [Py] [pathetiq/burpsmartbuster](https://github.com/pathetiq/burpsmartbuster) A Burp Suite content discovery plugin that add the smart into the Buster!
- [**336**星][23d] [Java] [bit4woo/knife](https://github.com/bit4woo/knife) A burp extension that add some useful function to Context Menu 添加一些右键菜单让burp用起来更顺畅
- [**310**星][1y] [Java] [ebryx/aes-killer](https://github.com/ebryx/aes-killer) Burp plugin to decrypt AES Encrypted traffic of mobile apps on the fly
- [**273**星][2m] [Py] [quitten/autorize](https://github.com/quitten/autorize) Automatic authorization enforcement detection extension for burp suite written in Jython developed by Barak Tawily in order to ease application security people work and allow them perform an automatic authorization tests
- [**257**星][3m] [Py] [rhinosecuritylabs/iprotate_burp_extension](https://github.com/rhinosecuritylabs/iprotate_burp_extension) Extension for Burp Suite which uses AWS API Gateway to rotate your IP on every request.
- [**250**星][1m] [Java] [c0ny1/jsencrypter](https://github.com/c0ny1/jsencrypter) 一个用于加密传输爆破的Burp Suite插件
- [**246**星][5m] [Py] [initroot/burpjslinkfinder](https://github.com/initroot/burpjslinkfinder) Burp Extension for a passive scanning JS files for endpoint links.
- [**244**星][3m] [Java] [c0ny1/passive-scan-client](https://github.com/c0ny1/passive-scan-client) Burp被动扫描流量转发插件
- [**238**星][3m] [Java] [samlraider/samlraider](https://github.com/samlraider/samlraider) SAML2 Burp Extension
- [**191**星][2y] [Java] [p3gleg/pwnback](https://github.com/P3GLEG/PwnBack) Burp Extender plugin that generates a sitemap of a website using Wayback Machine
- [**175**星][2y] [Py] [virtuesecurity/aws-extender](https://github.com/virtuesecurity/aws-extender) a Burp plugin to assess permissions of cloud storage containers on AWS, Google Cloud and Azure.
- [**174**星][3m] [Java] [lilifengcode/burpsuite-plugins-usage](https://github.com/lilifengcode/burpsuite-plugins-usage) Burpsuite-Plugins-Usage
- [**160**星][1m] [Py] [regala/burp-scope-monitor](https://github.com/regala/burp-scope-monitor) Burp Suite Extension to monitor new scope
- [**159**星][5m] [Java] [netspi/javaserialkiller](https://github.com/netspi/javaserialkiller) Burp extension to perform Java Deserialization Attacks
- [**158**星][1y] [Py] [bayotop/off-by-slash](https://github.com/bayotop/off-by-slash) Bupr扩展, 检测利用Nginx错误配置导致的重名遍历(alias traversal)
- [**157**星][7m] [Py] [thekingofduck/burpfakeip](https://github.com/thekingofduck/burpfakeip) 一个用于伪造ip地址进行爆破的Burp Suite插件
- [**149**星][3y] [Java] [mwielgoszewski/jython-burp-api](https://github.com/mwielgoszewski/jython-burp-api) Develop Burp extensions in Jython
- [**143**星][6m] [Py] [codingo/minesweeper](https://github.com/codingo/minesweeper) A Burpsuite plugin (BApp) to aid in the detection of scripts being loaded from over 23000 malicious cryptocurrency mining domains (cryptojacking).
- [**137**星][2y] [Java] [netspi/wsdler](https://github.com/netspi/wsdler) WSDL Parser extension for Burp
- [**123**星][4y] [Py] [moloch--/csp-bypass](https://github.com/moloch--/csp-bypass) A Burp Plugin for Detecting Weaknesses in Content Security Policies
- [**121**星][1m] [Py] [redhuntlabs/burpsuite-asset_discover](https://github.com/redhuntlabs/burpsuite-asset_discover) Burp Suite extension to discover assets from HTTP response.
- [**119**星][6y] [Py] [meatballs1/burp-extensions](https://github.com/meatballs1/burp-extensions) Burp Suite Extensions
- [**118**星][2m] [Py] [prodigysml/dr.-watson](https://github.com/prodigysml/dr.-watson) a simple Burp Suite extension that helps find assets, keys, subdomains, IP addresses, and other useful information!
- [**103**星][2y] [Java] [clr2of8/gathercontacts](https://github.com/clr2of8/gathercontacts) A Burp Suite Extension to pull Employee Names from Google and Bing LinkedIn Search Results
- [**103**星][2y] [Java] [gosecure/csp-auditor](https://github.com/gosecure/csp-auditor) Burp and ZAP plugin to analyse Content-Security-Policy headers or generate template CSP configuration from crawling a Website
- [**102**星][3m] [Java] [netspi/burp-extensions](https://github.com/netspi/burp-extensions) Central Repo for Burp extensions
- [**95**星][19d] [Py] [m4ll0k/burpsuite-secret_finder](https://github.com/m4ll0k/burpsuite-secret_finder) Burp Suite extension to discover apikeys/accesstokens and sensitive data from HTTP response.
- [**89**星][3y] [Java] [dobin/burpsentinel](https://github.com/dobin/burpsentinel) GUI Burp Plugin to ease discovering of security holes in web applications
- [**89**星][8m] [Py] [lopseg/jsdir](https://github.com/Lopseg/Jsdir) a Burp Suite extension that extracts hidden paths from js files and beautifies it for further reading.
- [**88**星][2y] [Java] [silentsignal/burp-image-size](https://github.com/silentsignal/burp-image-size) Image size issues plugin for Burp Suite
- [**87**星][10m] [Java] [doyensec/burpdeveltraining](https://github.com/doyensec/burpdeveltraining) Material for the training "Developing Burp Suite Extensions – From Manual Testing to Security Automation"
- [**83**星][1m] [Java] [jgillam/burp-paramalyzer](https://github.com/jgillam/burp-paramalyzer) Burp extension for parameter analysis of large-scale web application penetration tests.
- [**83**星][1y] [Py] [nccgroup/blackboxprotobuf](https://github.com/nccgroup/blackboxprotobuf) Blackbox protobuf is a Burp Suite extension for decoding and modifying arbitrary protobuf messages without the protobuf type definition.
- [**75**星][1y] [Java] [bit4woo/u2c](https://github.com/bit4woo/u2c) Unicode To Chinese -- U2C : A burpsuite Extender That Convert Unicode To Chinese 【Unicode编码转中文的burp插件】
- [**73**星][2y] [Java] [spiderlabs/burplay](https://github.com/spiderlabs/burplay) Burplay is a Burp Extension allowing for replaying any number of requests using same modifications definition. Its main purpose is to aid in searching for Privilege Escalation issues.
- [**69**星][12d] [Java] [c0ny1/captcha-killer](https://github.com/c0ny1/captcha-killer) burp验证码识别接口调用插件
- [**65**星][2y] [Py] [markclayton/bumpster](https://github.com/markclayton/bumpster) The Unofficial Burp Extension for DNSDumpster.com
- [**64**星][1y] [Java] [c0ny1/httpheadmodifer](https://github.com/c0ny1/httpheadmodifer) 一款快速修改HTTP数据包头的Burp Suite插件
- [**63**星][5m] [Java] [nccgroup/berserko](https://github.com/nccgroup/berserko) Burp Suite extension to perform Kerberos authentication
- [**58**星][11m] [Java] [portswigger/replicator](https://github.com/portswigger/replicator) Burp extension to help developers replicate findings from pen tests
- [**57**星][6y] [Java] [spiderlabs/burpnotesextension](https://github.com/spiderlabs/burpnotesextension) a plugin for Burp Suite that adds a Notes tab. The tool aims to better organize external files that are created during penetration testing.
- [**51**星][1y] [Java] [netspi/burpextractor](https://github.com/netspi/burpextractor) A Burp extension for generic extraction and reuse of data within HTTP requests and responses.
- [**48**星][2y] [Java] [inode-/attackselector](https://github.com/inode-/attackselector) Burp Suite Attack Selector Plugin
- [**46**星][28d] [Java] [netspi/awssigner](https://github.com/netspi/awssigner) Burp Extension for AWS Signing
- [**43**星][1y] [Py] [br3akp0int/gqlparser](https://github.com/br3akp0int/gqlparser) A repository for GraphQL Extension for Burp Suite
- [**42**星][5m] [Py] [gh0stkey/jsonandhttpp](https://github.com/gh0stkey/JSONandHTTPP) Burp Suite Plugin to convert the json text that returns the body into HTTP request parameters.
- [**40**星][6y] [Java] [wuntee/burpauthzplugin](https://github.com/wuntee/burpauthzplugin) Burp plugin to test for authorization flaws
- [**39**星][11m] [Java] [tijme/similar-request-excluder](https://github.com/tijme/similar-request-excluder) A Burp Suite extension that automatically marks similar requests as 'out-of-scope'.
- [**37**星][1y] [Java] [augustd/burp-suite-error-message-checks](https://github.com/augustd/burp-suite-error-message-checks) Burp Suite extension to passively scan for applications revealing server error messages
- [**36**星][3y] [Py] [0ang3el/unsafe-jax-rs-burp](https://github.com/0ang3el/unsafe-jax-rs-burp) Burp Suite extension for JAX-RS
- [**35**星][1y] [Java] [ikkisoft/blazer](https://github.com/ikkisoft/blazer) Burp Suite AMF Extension
- [**35**星][11d] [Kotlin] [typeerror/bookmarks](https://github.com/typeerror/bookmarks) A Burp Suite Extension to take back your repeater tabs
- [**34**星][5y] [Py] [dionach/headersanalyzer](https://github.com/dionach/headersanalyzer) Burp extension that checks for interesting and security headers
- [**34**星][2y] [Py] [penafieljlm/burp-tracer](https://github.com/penafieljlm/burp-tracer) BurpSuite 扩展。获取当前的站点地图，提取每个请求参数，并搜索存在请求参数值的回复
- [**33**星][2y] [Java] [dnet/burp-oauth](https://github.com/dnet/burp-oauth) OAuth plugin for Burp Suite Extender
- [**33**星][2m] [Java] [rub-nds/tls-attacker-burpextension](https://github.com/rub-nds/tls-attacker-burpextension) assist in the evaluation of TLS Server configurations with Burp Suite.
- [**32**星][5y] [Java] [malerisch/burp-csj](https://github.com/malerisch/burp-csj) BurpCSJ extension for Burp Pro - Crawljax Selenium JUnit integration
- [**32**星][7m] [Py] [portswigger/active-scan-plus-plus](https://github.com/portswigger/active-scan-plus-plus) ActiveScan++ Burp Suite Plugin
- [**30**星][4y] [Py] [carstein/burp-extensions](https://github.com/carstein/burp-extensions) Automatically exported from code.google.com/p/burp-extensions
- [**30**星][7y] [Py] [meatballs1/burp_jsbeautifier](https://github.com/meatballs1/burp_jsbeautifier) js-beautifier extension for Burp Suite
- [**30**星][4m] [Py] [portswigger/js-link-finder](https://github.com/portswigger/js-link-finder) Burp Extension for a passive scanning JS files for endpoint links.
- [**29**星][8m] [Java] [hvqzao/burp-flow](https://github.com/hvqzao/burp-flow) Extension providing view with filtering capabilities for both complete and incomplete requests from all burp tools.
- [**26**星][10m] [Kotlin] [gosecure/burp-ntlm-challenge-decoder](https://github.com/gosecure/burp-ntlm-challenge-decoder) Burp extension to decode NTLM SSP headers and extract domain/host information
- [**24**星][2y] [Py] [portswigger/burp-smart-buster](https://github.com/portswigger/burp-smart-buster) A Burp Suite content discovery plugin that add the smart into the Buster!
- [**24**星][3y] [Py] [silentsignal/activescan3plus](https://github.com/silentsignal/activescan3plus) Modified version of ActiveScan++ Burp Suite extension
- [**23**星][2y] [Py] [aur3lius-dev/spydir](https://github.com/aur3lius-dev/spydir) BurpSuite extension to assist with Automated Forced Browsing/Endpoint Enumeration
- [**23**星][5m] [Py] [elespike/burp-cph](https://github.com/elespike/burp-cph) Custom Parameter Handler extension for Burp Suite.
- [**23**星][2y] [Ruby] [zidekmat/graphql_beautifier](https://github.com/zidekmat/graphql_beautifier) Burp Suite extension to help make Graphql request more readable
- [**22**星][8m] [Java] [silentsignal/burp-requests](https://github.com/silentsignal/burp-requests) Copy as requests plugin for Burp Suite
- [**21**星][2y] [Py] [unamer/ctfhelper](https://github.com/unamer/ctfhelper) A simple Burp extension for scanning stuffs in CTF
- [**20**星][3y] [Ruby] [kingsabri/burp_suite_extension_ruby](https://github.com/kingsabri/burp_suite_extension_ruby) BurpSuite Extension Ruby Template to speed up building a Burp Extension using Ruby
- [**20**星][3y] [Py] [securitymb/burp-exceptions](https://github.com/securitymb/burp-exceptions) Simple trick to increase readability of exceptions raised by Burp extensions written in Python
- [**19**星][8m] [Java] [hvqzao/burp-wildcard](https://github.com/hvqzao/burp-wildcard) Burp extension intended to compact Burp extension tabs by hijacking them to own tab.
- [**19**星][5y] [Java] [nccgroup/wcfdser-ngng](https://github.com/nccgroup/wcfdser-ngng) A Burp Extender plugin, that will make binary soap objects readable and modifiable.
- [**18**星][4m] [Java] [augustd/burp-suite-software-version-checks](https://github.com/augustd/burp-suite-software-version-checks) Burp extension to passively scan for applications revealing software version numbers
- [**17**星][2m] [Java] [phefley/burp-javascript-security-extension](https://github.com/phefley/burp-javascript-security-extension) A Burp Suite extension which performs checks for cross-domain scripting against the DOM, subresource integrity checks, and evaluates JavaScript resources against threat intelligence data.
- [**17**星][7m] [Py] [yeswehack/yesweburp](https://github.com/yeswehack/yesweburp) YesWeHack Api Extension for Burp
- [**15**星][4y] [Java] [shengqi158/rsa-crypto-burp-extention](https://github.com/shengqi158/rsa-crypto-burp-extention) burp 插件 用于RSA 数据包加解密
- [**15**星][10m] [Java] [twelvesec/jdser-dcomp](https://github.com/twelvesec/jdser-dcomp) A Burp Extender plugin that will allow you to tamper with requests containing compressed, serialized java objects.
- [**15**星][1y] [Py] [portswigger/nginx-alias-traversal](https://github.com/portswigger/nginx-alias-traversal) Burp extension to detect alias traversal via NGINX misconfiguration at scale.
- [**14**星][3y] [JS] [rinetd/burpsuite-1](https://github.com/rinetd/burpsuite-1) BurpSuite using the document and some extensions
- [**13**星][5y] [Py] [enablesecurity/identity-crisis](https://github.com/enablesecurity/identity-crisis) A Burp Suite extension that checks if a particular URL responds differently to various User-Agent headers
- [**13**星][7m] [Py] [modzero/burp-responseclusterer](https://github.com/modzero/burp-responseclusterer) Burp plugin that clusters responses to show an overview of received responses
- [**13**星][1y] [Java] [moeinfatehi/admin-panel_finder](https://github.com/moeinfatehi/admin-panel_finder) A burp suite extension that enumerates infrastructure and application admin interfaces (OTG-CONFIG-005)
- [**13**星][7m] [Py] [solomonsklash/sri-check](https://github.com/SolomonSklash/sri-check) A Burp Suite extension for identifying missing Subresource Integrity attributes.
- [**12**星][3m] [Java] [augustd/burp-suite-utils](https://github.com/augustd/burp-suite-utils) Utilities for creating Burp Suite Extensions.
- [**12**星][5y] [Java] [federicodotta/burpjdser-ng-edited](https://github.com/federicodotta/burpjdser-ng-edited) Burp Suite plugin that allow to deserialize Java objects and convert them in an XML format. Unpack also gzip responses. Based on BurpJDSer-ng of omercnet.
- [**12**星][7y] [Py] [infodel/burp.extension-googlehack](https://github.com/infodel/burp.extension-googlehack) Burp Suite Extension providing Google Hacking Interface
- [**11**星][2y] [Ruby] [crashgrindrips/burp-dump](https://github.com/crashgrindrips/burp-dump) A Burp plugin to dump HTTP(S) requests/responses to a file system
- [**11**星][6y] [Py] [faffi/curlit](https://github.com/faffi/curlit) Burp plugin to turn requests into curl commands
- [**11**星][3y] [Java] [h3xstream/burp-image-metadata](https://github.com/h3xstream/burp-image-metadata) Burp and ZAP plugin that display image metadata (JPEG Exif or PNG text chunk).
- [**11**星][2y] [Java] [hvqzao/burp-token-rewrite](https://github.com/hvqzao/burp-token-rewrite) Burp extension for automated handling of CSRF tokens
- [**11**星][2y] [Java] [portswigger/attack-selector](https://github.com/portswigger/attack-selector) Burp Suite Attack Selector Plugin
- [**11**星][7m] [Java] [portswigger/copy-as-python-requests](https://github.com/portswigger/copy-as-python-requests) Copy as requests plugin for Burp Suite
- [**11**星][6y] [Py] [smeegesec/wsdlwizard](https://github.com/smeegesec/wsdlwizard) WSDL Wizard is a Burp Suite plugin written in Python to detect current and discover new WSDL (Web Service Definition Language) files.
- [**11**星][4y] [Java] [monikamorrow/burp-suite-extension-examples](https://github.com/monikamorrow/Burp-Suite-Extension-Examples) Burp Suite starter example projects.
- [**10**星][2y] [HTML] [adriancitu/burp-tabnabbing-extension](https://github.com/adriancitu/burp-tabnabbing-extension) Burp Suite Professional extension in Java for Tabnabbing attack
- [**10**星][6y] [Java] [xxux11/burpheartbleedextension](https://github.com/xxux11/burpheartbleedextension) Burp Heartbleed Extension
- [**10**星][2y] [Java] [c0ny1/burp-cookie-porter](https://github.com/c0ny1/burp-cookie-porter) 一个可快速“搬运”cookie的Burp Suite插件
- [**10**星][2y] [Java] [portswigger/kerberos-authentication](https://github.com/portswigger/kerberos-authentication) Burp Suite extension to perform Kerberos authentication
- [**9**星][5y] [Java] [allfro/dotnetbeautifier](https://github.com/allfro/dotnetbeautifier) A BurpSuite extension for beautifying .NET message parameters and hiding some of the extra clutter that comes with .NET web apps (i.e. __VIEWSTATE).
- [**9**星][4y] [Java] [augustd/burp-suite-gwt-scan](https://github.com/augustd/burp-suite-gwt-scan) Burp Suite plugin identifies insertion points for GWT (Google Web Toolkit) requests
- [**9**星][7m] [Py] [defectdojo/burp-plugin](https://github.com/defectdojo/burp-plugin) A Burp plugin to export findings to DefectDojo
- [**9**星][1y] [Java] [sampsonc/authheaderupdater](https://github.com/sampsonc/authheaderupdater) Burp extension to specify the token value for the Authenication header while scanning.
- [**9**星][2y] [Java] [aoncyberlabs/fastinfoset-burp-plugin](https://github.com/AonCyberLabs/FastInfoset-Burp-Plugin) Burp plugin to convert fast infoset (FI) to/from the text-based XML document format allowing easy editing
- [**8**星][2y] [Py] [bao7uo/waf-cookie-fetcher](https://github.com/bao7uo/waf-cookie-fetcher) WAF Cookie Fetcher is a Burp Suite extension written in Python, which uses a headless browser to obtain the values of WAF-injected cookies which are calculated in the browser by client-side JavaScript code and adds them to Burp's cookie jar. Requires PhantomJS.
- [**8**星][6y] [Java] [cyberisltd/post2json](https://github.com/cyberisltd/post2json) Burp Suite Extension to convert a POST request to JSON message, moving any .NET request verification token to HTTP headers if present
- [**8**星][3y] [Java] [eonlight/burpextenderheaderchecks](https://github.com/eonlight/burpextenderheaderchecks) A Burp Suite Extension that adds Header Checks and other helper functionalities
- [**8**星][2y] [Java] [rammarj/csrf-poc-creator](https://github.com/rammarj/csrf-poc-creator) A Burp Suite extension for CSRF proof of concepts.
- [**8**星][5m] [Py] [fsecurelabs/timeinator](https://github.com/FSecureLABS/timeinator) Timeinator is an extension for Burp Suite that can be used to perform timing attacks over an unreliable network such as the internet.
- [**7**星][3y] [Java] [dibsy/staticanalyzer](https://github.com/dibsy/staticanalyzer) StaticAnalyzer is a burp plugin that can be used to perform static analysis of the response information from server during run time. It will search for specific words in the response that is mentioned in the vectors.txt
- [**7**星][3y] [Ruby] [dradis/burp-dradis](https://github.com/dradis/burp-dradis) Dradis Framework extension for Burp Suite
- [**7**星][3y] [Java] [fruh/extendedmacro](https://github.com/fruh/extendedmacro) ExtendedMacro - BurpSuite plugin providing extended macro functionality
- [**7**星][1y] [Java] [pajswigger/add-request-to-macro](https://github.com/pajswigger/add-request-to-macro) Burp extension to add a request to a macro
- [**7**星][2y] [Java] [yehgdotnet/burp-extention-bing-translator](https://github.com/yehgdotnet/burp-extention-bing-translator) Burp Plugin - Bing Translator
- [**6**星][3m] [Java] [aress31/copy-as-powershell-requests](https://github.com/aress31/copy-as-powershell-requests) Copy as PowerShell request(s) plugin for Burp Suite (approved by PortSwigger for inclusion in their official BApp Store).
- [**6**星][1m] [Java] [aress31/googleauthenticator](https://github.com/aress31/googleauthenticator) Burp Suite plugin that dynamically generates Google 2FA codes for use in session handling rules (approved by PortSwigger for inclusion in their official BApp Store).
- [**6**星][3m] [Java] [lorenzog/burpaddcustomheader](https://github.com/lorenzog/burpaddcustomheader) A Burp Suite extension to add a custom header (e.g. JWT)
- [**6**星][2y] [Py] [maxence-schmitt/officeopenxmleditor](https://github.com/maxence-schmitt/officeopenxmleditor) Burp extension that add a tab to edit Office Open XML document (xlsx,docx,pptx)
- [**6**星][2y] [Java] [silentsignal/burp-uniqueness](https://github.com/silentsignal/burp-uniqueness) Uniqueness plugin for Burp Suite
- [**6**星][2y] [Java] [stackcrash/burpheaders](https://github.com/stackcrash/burpheaders) Burp extension for checking optional headers
- [**6**星][5m] [Java] [augustd/burp-suite-jsonpath](https://github.com/augustd/burp-suite-jsonpath) JSONPath extension for BurpSuite
- [**6**星][7m] [Java] [denniskniep/gqlraider](https://github.com/denniskniep/gqlraider) GQL Burp Extension
- [**6**星][2m] [Java] [neal1991/r-forwarder-burp](https://github.com/neal1991/r-forwarder-burp) The burp extension to forward the request
- [**5**星][6y] [Java] [eganist/burp-issue-poster](https://github.com/eganist/burp-issue-poster) This Burp Extension is intended to post to a service the details of an issue found either by active or passive scanning
- [**5**星][3y] [Py] [floyd-fuh/burp-collect500](https://github.com/floyd-fuh/burp-collect500) Burp plugin that collects all HTTP 500 messages
- [**5**星][7y] [Py] [mwielgoszewski/jython-burp-extensions](https://github.com/mwielgoszewski/jython-burp-extensions) Jython burp extensioins
- [**5**星][2m] [Java] [iamaldi/rapid](https://github.com/iamaldi/rapid) Rapid is a Burp extension that enables you to save HTTP Request / Response to file in a user friendly text format a lot faster.
- [**5**星][22d] [Ruby] [dradis/dradis-burp](https://github.com/dradis/dradis-burp) Burp Suite plugin for the Dradis Framework
- [**5**星][27d] [Java] [parsiya/bug-diaries](https://github.com/parsiya/bug-diaries) A extension for Burp's free edition that mimics the pro edition's custom scan issues.
- [**4**星][6y] [Perl] [allfro/browserrepeater](https://github.com/allfro/browserrepeater) BurpSuite extension for Repeater tool that renders responses in a real browser.
- [**4**星][2y] [Java] [dannegrea/tokenjar](https://github.com/dannegrea/tokenjar) Burp Suite extension. Useful for managing tokens like anti-CSRF, CSurf, Session values. Can be used to set params that require random numbers or params that are computed based on application response.
- [**4**星][2y] [Java] [pentestpartners/fista](https://github.com/pentestpartners/fista) A Burp Extender plugin allowing decoding of fastinfoset encoded communications.
- [**4**星][3y] [Java] [jksecurity/burp_savetofile](https://github.com/jksecurity/burp_savetofile) BurpSuite plugin to save just the body of a request or response to a file
- [**3**星][2y] [Py] [externalist/aes-encrypt-decrypt-burp-extender-plugin-example](https://github.com/externalist/aes-encrypt-decrypt-burp-extender-plugin-example) A POC burp extender plugin to seamlessly decrypt/encrypt encrypted HTTP network traffic.
- [**3**星][9m] [Java] [raise-isayan/bigipdiscover](https://github.com/raise-isayan/bigipdiscover) It becomes the extension of Burp suite. The cookie set by the BipIP server may include a private IP, which is an extension to detect that IP
- [**3**星][2y] [Py] [snoopysecurity/noopener-burp-extension](https://github.com/snoopysecurity/noopener-burp-extension) Find Target="_blank" values within web pages that are set without 'noopener' and 'noreferrer' attributes
- [**3**星][3y] [Py] [vergl4s/signatures](https://github.com/vergl4s/signatures) Length extension attacks in Burp Suite
- [**3**星][3y] [Java] [cnotin/burp-scan-manual-insertion-point](https://github.com/cnotin/burp-scan-manual-insertion-point) Burp Suite Pro extension
- [**3**星][3m] [Java] [wrvenkat/burp-multistep-csrf-poc](https://github.com/wrvenkat/burp-multistep-csrf-poc) Burp extension to generate multi-step CSRF POC.
- [**3**星][3m] [Java] [augustd/burp-suite-swaggy](https://github.com/augustd/burp-suite-swaggy) Burp Suite extension for parsing Swagger web service definition files
- [**3**星][7m] [Py] [solomonsklash/cookie-decrypter](https://github.com/solomonsklash/cookie-decrypter) A Burp Suite Professional extension for decrypting/decoding various types of cookies.
- [**2**星][2y] [Java] [alexlauerman/incrementmeplease](https://github.com/alexlauerman/incrementmeplease) Burp extension to increment a parameter in each active scan request
- [**2**星][4y] [Py] [d453d2/burp-jython-console](https://github.com/d453d2/burp-jython-console) Burp Suite extension to enable a Jython console - origin (
- [**2**星][1y] [Java] [matanatr96/decoderproburpsuite](https://github.com/matanatr96/decoderproburpsuite) Burp Suite Plugin to decode and clean up garbage response text
- [**2**星][3y] [Java] [silentsignal/burp-json-array](https://github.com/silentsignal/burp-json-array) JSON Array issues plugin for Burp Suite
- [**2**星][2y] [stayliv3/burpsuite-magic](https://github.com/stayliv3/burpsuite-magic) 收集burpsuite插件，并对每个插件编写使用说明手册。
- [**2**星][2y] [Ruby] [thec00n/uploader](https://github.com/thec00n/uploader) Burp extension to test for directory traversal attacks in insecure file uploads
- [**2**星][8y] [Java] [thecao365/burp-suite-beautifier-extension](https://github.com/thecao365/burp-suite-beautifier-extension) burp-suite-beautifier-extension
- [**2**星][28d] [Java] [parsiya/burp-sample-extension-java](https://github.com/parsiya/burp-sample-extension-java) Sample Burp Extension in Java
- [**1**星][7m] [Java] [bort-millipede/burp-batch-report-generator](https://github.com/bort-millipede/burp-batch-report-generator) Small Burp Suite Extension to generate multiple scan reports by host with just a few clicks. Works with Burp Suite Professional only.
- [**1**星][28d] [Java] [infobyte/faraday_burp](https://github.com/infobyte/faraday_burp) Faraday Burp Extension
- [**1**星][9m] [Java] [jonluca/burp-copy-as-node](https://github.com/jonluca/burp-copy-as-node) Burp extension to copy a request as a node.js requests function
- [**1**星][2y] [Java] [moradotai/cms-scan](https://github.com/moradotai/cms-scan) An active scan extension for Burp that provides supplemental coverage when testing popular content management systems.
- [**1**星][3y] [Java] [tagomaru/burp-extension-sync-parameter](https://github.com/tagomaru/burp-extension-sync-parameter)  an extension to Burp Suite that provides a sync function for CSRF token parameter.
- [**1**星][3m] [Py] [bomsi/blockerlite](https://github.com/bomsi/blockerlite) Simple Burp extension to drop blacklisted hosts
- [**1**星][4y] [Py] [hvqzao/burp-csrf-handling](https://github.com/hvqzao/burp-csrf-handling) CSRF tokens handling Burp extension
- [**1**星][1m] [Java] [sunny0day/burp-auto-drop](https://github.com/sunny0day/burp-auto-drop) Burp extension to automatically drop requests that match a certain regex.
- [**0**星][3y] [Java] [chris-atredis/burpchat](https://github.com/chris-atredis/burpchat) burpChat is a BurpSuite plugin that enables collaborative BurpSuite usage using XMPP/Jabber.
- [**0**星][2y] [Java] [insighti/burpamx](https://github.com/insighti/burpamx) AMX Authorization Burp Suite Extension
- [**0**星][9m] [Java] [xorrbit/burp-nessusloader](https://github.com/xorrbit/burp-nessusloader) Burp Suite extension to import detected web servers from a Nessus scan xml file (.nessus)


***


## <a id="90339d9a130e105e1617bff2c2ca9721"></a>漏洞&&扫描


- [**663**星][10m] [Java] [vulnerscom/burp-vulners-scanner](https://github.com/vulnerscom/burp-vulners-scanner) Burp扫描插件，基于vulners.com搜索API
- [**510**星][2m] [Java] [wagiro/burpbounty](https://github.com/wagiro/burpbounty) is a extension of Burp Suite that allows you, in a quick and simple way, to improve the active and passive scanner by means of personalized rules through a very intuitive graphical interface.
- [**395**星][2y] [Java] [federicodotta/java-deserialization-scanner](https://github.com/federicodotta/java-deserialization-scanner) All-in-one plugin for Burp Suite for the detection and the exploitation of Java deserialization vulnerabilities
- [**225**星][6m] [Perl] [modzero/mod0burpuploadscanner](https://github.com/modzero/mod0burpuploadscanner) HTTP file upload scanner for Burp Proxy
- [**186**星][1y] [Perl] [portswigger/upload-scanner](https://github.com/portswigger/upload-scanner) HTTP file upload scanner for Burp Proxy
- [**136**星][22d] [JS] [h3xstream/burp-retire-js](https://github.com/h3xstream/burp-retire-js) Burp/ZAP/Maven extension that integrate Retire.js repository to find vulnerable Javascript libraries.
- [**128**星][2y] [Java] [yandex/burp-molly-scanner](https://github.com/yandex/burp-molly-scanner) Turn your Burp suite into headless active web application vulnerability scanner
- [**101**星][2y] [Java] [spiderlabs/airachnid-burp-extension](https://github.com/spiderlabs/airachnid-burp-extension) A Burp Extension to test applications for vulnerability to the Web Cache Deception attack
- [**85**星][4m] [Py] [kapytein/jsonp](https://github.com/kapytein/jsonp) a Burp Extension which attempts to reveal JSONP functionality behind JSON endpoints. This could help reveal cross-site script inclusion vulnerabilities or aid in bypassing content security policies.
- [**81**星][9m] [Py] [nccgroup/argumentinjectionhammer](https://github.com/nccgroup/argumentinjectionhammer) A Burp Extension designed to identify argument injection vulnerabilities.
- [**75**星][4y] [Java] [directdefense/superserial](https://github.com/directdefense/superserial) SuperSerial - Burp Java Deserialization Vulnerability Identification
- [**74**星][4y] [Py] [integrissecurity/carbonator](https://github.com/integrissecurity/carbonator) The Burp Suite Pro extension that automates scope, spider & scan from the command line. 
- [**59**星][1y] [Py] [capt-meelo/telewreck](https://github.com/capt-meelo/telewreck) A Burp extension to detect and exploit versions of Telerik Web UI vulnerable to CVE-2017-9248.
- [**58**星][3y] [Java] [vulnerscom/burp-dirbuster](https://github.com/vulnerscom/burp-dirbuster) Dirbuster plugin for Burp Suite
- [**57**星][3y] [Java] [linkedin/sometime](https://github.com/linkedin/sometime) A BurpSuite plugin to detect Same Origin Method Execution vulnerabilities
- [**56**星][2y] [Java] [bigsizeme/burplugin-java-rce](https://github.com/bigsizeme/burplugin-java-rce) Burp plugin, Java RCE
- [**46**星][2y] [Java] [portswigger/httpoxy-scanner](https://github.com/portswigger/httpoxy-scanner) A Burp Suite extension that checks for the HTTPoxy vulnerability.
- [**42**星][2y] [Py] [modzero/interestingfilescanner](https://github.com/modzero/interestingfilescanner) Burp extension
- [**39**星][3y] [Java] [directdefense/superserial-active](https://github.com/directdefense/superserial-active) SuperSerial-Active - Java Deserialization Vulnerability Active Identification Burp Extender
- [**38**星][1y] [Py] [luh2/detectdynamicjs](https://github.com/luh2/detectdynamicjs) The DetectDynamicJS Burp Extension provides an additional passive scanner that tries to find differing content in JavaScript files and aid in finding user/session data.
- [**35**星][4m] [Py] [arbazkiraak/burpblh](https://github.com/arbazkiraak/burpblh) 使用IScannerCheck发现被劫持的损坏链接. Burp插件
- [**34**星][4y] [Py] [politoinc/yara-scanner](https://github.com/politoinc/yara-scanner) Yara intergrated into BurpSuite
- [**34**星][3y] [Py] [thomaspatzke/burp-sessionauthtool](https://github.com/thomaspatzke/burp-sessionauthtool) Burp plugin which supports in finding privilege escalation vulnerabilities
- [**29**星][2y] [Py] [portswigger/wordpress-scanner](https://github.com/portswigger/wordpress-scanner) Find known vulnerabilities in WordPress plugins and themes using Burp Suite proxy. WPScan like plugin for Burp.
- [**29**星][7m] [Java] [portswigger/scan-check-builder](https://github.com/portswigger/scan-check-builder) Burp Bounty is a extension of Burp Suite that improve an active and passive scanner by yourself. This extension requires Burp Suite Pro.
- [**25**星][2y] [Java] [vankyver/burp-vulners-scanner](https://github.com/vankyver/burp-vulners-scanner) Burp scanner plugin based on Vulners.com vulnerability database
- [**25**星][6y] [Py] [opensecurityresearch/custompassivescanner](https://github.com/opensecurityresearch/custompassivescanner) A Custom Scanner for Burp
- [**23**星][3y] [Java] [vah13/burpcrlfplugin](https://github.com/vah13/burpcrlfplugin) Another plugin for CRLF vulnerability detection
- [**22**星][9m] [BitBake] [ghsec/bbprofiles](https://github.com/ghsec/bbprofiles) Burp Bounty (Scan Check Builder in BApp Store) is a extension of Burp Suite that improve an active and passive scanner by yourself. This extension requires Burp Suite Pro.
- [**21**星][3y] [Py] [f-secure/headless-scanner-driver](https://github.com/f-secure/headless-scanner-driver) A Burp Suite extension that starts scanning on requests it sees, and dumps results on standard output
- [**20**星][3m] [Java] [aress31/flarequench](https://github.com/aress31/flarequench) Burp Suite plugin that adds additional checks to the passive scanner to reveal the origin IP(s) of Cloudflare-protected web applications.
- [**19**星][2m] [Java] [mirfansulaiman/customheader](https://github.com/mirfansulaiman/customheader) This Burp Suite extension allows you to customize header with put a new header into HTTP REQUEST BurpSuite (Scanner, Intruder, Repeater, Proxy History)
- [**18**星][4y] [codewatchorg/burp-yara-rules](https://github.com/codewatchorg/burp-yara-rules) Yara rules to be used with the Burp Yara-Scanner extension
- [**18**星][6m] [Java] [thomashartm/burp-aem-scanner](https://github.com/thomashartm/burp-aem-scanner) Burp Scanner extension to fingerprint and actively scan instances of the Adobe Experience Manager CMS. It checks the website for common misconfigurations and security holes.
- [**16**星][1y] [Py] [portswigger/additional-scanner-checks](https://github.com/portswigger/additional-scanner-checks) Collection of scanner checks missing in Burp
- [**14**星][3y] [Java] [portswigger/same-origin-method-execution](https://github.com/portswigger/same-origin-method-execution) A BurpSuite plugin to detect Same Origin Method Execution vulnerabilities
- [**13**星][1y] [Py] [thomaspatzke/burp-missingscannerchecks](https://github.com/thomaspatzke/burp-missingscannerchecks) Collection of scanner checks missing in Burp
- [**12**星][2y] [Java] [ah8r/csrf](https://github.com/ah8r/csrf) CSRF Scanner Extension for Burp Suite Pro
- [**10**星][4y] [Java] [augustd/burp-suite-token-fetcher](https://github.com/augustd/burp-suite-token-fetcher) Burp Extender to add unique form tokens to scanner requests.
- [**10**星][1y] [Py] [portswigger/detect-dynamic-js](https://github.com/portswigger/detect-dynamic-js) The DetectDynamicJS Burp Extension provides an additional passive scanner that tries to find differing content in JavaScript files and aid in finding user/session data.
- [**10**星][3y] [Java] [ring04h/java-deserialization-scanner](https://github.com/ring04h/java-deserialization-scanner) All-in-one plugin for Burp Suite for the detection and the exploitation of Java deserialization vulnerabilities
- [**10**星][2y] [Java] [securifybv/phpunserializecheck](https://github.com/securifybv/phpunserializecheck) PHP Unserialize Check - Burp Scanner Extension
- [**10**星][23d] [Java] [veggiespam/imagelocationscanner](https://github.com/veggiespam/imagelocationscanner) Scan for GPS location exposure in images with this Burp & ZAP plugin.
- [**7**星][3y] [Py] [luh2/pdfmetadata](https://github.com/luh2/pdfmetadata) The PDF Metadata Burp Extension provides an additional passive Scanner check for metadata in PDF files.
- [**4**星][4y] [Ruby] [blazeinfosec/activeevent](https://github.com/blazeinfosec/activeevent) ActiveEvent is a Burp plugin that integrates Burp Scanner and Splunk events
- [**4**星][2y] [Java] [codedx/burp-extension](https://github.com/codedx/burp-extension) Burp Suite plugin to send data to Code Dx software vulnerability management system
- [**2**星][3y] [Java] [moeinfatehi/cvss_calculator](https://github.com/moeinfatehi/cvss_calculator) CVSS Calculator - a burp suite extension for calculating CVSS v2 and v3 scores of vulnerabilities.
- [**2**星][6y] [Java] [thec00n/dradis-vuln-table](https://github.com/thec00n/dradis-vuln-table) Dradis Vuln Table extension for Burp suite
- [**1**星][1y] [Java] [logicaltrust/burpexiftoolscanner](https://github.com/logicaltrust/burpexiftoolscanner) Burp extension, reads metadata using ExifTool
- [**1**星][2y] [Java] [rammarj/burp-header-injector](https://github.com/rammarj/burp-header-injector) Burp Free plugin to test for host header injection vulnerabilities. (Development)
- [**1**星][9m] [Py] [jamesm0rr1s/burpsuite-add-and-track-custom-issues](https://github.com/jamesm0rr1s/BurpSuite-Add-and-Track-Custom-Issues) Add & Track Custom Issues is a Burp Suite extension that allows users to add and track manual findings that the automated scanner was unable to identify.


***


## <a id="280b7fad90dd1238909425140c788365"></a>代理


- [**912**星][3y] [Java] [summitt/burp-non-http-extension](https://github.com/summitt/burp-non-http-extension) Non-HTTP Protocol Extension (NoPE) Proxy and DNS for Burp Suite.
- [**303**星][15d] [Java] [ilmila/j2eescan](https://github.com/ilmila/j2eescan) a plugin for Burp Suite Proxy. The goal of this plugin is to improve the test coverage during web application penetration tests on J2EE applications.
- [**250**星][2y] [Java] [portswigger/collaborator-everywhere](https://github.com/portswigger/collaborator-everywhere) Burp Suite 扩展，通过注入非侵入性 headers 来增强代理流量，通过引起 Pingback 到 Burp Collaborator 来揭露后端系统
- [**150**星][5m] [Py] [kacperszurek/burp_wp](https://github.com/kacperszurek/burp_wp) Find known vulnerabilities in WordPress plugins and themes using Burp Suite proxy. WPScan like plugin for Burp.
- [**88**星][6m] [Java] [rub-nds/burpssoextension](https://github.com/rub-nds/burpssoextension) An extension for BurpSuite that highlights SSO messages in Burp's proxy window..
- [**73**星][8m] [Py] [jiangsir404/pbscan](https://github.com/jiangsir404/pbscan) 基于burpsuite headless 的代理式被动扫描系统
- [**66**星][2m] [Java] [static-flow/burpsuite-team-extension](https://github.com/static-flow/burpsuite-team-extension) This Burpsuite plugin allows for multiple web app testers to share their proxy history with each other in real time. Requests that comes through your Burpsuite instance will be replicated in the history of the other testers and vice-versa!
- [**49**星][2y] [Py] [mrschyte/socksmon](https://github.com/mrschyte/socksmon) 使用 BURP 或 ZAP 的 TCP 拦截代理
- [**33**星][4y] [Py] [peacand/burp-pytemplate](https://github.com/peacand/burp-pytemplate) Burp extension to quickly and easily develop Python complex exploits based on Burp proxy requests.
- [**30**星][2y] [Py] [aurainfosec/burp-multi-browser-highlighting](https://github.com/aurainfosec/burp-multi-browser-highlighting) Highlight Burp proxy requests made by different browsers
- [**29**星][2y] [Java] [ibey0nd/nstproxy](https://github.com/ibey0nd/nstproxy) 一款存储HTTP请求入库的burpsuite插件
- [**27**星][2y] [Py] [mrts/burp-suite-http-proxy-history-converter](https://github.com/mrts/burp-suite-http-proxy-history-converter) Python script that converts Burp Suite HTTP proxy history files to CSV or HTML
- [**26**星][7m] [Java] [static-flow/directoryimporter](https://github.com/static-flow/directoryimporter) a Burpsuite plugin built to enable you to import your directory bruteforcing results into burp for easy viewing later. This is an alternative to proxying bruteforcing tools through burp to catch the results.
- [**22**星][3y] [Swift] [melvinsh/burptoggle](https://github.com/melvinsh/burptoggle) Status bar application for OS X to toggle the state of the system HTTP/HTTPS proxy.
- [**17**星][2y] [Java] [portswigger/j2ee-scan](https://github.com/portswigger/j2ee-scan) J2EEScan is a plugin for Burp Suite Proxy. The goal of this plugin is to improve the test coverage during web application penetration tests on J2EE applications.
- [**13**星][4y] [Java] [retanoj/burpmultiproxy](https://github.com/retanoj/burpmultiproxy) Burpsuite 切换代理插件
- [**11**星][8y] [Java] [gdssecurity/deflate-burp-plugin](https://github.com/gdssecurity/deflate-burp-plugin) The Deflate Burp Plugin is a plug-in for Burp Proxy (it implements the IBurpExtender interface) that decompresses HTTP response content in the ZLIB (RFC1950) and DEFLATE (RFC1951) compression formats.
- [**11**星][4y] [Py] [vincd/burpproxypacextension](https://github.com/vincd/burpproxypacextension) Exemple d'extension Burp permettant d'utiliser les fichiers de configuration de proxy PAC
- [**8**星][2y] [Py] [andresriancho/burp-proxy-search](https://github.com/andresriancho/burp-proxy-search) Burp suite HTTP history advanced search
- [**6**星][2y] [Java] [secureskytechnology/burpextender-proxyhistory-webui](https://github.com/secureskytechnology/burpextender-proxyhistory-webui) Burp Extender . Proxy History viewer in Web UI
- [**5**星][3y] [Java] [mrts/burp-suite-http-proxy-history-viewer](https://github.com/mrts/burp-suite-http-proxy-history-viewer) Burp Suite HTTP proxy history viewer
- [**5**星][3y] [Java] [netspi/jsws](https://github.com/netspi/jsws) JavaScript Web Service Proxy Burp Plugin
- [**3**星][2y] [Kotlin] [pajswigger/filter-options](https://github.com/pajswigger/filter-options) Burp extension to filter OPTIONS requests from proxy history
- [**2**星][1y] [Java] [coastalhacking/burp-pac](https://github.com/coastalhacking/burp-pac) Burp Proxy Auto-config Extension


***


## <a id="19f0f074fc013e6060e96568076b7c9a"></a>日志


- [**496**星][2m] [Py] [romanzaikin/burpextension-whatsapp-decryption-checkpoint](https://github.com/romanzaikin/burpextension-whatsapp-decryption-checkpoint) Burp extension to decrypt WhatsApp Protocol
- [**239**星][1y] [Java] [nccgroup/burpsuiteloggerplusplus](https://github.com/nccgroup/burpsuiteloggerplusplus) Burp Suite Logger++: Log activities of all the tools in Burp Suite
- [**93**星][2y] [Py] [debasishm89/burpy](https://github.com/debasishm89/burpy)  parses Burp Suite log and performs various tests depending on the module provided and finally generate a HTML report.
- [**63**星][4y] [Py] [tony1016/burplogfilter](https://github.com/tony1016/burplogfilter) A python3 program to filter Burp Suite log file.
- [**43**星][1y] [Py] [bayotop/sink-logger](https://github.com/bayotop/sink-logger) Burp扩展,无缝记录所有传递到已知JavaScript sinks的数据
- [**32**星][3m] [Java] [righettod/log-requests-to-sqlite](https://github.com/righettod/log-requests-to-sqlite) BURP extension to record every HTTP request send via BURP and create an audit trail log of an assessment.
- [**5**星][8m] [Java] [logicaltrust/burphttpmock](https://github.com/logicaltrust/burphttpmock) This Burp extension provides mock responses based on the real ones.
- [**3**星][1y] [Java] [ax/burp-logs](https://github.com/ax/burp-logs) Logs is a Burp Suite extension to work with log files.
- [**0**星][3y] [Java] [silentsignal/burp-sqlite-logger](https://github.com/silentsignal/burp-sqlite-logger) SQLite logger for Burp Suite
    - 重复区段: [工具->SQL](#0481f52a7f7ee969fa5834227e49412e) |


***


## <a id="7a78bdcffe72cd39b193d93aaec80289"></a>XSS


- [**301**星][1y] [Java] [elkokc/reflector](https://github.com/elkokc/reflector) Burp 插件，浏览网页时实时查找反射 XSS
- [**301**星][3y] [Java] [nvisium/xssvalidator](https://github.com/nvisium/xssvalidator) This is a burp intruder extender that is designed for automation and validation of XSS vulnerabilities.
- [**163**星][3m] [Py] [wish-i-was/femida](https://github.com/wish-i-was/femida) Automated blind-xss search for Burp Suite
- [**101**星][1y] [Java] [mystech7/burp-hunter](https://github.com/mystech7/burp-hunter) XSS Hunter Burp Plugin
- [**44**星][7m] [Py] [bitthebyte/bitblinder](https://github.com/bitthebyte/bitblinder) Burp extension helps in finding blind xss vulnerabilities
- [**34**星][3y] [Py] [attackercan/burp-xss-sql-plugin](https://github.com/attackercan/burp-xss-sql-plugin) Burp plugin which I used for years which helped me to find several bugbounty-worthy XSSes, OpenRedirects and SQLi.
- [**30**星][14d] [JS] [psych0tr1a/elscripto](https://github.com/psych0tr1a/elscripto) XSS explot kit/Blind XSS framework/BurpSuite extension
- [**27**星][3y] [Java] [portswigger/xss-validator](https://github.com/portswigger/xss-validator) This is a burp intruder extender that is designed for automation and validation of XSS vulnerabilities.
- [**23**星][9m] [Py] [hpd0ger/supertags](https://github.com/hpd0ger/supertags) 一个Burpsuite插件，用于检测隐藏的XSS
- [**22**星][1y] [Py] [jiangsir404/xss-sql-fuzz](https://github.com/jiangsir404/xss-sql-fuzz) burpsuite 插件对GP所有参数(过滤特殊参数)一键自动添加xss sql payload 进行fuzz
    - 重复区段: [工具->Fuzz](#e9a969fc073afb5add0b75607e43def0) |[工具->SQL](#0481f52a7f7ee969fa5834227e49412e) |
- [**2**星][1y] [Java] [conanjun/xssblindinjector](https://github.com/conanjun/xssblindinjector) burp插件，实现自动化xss盲打以及xss log


***


## <a id="e0b6358d9096e96238b76258482a1c2f"></a>Collaborator


- [**88**星][2y] [Java] [federicodotta/handycollaborator](https://github.com/federicodotta/handycollaborator) Burp Suite plugin created for using Collaborator tool during manual testing in a comfortable way!
- [**68**星][3m] [Java] [netspi/burpcollaboratordnstunnel](https://github.com/netspi/burpcollaboratordnstunnel) A DNS tunnel utilizing the Burp Collaborator
- [**39**星][2y] [Java] [bit4woo/burp_collaborator_http_api](https://github.com/bit4woo/burp_collaborator_http_api) 基于Burp Collaborator的HTTP API
- [**31**星][3y] [Java] [silentsignal/burp-collab-gw](https://github.com/silentsignal/burp-collab-gw) Simple socket-based gateway to the Burp Collaborator
- [**30**星][2m] [Shell] [putsi/privatecollaborator](https://github.com/putsi/privatecollaborator) A script for installing private Burp Collaborator with free Let's Encrypt SSL-certificate
- [**25**星][27d] [Java] [portswigger/taborator](https://github.com/portswigger/taborator) A Burp extension to show the Collaborator client in a tab
- [**17**星][2y] [HCL] [4armed/terraform-burp-collaborator](https://github.com/4armed/terraform-burp-collaborator) Terraform configuration to build a Burp Private Collaborator Server
- [**8**星][27d] [Java] [hackvertor/taborator](https://github.com/hackvertor/taborator) A Burp extension to show the Collaborator client in a tab


***


## <a id="e9a969fc073afb5add0b75607e43def0"></a>Fuzz


- [**209**星][3m] [Java] [h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator) ZAP/Burp plugin that generate script to reproduce a specific HTTP request (Intended for fuzzing or scripted attacks)
- [**62**星][5m] [Py] [pinnace/burp-jwt-fuzzhelper-extension](https://github.com/pinnace/burp-jwt-fuzzhelper-extension) Burp扩展, 用于Fuzzing JWT
- [**54**星][3y] [Py] [mseclab/burp-pyjfuzz](https://github.com/mseclab/burp-pyjfuzz) Burp Suite plugin which implement PyJFuzz for fuzzing web application.
- [**38**星][3y] [team-firebugs/burp-lfi-tests](https://github.com/team-firebugs/burp-lfi-tests) Fuzzing for LFI using Burpsuite
- [**28**星][3y] [Py] [floyd-fuh/burp-httpfuzzer](https://github.com/floyd-fuh/burp-httpfuzzer) Burp plugin to do random fuzzing of HTTP requests
- [**22**星][1y] [Py] [jiangsir404/xss-sql-fuzz](https://github.com/jiangsir404/xss-sql-fuzz) burpsuite 插件对GP所有参数(过滤特殊参数)一键自动添加xss sql payload 进行fuzz
    - 重复区段: [工具->XSS](#7a78bdcffe72cd39b193d93aaec80289) |[工具->SQL](#0481f52a7f7ee969fa5834227e49412e) |
- [**18**星][1y] [Py] [mgeeky/burpcontextawarefuzzer](https://github.com/mgeeky/burpcontextawarefuzzer) BurpSuite's payload-generation extension aiming at applying fuzzed test-cases depending on the type of payload (integer, string, path; JSON; XML; GWT; binary) and following encoding-scheme applied originally.
- [**18**星][7y] [raz0r/burp-radamsa](https://github.com/raz0r/burp-radamsa) Radamsa fuzzer extension for Burp Suite
- [**11**星][3y] [Java] [portswigger/reissue-request-scripter](https://github.com/portswigger/reissue-request-scripter) ZAP/Burp plugin that generate script to reproduce a specific HTTP request (Intended for fuzzing or scripted attacks)
- [**4**星][2y] [Java] [huvuqu/fuzz18plus](https://github.com/huvuqu/fuzz18plus) Advance of fuzzing for Web pentest. Based on Burp extension, send HTTP request template out to Python fuzzer.
- [**1**星][5m] [Kotlin] [gosecure/burp-fuzzy-encoding-generator](https://github.com/gosecure/burp-fuzzy-encoding-generator) Quickly test various encoding for a given value in Burp Intruder


***


## <a id="fc5f535e219ba9694bb72df4c11b32bd"></a>Payload


- [**423**星][6m] [Java] [bit4woo/recaptcha](https://github.com/bit4woo/recaptcha) 自动识别图形验证码并用于burp intruder爆破模块的插件
- [**152**星][4y] [trietptm/sql-injection-payloads](https://github.com/trietptm/sql-injection-payloads) SQL Injection Payloads for Burp Suite, OWASP Zed Attack Proxy,...
    - 重复区段: [工具->SQL](#0481f52a7f7ee969fa5834227e49412e) |
- [**70**星][2y] [Java] [ikkisoft/bradamsa](https://github.com/ikkisoft/bradamsa) Burp Suite extension to generate Intruder payloads using Radamsa
- [**56**星][1y] [Py] [destine21/zipfileraider](https://github.com/destine21/zipfileraider) ZIP File Raider - Burp Extension for ZIP File Payload Testing
- [**55**星][2y] [Java] [righettod/virtualhost-payload-generator](https://github.com/righettod/virtualhost-payload-generator) BURP extension providing a set of values for the HTTP request "Host" header for the "BURP Intruder" in order to abuse virtual host resolution.
- [**32**星][3y] [tdifg/payloads](https://github.com/tdifg/payloads) for burp
- [**19**星][4y] [Java] [lgrangeia/aesburp](https://github.com/lgrangeia/aesburp) Burp Extension to manipulate AES encrypted payloads
- [**17**星][3m] [thehackingsage/burpsuite](https://github.com/thehackingsage/burpsuite) BurpSuite Pro, Plugins and Payloads
- [**16**星][3y] [Java] [portswigger/java-serialized-payloads](https://github.com/portswigger/java-serialized-payloads) YSOSERIAL Integration with burp suite
- [**12**星][2m] [Java] [tmendo/burpintruderfilepayloadgenerator](https://github.com/tmendo/burpintruderfilepayloadgenerator) Burp Intruder File Payload Generator
- [**10**星][2y] [antichown/burp-payloads](https://github.com/antichown/burp-payloads) Burp Payloads
- [**5**星][4y] [Java] [antoinet/burp-decompressor](https://github.com/antoinet/burp-decompressor) An extension for BurpSuite used to access and modify compressed HTTP payloads without changing the content-encoding.
- [**5**星][5y] [Py] [enablesecurity/burp-luhn-payload-processor](https://github.com/enablesecurity/burp-luhn-payload-processor) A plugin for Burp Suite Pro to work with attacker payloads and automatically generate check digits for credit card numbers and similar numbers that end with a check digit generated using the Luhn algorithm or formula (also known as the "modulus 10" or "mod 10" algorithm).
- [**3**星][7y] [Py] [infodel/burp.extension-payloadparser](https://github.com/infodel/burp.extension-payloadparser) Burp Extension for parsing payloads containing/excluding characters you provide.
- [**3**星][2y] [Java] [pan-lu/recaptcha](https://github.com/pan-lu/recaptcha) A Burp Extender that auto recognize CAPTCHA and use for Intruder payload


***


## <a id="0481f52a7f7ee969fa5834227e49412e"></a>SQL


- [**381**星][1y] [Py] [rhinosecuritylabs/sleuthql](https://github.com/rhinosecuritylabs/sleuthql) Python3 Burp History parsing tool to discover potential SQL injection points. To be used in tandem with SQLmap.
- [**235**星][1y] [Java] [difcareer/sqlmap4burp](https://github.com/difcareer/sqlmap4burp) sqlmap embed in burpsuite
- [**174**星][2m] [Py] [codewatchorg/sqlipy](https://github.com/codewatchorg/sqlipy) Burp Suite 插件, 使用 SQLMap API 集成SQLMap
- [**152**星][4y] [trietptm/sql-injection-payloads](https://github.com/trietptm/sql-injection-payloads) SQL Injection Payloads for Burp Suite, OWASP Zed Attack Proxy,...
    - 重复区段: [工具->Payload](#fc5f535e219ba9694bb72df4c11b32bd) |
- [**109**星][2m] [Java] [c0ny1/sqlmap4burp-plus-plus](https://github.com/c0ny1/sqlmap4burp-plus-plus) 一款兼容Windows，mac，linux多个系统平台的Burp与sqlmap联动插件
- [**24**星][2m] [Py] [portswigger/sqli-py](https://github.com/portswigger/sqli-py) a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
- [**22**星][1y] [Py] [jiangsir404/xss-sql-fuzz](https://github.com/jiangsir404/xss-sql-fuzz) burpsuite 插件对GP所有参数(过滤特殊参数)一键自动添加xss sql payload 进行fuzz
    - 重复区段: [工具->XSS](#7a78bdcffe72cd39b193d93aaec80289) |[工具->Fuzz](#e9a969fc073afb5add0b75607e43def0) |
- [**22**星][7y] [Py] [milo2012/burpsql](https://github.com/milo2012/burpsql) Automating SQL injection using Burp Proxy Logs and SQLMap
- [**8**星][8m] [Py] [orleven/burpcollect](https://github.com/orleven/burpcollect) 基于BurpCollector的二次开发， 记录Burpsuite Site Map记录的里的数据包中的目录路径参数名信息，并存入Sqlite，并可导出txt文件。
- [**0**星][3y] [Java] [silentsignal/burp-sqlite-logger](https://github.com/silentsignal/burp-sqlite-logger) SQLite logger for Burp Suite
    - 重复区段: [工具->日志](#19f0f074fc013e6060e96568076b7c9a) |


***


## <a id="33431f1a7baa0f6193334ef4d74ff82c"></a>Android


- [**274**星][2y] [Java] [mateuszk87/badintent](https://github.com/mateuszk87/badintent) Intercept, modify, repeat and attack Android's Binder transactions using Burp Suite
- [**9**星][4m] [JS] [shahidcodes/android-nougat-ssl-intercept](https://github.com/shahidcodes/android-nougat-ssl-intercept) It decompiles target apk and adds security exception to accept all certificates thus making able to work with Burp/Charles and Other Tools


***


## <a id="01a878dcb14c47e0a1d05dc36ab95bfc"></a>其他


- [**584**星][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) The new bridge between Burp Suite and Frida!
- [**354**星][2y] [Shell] [koenbuyens/kalirouter](https://github.com/koenbuyens/kalirouter) 将 KaliLinux 主机转变为路由器，使用 Wireshark 记录所有的网络流量，同时将 HTTP/HTTPS 流量发送到其他主机的拦截代理（例如 BurpSuite）
- [**298**星][1y] [Shell] [yw9381/burp_suite_doc_zh_cn](https://github.com/yw9381/burp_suite_doc_zh_cn) 这是基于Burp Suite官方文档翻译而来的中文版文档
- [**230**星][1y] [Py] [audibleblink/doxycannon](https://github.com/audibleblink/doxycannon) 为一堆OpenVPN文件分别创建Docker容器, 每个容器开启SOCKS5代理服务器并绑定至Docker主机端口, 再结合使用Burp或ProxyChains, 构建私有的Botnet
- [**219**星][10m] [Py] [teag1e/burpcollector](https://github.com/teag1e/burpcollector) 通过BurpSuite来构建自己的爆破字典，可以通过字典爆破来发现隐藏资产。
- [**141**星][6m] [Py] [integrity-sa/burpcollaborator-docker](https://github.com/integrity-sa/burpcollaborator-docker) a set of scripts to install a Burp Collaborator Server in a docker environment, using a LetsEncrypt wildcard certificate
- [**130**星][7m] [Go] [empijei/wapty](https://github.com/empijei/wapty) Go语言编写的Burp的替代品。（已不再维护）
- [**121**星][2m] [cujanovic/content-bruteforcing-wordlist](https://github.com/cujanovic/content-bruteforcing-wordlist) Wordlist for content(directory) bruteforce discovering with Burp or dirsearch
- [**77**星][1m] [Go] [root4loot/rescope](https://github.com/root4loot/rescope) defining scopes for Burp Suite and OWASP ZAP.
- [**64**星][3m] [Java] [aress31/swurg](https://github.com/aress31/swurg) Parse OpenAPI documents into Burp Suite for automating OpenAPI-based APIs security assessments
- [**12**星][30d] [boreas514/burp-suite-2.0-chinese-document](https://github.com/boreas514/burp-suite-2.0-chinese-document) 中文版burp2.0官方文档
- [**0**星][3y] [fbogner/burp.app](https://github.com/fbogner/burp.app) A small AppleScript wrapper application around Burp.jar to make it more OS X like


# <a id="dab83e734c8176aae854176552bff628"></a>文章


***


## <a id="ad95cb0314046788911641086ec4d674"></a>新添加


- 2019.12 [aliyun] [如何利用xray、burp、lsc构成自动化挖src平台](https://xz.aliyun.com/t/7007)
- 2019.12 [parsiya] [Developing and Debugging Java Burp Extensions with Visual Studio Code](https://parsiya.net/blog/2019-12-02-developing-and-debugging-java-burp-extensions-with-visual-studio-code/)
- 2019.11 [parsiya] [Swing in Python Burp Extensions - Part 3 - Tips and Tricks](https://parsiya.net/blog/2019-11-26-swing-in-python-burp-extensions-part-3-tips-and-tricks/)
- 2019.11 [parsiya] [Swing in Python Burp Extensions - Part 2 - NetBeans and TableModels](https://parsiya.net/blog/2019-11-11-swing-in-python-burp-extensions-part-2-netbeans-and-tablemodels/)
- 2019.11 [parsiya] [Swing in Python Burp Extensions - Part 1](https://parsiya.net/blog/2019-11-04-swing-in-python-burp-extensions-part-1/)
- 2019.10 [KacperSzurek] [[BURP] Intruder: Jak sprawdzić typ konta?](https://www.youtube.com/watch?v=K1_3WFA3Dmc)
- 2019.10 [KacperSzurek] [[BURP] 12 trików do Burp Repeater](https://www.youtube.com/watch?v=-M4bh94Mfyc)
- 2019.10 [parsiya] [Quality of Life Tips and Tricks - Burp Suite](https://parsiya.net/blog/2019-10-13-quality-of-life-tips-and-tricks-burp-suite/)
- 2019.10 [freebuf] [使用Burp拦截Flutter App与其后端的通信](https://www.freebuf.com/articles/terminal/213346.html)
- 2019.10 [KacperSzurek] [[BURP] Jak stworzyć makro do odświeżania sesji?](https://www.youtube.com/watch?v=d1lg2WGzvW4)
- 2019.09 [BrokenSecurity] [036 part of Ethical Hacking - Burpsuite login bruteforce](https://www.youtube.com/watch?v=b1ggBAk2yDE)
- 2019.09 [BrokenSecurity] [033 part of Ethical Hacking - Editing packets in Burpsuite](https://www.youtube.com/watch?v=o8yLE8Ls81I)
- 2019.09 [BrokenSecurity] [032 part of Ethical Hacking - Burpsuite configuration](https://www.youtube.com/watch?v=m_SLme98650)
- 2019.09 [aliyun] [BurpSuite插件 -  AutoRepeater说明](https://xz.aliyun.com/t/6244)
- 2019.09 [radekk] [Firefox and Burp Suite — the most secure configuration](https://medium.com/p/3c08e6c23194)
- 2019.08 [nviso] [Using Burp’s session Handling Rules to insert authorization cookies into Intruder, Repeater and even sqlmap](https://blog.nviso.be/2019/08/29/using-burps-session-handling-rules-to-insert-authorization-cookies-into-intruderrepeater-and-even-sqlmap/)
- 2019.08 [arbazhussain] [LinkDumper Burp Plugin](https://medium.com/p/6bde89937646)
- 2019.08 [chawdamrunal] [How i exploit out-of-band resource load (HTTP) using burp suite extension plugin (taborator)](https://medium.com/p/2c5065d6a50b)
- 2019.07 [0x00sec] [Doubt with header. Burp & Tamper](https://0x00sec.org/t/doubt-with-header-burp-tamper/15197)
- 2019.06 [appsecconsulting] [Ten Useful Burp Suite Pro Extensions for Web Application Testing](https://appsecconsulting.com/blog/ten-useful-burp-suite-pro-extensions-for-web-application-testing)
- 2019.06 [bugbountywriteup] [Deploy a private Burp Collaborator Server in Azure](https://medium.com/p/f0d932ae1d70)
- 2019.06 [infosecinstitute] [Intercepting HTTPS traffic with Burp Suite](https://resources.infosecinstitute.com/intercepting-https-traffic-with-burp-suite/)
- 2019.06 [0x00sec] [Achieving Persistent Access to Burp Collaborator Sessions](https://0x00sec.org/t/achieving-persistent-access-to-burp-collaborator-sessions/14311)
- 2019.06 [bugbountywriteup] [Digging Android Applications — Part 1 — Drozer + Burp](https://medium.com/p/4fd4730d1cf2)
- 2019.06 [NetworkHeros] [Bug Bounty : BurpSuite Professional v2.0.11 Free  and Set up for Proxy Intercept](https://www.youtube.com/watch?v=m7o-qIYzLt0)
- 2019.05 [web] [Scanning TLS Server Configurations with Burp Suite](https://web-in-security.blogspot.com/2019/05/scanning-tls-server-configurations-with.html)
- 2019.05 [infosecaddicts] [Burp Suite](https://infosecaddicts.com/burp-suite-2/)
- 2019.04 [parsiya] [Disabling Burp's Update Screen - Part 1 - Analysis and Failures](https://parsiya.net/blog/2019-04-21-disabling-burps-update-screen-part-1-analysis-and-failures/)
- 2019.04 [parsiya] [Disabling Burp's Update Screen - Part 1 - Analysis and Failures](https://parsiya.net/blog/2019-04-21-disabling-burps-update-screen---part-1---analysis-and-failures/)
- 2019.04 [parsiya] [Hiding OPTIONS - An Adventure in Dealing with Burp Proxy in an Extension](https://parsiya.net/blog/2019-04-06-hiding-options-an-adventure-in-dealing-with-burp-proxy-in-an-extension/)
- 2019.04 [parsiya] [Hiding OPTIONS - An Adventure in Dealing with Burp Proxy in an Extension](https://parsiya.net/blog/2019-04-06-hiding-options---an-adventure-in-dealing-with-burp-proxy-in-an-extension/)
- 2019.02 [infosecinstitute] [Quick and Dirty BurpSuite Tutorial (2019 Update)](https://resources.infosecinstitute.com/burpsuite-tutorial/)
- 2019.02 [pentestpartners] [Burp HMAC header extensions, a how-to](https://www.pentestpartners.com/security-blog/burp-hmac-header-extensions-a-how-to/)
- 2019.01 [freebuf] [详细讲解 | 利用python开发Burp Suite插件（二）](https://www.freebuf.com/articles/web/193950.html)
- 2019.01 [nxadmin] [Android 7.0+手机burpsuite抓包https](http://www.nxadmin.com/tools/1733.html)
- 2019.01 [freebuf] [详细讲解 | 利用python开发Burp Suite插件（一）](https://www.freebuf.com/news/193657.html)
- 2019.01 [freebuf] [Burpsuite Collaborato模块详解](https://www.freebuf.com/news/193447.html)
- 2019.01 [4hou] [利用Python编写具有加密和解密功能的Burp插件 （下）](http://www.4hou.com/technology/15502.html)
- 2019.01 [4hou] [利用Python编写具有加密和解密功能的Burp插件 （上）](http://www.4hou.com/technology/15501.html)
- 2019.01 [aliyun] [使用Burp Suite 宏自动化处理 Session 会话](https://xz.aliyun.com/t/3751)
- 2019.01 [sans] [Extending Burp to Find Struts and XXE Vulnerabilities](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1542133744.pdf)
- 2018.12 [parsiya] [Cryptography in Python Burp Extensions](https://parsiya.net/blog/2018-12-24-cryptography-in-python-burp-extensions/)
- 2018.12 [parsiya] [Python Utility Modules for Burp Extensions](https://parsiya.net/blog/2018-12-19-python-utility-modules-for-burp-extensions/)
- 2018.12 [ecforce] [创建Burp扩展, 使用HMAC签名替换HTTP Header](https://www.secforce.com/blog/2018/12/burp-extension-hmac-signature-in-custom-http-header/)
- 2018.12 [parsiya] [使用Burp的网站地图比较功能, 检测强制浏览/访问控制/直接对象引用等问题](https://parsiya.net/blog/2018-12-17-tiredful-api---part-2---comparing-site-maps-with-burp/)
- 2018.12 [parsiya] [Tiredful API - Part 2 - Comparing Site Maps with Burp](https://parsiya.net/blog/2018-12-17-tiredful-api-part-2-comparing-site-maps-with-burp/)
- 2018.12 [parsiya] [Tiredful API - Part 1 - Burp Session Validation with Macros](https://parsiya.net/blog/2018-12-11-tiredful-api-part-1-burp-session-validation-with-macros/)
- 2018.12 [4hou] [通过Burp Macros自动化平台对Web应用的模糊输入进行处理](http://www.4hou.com/web/14930.html)
- 2018.12 [parsiya] [Tiredful API. Part1: 使用宏验证Burp会话](https://parsiya.net/blog/2018-12-11-tiredful-api---part-1---burp-session-validation-with-macros/)
- 2018.12 [doyler] [Proxy Android Apps through Burp for Mobile Assessments](https://www.doyler.net/security-not-included/proxy-android-apps-through-burp)
- 2018.12 [mindpointgroup] [REST Assured: Penetration Testing REST APIs Using Burp Suite: Part 3 – Reporting](https://www.mindpointgroup.com/blog/rest-assured-penetration-testing-rest-apis-using-burp-suite-part-3-reporting/)
- 2018.11 [wallarm] [FAST or Burp or both?](https://medium.com/p/e61a935c9aca)
- 2018.11 [arbazhussain] [Broken Link Hijacking Burp Plugin](https://medium.com/p/6918d922c3fb)
- 2018.11 [4hou] [利用burp插件Hackvertor绕过waf并破解XOR加密](http://www.4hou.com/tools/14353.html)
- 2018.11 [mindpointgroup] [使用Burp对REST API进行渗透测试. Part2](https://www.mindpointgroup.com/blog/pen-test/rest-assured-penetration-testing-rest-apis-using-burp-suite-part-2-testing/)
- 2018.11 [pediy] [[原创]利用BurpSuite到SQLMap批量测试SQL注入](https://bbs.pediy.com/thread-247775.htm)
- 2018.11 [vanimpe] [Hunt for devices with default passwords (with Burp)](https://www.vanimpe.eu/2018/11/12/hunt-for-devices-with-default-passwords-with-burp/)
- 2018.11 [d0znpp] [Extending fuzzing with Burp by FAST](https://medium.com/p/f67d8b5d63e7)
- 2018.11 [jerrygamblin] [Automatically Create Github Issues From Burp 2.0](https://jerrygamblin.com/2018/11/07/automatically-create-github-issues-from-burp-2-0/)
- 2018.11 [mindpointgroup] [使用Burp Suite对REST API进行渗透测试. Part1:介绍与配置](https://www.mindpointgroup.com/blog/pen-test/rest-assured-penetration-testing-rest-apis-using-burp-suite-part-1-introduction-configuration/)
- 2018.11 [doyensec] [Introducing burp-rest-api v2](https://blog.doyensec.com/2018/11/05/burp-rest-api-v2.html)
- 2018.10 [valerio] [MITM using arpspoof + Burp or mitmproxy on Kali Linux](https://medium.com/p/95213ff60304)
- 2018.10 [portswigger] [Burp 2.0: How do I throttle requests? | Blog](https://portswigger.net/blog/burp-2-0-how-do-i-throttle-requests)
- 2018.10 [portswigger] [Burp 2.0: Where is live scanning? | Blog](https://portswigger.net/blog/burp-2-0-where-is-live-scanning)
- 2018.10 [portswigger] [Burp 2.0: How do I scan individual items? | Blog](https://portswigger.net/blog/burp-2-0-how-do-i-scan-individual-items)
- 2018.10 [portswigger] [Burp 2.0: Where is the scan queue? | Blog](https://portswigger.net/blog/burp-2-0-where-is-the-scan-queue)
- 2018.10 [MastersInEthicalHacking] [An Introduction To Burp Suite Tool In Hindi](https://www.youtube.com/watch?v=NIxy8rLQ4zI)
- 2018.10 [portswigger] [Burp 2.0: Where are the Spider and Scanner? | Blog](https://portswigger.net/blog/burp-2-0-where-are-the-spider-and-scanner)
- 2018.09 [4hou] [使用Burp和Ysoserial实现Java反序列化漏洞的盲利用](http://www.4hou.com/technology/13440.html)
- 2018.08 [portswigger] [Burp Suite Enterprise Edition beta now available | Blog](https://portswigger.net/blog/burp-suite-enterprise-edition-beta-now-available)
- 2018.08 [jerrygamblin] [Bulk Bug Bounty Scanning With The Burp 2.0 API](https://jerrygamblin.com/2018/08/30/bulk-bug-bounty-scanning-with-the-burp-2-0-api/)
- 2018.08 [4hou] [Burp Extractor扩展工具介绍](http://www.4hou.com/tools/12985.html)
- 2018.08 [aliyun] [BurpSuite Extender之巧用Marco和Extractor绕过Token限制](https://xz.aliyun.com/t/2547)
- 2018.08 [netspi] [Introducing Burp Extractor](https://blog.netspi.com/introducing-burp-extractor/)
- 2018.08 [portswigger] [Burp's new crawler | Blog](https://portswigger.net/blog/burps-new-crawler)
- 2018.07 [cqureacademy] [How To Burp With Confidence – Our 5 Favorite Features](https://cqureacademy.com/blog/penetration-testing/how-to-burp-our-5-favorite-features)
- 2018.07 [freebuf] [使用VirtualBox，INetSim和Burp建立自己的恶意软件分析实验环境](http://www.freebuf.com/articles/system/177601.html)
- 2018.07 [web] [Support for XXE attacks in SAML in our Burp Suite extension](https://web-in-security.blogspot.com/2018/07/support-for-xxe-attacks-in-saml-in-our.html)
- 2018.06 [bugbountywriteup] [How to brute force efficiently without Burp Pro](https://medium.com/p/1bb2a414a09f)
- 2018.06 [finnwea] [An efficiency improvement for Burp Suite](https://finnwea.com/blog/an-efficiency-improvement-for-burp-suite/)
- 2018.06 [finnwea] [An efficiency improvement for Burp Suite](https://tij.me/blog/an-efficiency-improvement-for-burp-suite/)
- 2018.06 [hackers] [Online Password Cracking with THC-Hydra and BurpSuite](https://www.hackers-arise.com/single-post/2018/06/21/Online-Password-Cracking-with-THC-Hydra-and-BurpSuite)
- 2018.06 [integrity] [CVE-2018-10377 - Insufficient Validation of Burp Collaborator Server Certificate](https://labs.integrity.pt/advisories/cve-2018-10377/)
- 2018.06 [NetworkHeros] [Ethical Hacking (CEHv10) :Intercept HTTPS (SSL) traffic with Burpsuite](https://www.youtube.com/watch?v=rhJcRqgScz8)
- 2018.06 [NetworkHeros] [Ethical Hacking (CEHv10): BurpSuite install and configure proxy](https://www.youtube.com/watch?v=tK_nCYWbbOc)
- 2018.05 [hackerone] [New Hacker101 Content: Threat modeling, Burp basics, and more](https://www.hackerone.com/blog/New-Hacker101-Content-Threat-modeling-Burp-basics-and-more)
- 2018.05 [aliyun] [基于Burp Collaborator的HTTP API](https://xz.aliyun.com/t/2353)
- 2018.05 [freebuf] [Burpsuit结合SQLMapAPI产生的批量注入插件（X10）](http://www.freebuf.com/articles/web/171622.html)
- 2018.05 [tevora] [Blind Command Injection Testing with Burp Collaborator](http://threat.tevora.com/stop-collaborate-and-listen/)
- 2018.05 [pentestingexperts] [Minesweeper – A Burpsuite plugin (BApp) to aid in the detection of cryptocurrency mining domains (cryptojacking)](http://www.pentestingexperts.com/minesweeper-a-burpsuite-plugin-bapp-to-aid-in-the-detection-of-cryptocurrency-mining-domains-cryptojacking/)
- 2018.05 [freebuf] [Burp Xss Scanner插件开发思路分享（附下载）](http://www.freebuf.com/articles/web/170884.html)
- 2018.05 [thief] [burpsuite插件开发之检测越权访问漏洞](https://thief.one/2018/05/04/1/)
- 2018.05 [freebuf] [Burpsuit结合SQLMapAPI产生的批量注入插件](http://www.freebuf.com/articles/web/169727.html)
- 2018.04 [PNPtutorials] [Burpsuite Tutorial for Beginners: Learn Burpsuite from Scratch](https://www.youtube.com/watch?v=BaN89Te85W4)
- 2018.04 [freebuf] [实现一个简单的Burp验证码本地识别插件](http://www.freebuf.com/articles/web/168679.html)
- 2018.04 [dustri] [Confusing Burp's display with fake encoding](https://dustri.org/b/confusing-burps-display-with-fake-encoding.html)
- 2018.04 [aliyun] [如何搭建自己的 Burp Collaborator 服务器](https://xz.aliyun.com/t/2267)
- 2018.04 [JosephDelgadillo] [Learn Kali Linux Episode #55: Burp Suite Basics](https://www.youtube.com/watch?v=vUzJZhhJjpk)
- 2018.04 [freebuf] [关于Sql注入以及Burpsuite Intruders使用的一些浅浅的见解](http://www.freebuf.com/news/166495.html)
- 2018.03 [secureideas] [Burp Suite continuing the Saga](https://blog.secureideas.com/2018/03/burp-suite-continuing-the-saga.html)
- 2018.03 [HackerSploit] [Web App Penetration Testing - #3 - Brute Force Attacks With Burp Suite](https://www.youtube.com/watch?v=cL9NsXpUqYI)
- 2018.03 [blackhillsinfosec] [Gathering Usernames from Google LinkedIn Results Using Burp Suite Pro](https://www.blackhillsinfosec.com/gathering-usernames-from-google-linkedin-results-using-burp-suite-pro/)
- 2018.03 [nviso] [Intercepting Belgian eID (PKCS#11) traffic with Burp Suite on OS X / Kali / Windows](https://blog.nviso.be/2018/03/05/intercepting-belgian-eid-pkcs11-traffic-with-burp-suite-on-os-x-kali-windows/)
- 2018.03 [4hou] [使用BurpSuite的Collaborator查找.Onion隐藏服务的真实IP地址](http://www.4hou.com/technology/10367.html)
- 2018.02 [hackingarticles] [Advance Web Application Testing using Burpsuite](http://www.hackingarticles.in/advance-web-application-testing-using-burpsuite/)
- 2018.02 [HackerSploit] [Web App Penetration Testing - #1 - Setting Up Burp Suite](https://www.youtube.com/watch?v=YCCrVtvAu2I)
- 2018.02 [hackers] [Online Password Cracking with THC-Hydra and Burp Suite](https://www.hackers-arise.com/single-post/2018/02/26/Online-Password-Cracking-with-THC-Hydra-and-Burp-Suite)
- 2018.02 [nxadmin] [ios 11.2.5 burpsuite抓https](http://www.nxadmin.com/mobile-sec/1673.html)
- 2018.02 [ZeroNights] [[Defensive Track]Eldar Zaitov, Andrey Abakumov - Automation of Web Application Scanning With Burp](https://www.youtube.com/watch?v=pQ4v4H7bHLE)
- 2018.02 [hackingarticles] [Engagement Tools Tutorial in Burp suite](http://www.hackingarticles.in/engagement-tools-tutorial-burp-suite/)
- 2018.02 [hackingarticles] [Payload Processing Rule in Burp suite (Part 2)](http://www.hackingarticles.in/payload-processing-rule-burp-suite-part-2/)
- 2018.02 [dustri] [Ghetto recursive payload in the Burp Intruder](https://dustri.org/b/ghetto-recursive-payload-in-the-burp-intruder.html)
- 2018.02 [hackingarticles] [Payload Processing Rule in Burp suite (Part 1)](http://www.hackingarticles.in/payload-processing-rule-burp-suite-part-1/)
- 2018.01 [4hou] [如何绕过csrf保护，并在burp suite中使用intruder？](http://www.4hou.com/technology/10134.html)
- 2018.01 [360] [恶意软件逆向：burpsuite 序列号器后门分析](https://www.anquanke.com/post/id/96866/)
- 2018.01 [nviso] [结合使用 Burp 与自定义 rootCA 来探查 Android N 网络流量](https://blog.nviso.be/2018/01/31/using-a-custom-root-ca-with-burp-for-inspecting-android-n-traffic/)
- 2018.01 [hackingarticles] [WordPress Exploitation using Burpsuite (Burp_wp Plugin)](http://www.hackingarticles.in/wordpress-exploitation-using-burpsuite-burp_wp-plugin/)
- 2018.01 [0x00sec] [之前发布的 Burpsuite Keygen 内嵌的后门分析](https://0x00sec.org/t/malware-reversing-burpsuite-keygen/5167/)
- 2018.01 [hackingarticles] [Beginners Guide to Burpsuite Payloads (Part 2)](http://www.hackingarticles.in/beginners-guide-burpsuite-payloads-part-2/)
- 2018.01 [freebuf] [如何在Android Nougat中正确配置Burp Suite？](http://www.freebuf.com/articles/network/160900.html)
- 2018.01 [hackingarticles] [Burpsuite Encoder & Decoder Tutorial](http://www.hackingarticles.in/burpsuite-encoder-decoder-tutorial/)
- 2018.01 [hackingarticles] [Beginners Guide to Burpsuite Payloads (Part 1)](http://www.hackingarticles.in/beginners-guide-burpsuite-payloads-part-1/)
- 2018.01 [security] [Burp WP - Find vulnerabilities in WordPress using Burp](https://security.szurek.pl/burp-wp-find-vulnerabilities-in-wordpress-using-burp.html)
- 2018.01 [ropnop] [Configuring Burp Suite with Android Nougat](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/)
- 2018.01 [DemmSec] [Beginner Hacking 2.0 - Episode 6 - Burp (Brute-forcing)](https://www.youtube.com/watch?v=6EZ2oU-qsOQ)
- 2018.01 [blackhillsinfosec] [Analyzing Extension Effectiveness with Burp](https://www.blackhillsinfosec.com/analyzing-extension-effectiveness-burp/)
- 2018.01 [freebuf] [经验分享 | Burpsuite抓取非HTTP流量](http://www.freebuf.com/articles/network/158589.html)
- 2018.01 [4hou] [实战教程：用Burpsuite测试移动应用程序](http://www.4hou.com/penetration/8965.html)
- 2017.12 [pediy] [[翻译]使用Burp Suite执行更复杂的Intruder攻击](https://bbs.pediy.com/thread-223642.htm)
- 2017.12 [freebuf] [如何使用Burp和Magisk在Android 7.0监测HTTPS流量](http://www.freebuf.com/articles/terminal/158492.html)
- 2017.12 [freebuf] [经验分享 | Burpsuite插件的使用](http://www.freebuf.com/sectool/158005.html)
- 2017.12 [nviso] [Intercepting HTTPS Traffic from Apps on Android 7+ using Magisk & Burp](https://blog.nviso.be/2017/12/22/intercepting-https-traffic-from-apps-on-android-7-using-magisk-burp/)
- 2017.12 [trustedsec] [More Complex Intruder Attacks with Burp!](https://www.trustedsec.com/2017/12/complex-intruder-attacks-burp/)
- 2017.12 [4hou] [如何使用 Burp 代理调试安卓应用中的 HTTP(S) 流量](http://www.4hou.com/web/9385.html)
- 2017.12 [aliyun] [安卓脱壳&&协议分析&&Burp辅助分析插件编写](https://xz.aliyun.com/t/1805)
- 2017.12 [freebuf] [新手福利 | Burpsuite你可能不知道的技巧](http://www.freebuf.com/articles/rookie/156928.html)
- 2017.12 [freebuf] [经验分享 | Burpsuite中宏的使用](http://www.freebuf.com/articles/web/156735.html)
- 2017.12 [aliyun] [使用OWASP Zap度过没有Burp的过渡期](https://xz.aliyun.com/t/1782)
- 2017.12 [avleonov] [Vulners.com vulnerability detection plugins for Burp Suite and Google Chrome](https://avleonov.com/2017/12/10/vulners-com-vulnerability-detection-plugins-for-burp-suite-and-google-chrome/)
- 2017.12 [freebuf] [利用Burp Suite挖掘暗网服务的真实IP](http://www.freebuf.com/articles/web/155254.html)
- 2017.11 [digitalforensicstips] [Using Burp Suite’s Collaborator to Find the True IP Address for a .Onion Hidden Service](http://digitalforensicstips.com/2017/11/using-burp-suites-collaborator-to-find-the-true-ip-address-for-a-onion-hidden-service/)
- 2017.11 [n00py] [Exploiting blind Java deserialization with Burp and Ysoserial](https://www.n00py.io/2017/11/exploiting-blind-java-deserialization-with-burp-and-ysoserial/)
- 2017.11 [nxadmin] [burpsuite抓包https请求相关](http://www.nxadmin.com/mobile-sec/1646.html)
- 2017.11 [polaris] [reCAPTCHA：一款自动识别图形验证码并用于Intruder Payload中的BurpSuite插件](http://polaris-lab.com/index.php/archives/387/)
- 2017.10 [TechnoHacker] [How to Crack Logins with Burp Suite](https://www.youtube.com/watch?v=SCHEBItZkdo)
- 2017.10 [freebuf] [利用Burp Suite对OWASP Juice Shop进行渗透测试](http://www.freebuf.com/sectool/151920.html)
- 2017.10 [4hou] [Bypass WAF：使用Burp插件绕过一些WAF设备](http://www.4hou.com/tools/8065.html)
- 2017.10 [gdssecurity] [Pentesting Fast Infoset based web applications with Burp](https://blog.gdssecurity.com/labs/2017/10/10/pentesting-fast-infoset-based-web-applications-with-burp.html)
- 2017.10 [d0znpp] [The best Burp plugin I’ve ever seen](https://medium.com/p/2d17780342)
- 2017.10 [n00py] [How to Burp Good](https://www.n00py.io/2017/10/how-to-burp-good/)
- 2017.09 [netspi] [BurpCollaboratorDNSTunnel 介绍](https://blog.netspi.com/dns-tunneling-with-burp-collaborator/)
- 2017.09 [freebuf] [Handy Collaborator ：用于挖掘out-of-band类漏洞的Burp插件介绍](http://www.freebuf.com/sectool/147948.html)
- 2017.09 [aliyun] [请问能burpsuite的插件中直接获取到直接获取到漏洞报告吗？](https://xz.aliyun.com/t/1018)
- 2017.09 [niemand] [Automatizing Burp + Carbonator + Slack](https://niemand.com.ar/2017/09/18/automatizing-burp-carbonator-slack/)
- 2017.09 [trustwave] [burplay介绍](https://www.trustwave.com/Resources/SpiderLabs-Blog/Introducing-Burplay,-A-Burp-Extension-for-Detecting-Privilege-Escalations/)
- 2017.09 [freebuf] [如何通过BurpSuiteMacro自动化模糊测试Web应用的输入点](http://www.freebuf.com/articles/web/147182.html)
- 2017.09 [mediaservice] [HandyCollaborator介绍](https://techblog.mediaservice.net/2017/09/handy-collaborator-because-burp-suite-collaborator-is-useful-also-during-manual-testing/)
- 2017.09 [securestate] [Updating Anti-CSRF Tokens in Burp Suite](https://warroom.securestate.com/updating-anti-csrf-tokens-burp-suite/)
- 2017.09 [4hou] [利用Burp“宏”解决自动化 web fuzzer的登录问题](http://www.4hou.com/web/7542.html)
- 2017.09 [securestate] [Updating Anti-CSRF Tokens in Burp Suite](https://warroom.rsmus.com/updating-anti-csrf-tokens-burp-suite/)
- 2017.09 [360] [如何使用Burp Suite Macros绕过防护进行自动化fuzz测试](https://www.anquanke.com/post/id/86768/)
- 2017.09 [initblog] [Hacking a Pizza Order with Burp Suite](https://initblog.com/2017/pizza-hacking/)
- 2017.09 [securelayer7] [使用 Burp 的宏功能，实现 WebApp 输入 Fuzzing 的自动化](http://blog.securelayer7.net/automating-web-apps-input-fuzzing-via-burp-macros/)
- 2017.09 [securelayer7] [Automating Web Apps Input fuzzing via Burp Macros](https://blog.securelayer7.org/automating-web-apps-input-fuzzing-via-burp-macros/)
- 2017.09 [freebuf] [如何在特定的渗透测试中使用正确的Burp扩展插件](http://www.freebuf.com/sectool/146247.html)
- 2017.08 [avleonov] [Burp Suite Free Edition and NTLM authentication in ASP.net applications](https://avleonov.com/2017/08/29/burp-suite-free-edition-and-ntlm-authentication-in-asp-net-applications/)
- 2017.08 [portswigger] [如何为特定的渗透测试环境定制 Burp 扩展](https://portswigger.net/blog/adapting-burp-extensions-for-tailored-pentesting)
- 2017.08 [cybrary] [Your Complete Guide to Burp Suite](https://www.cybrary.it/2017/08/your-complete-guide-to-burp-suite/)
- 2017.08 [freebuf] [使用Burp和自定义Sqlmap Tamper利用二次注入漏洞](http://www.freebuf.com/articles/web/142963.html)
- 2017.08 [freebuf] [HUNT：一款可提升漏洞扫描能力的BurpSuite漏洞扫描插件](http://www.freebuf.com/sectool/143182.html)
- 2017.08 [4hou] [通过Burp以及自定义的Sqlmap Tamper进行二次SQL注入](http://www.4hou.com/system/6945.html)
- 2017.08 [360] [Burp Suite扩展之Java-Deserialization-Scanner](https://www.anquanke.com/post/id/86594/)
- 2017.08 [360] [联合Frida和BurpSuite的强大扩展--Brida](https://www.anquanke.com/post/id/86567/)
- 2017.08 [360] [如何借助Burp和SQLMap Tamper利用二次注入](https://www.anquanke.com/post/id/86551/)
- 2017.08 [4hou] [如何使用Burp Suite模糊测试SQL注入、XSS、命令执行漏洞](http://www.4hou.com/vulnerable/6933.html)
- 2017.08 [4hou] [Brida:将frida与burp结合进行移动app渗透测试](http://www.4hou.com/penetration/6916.html)
- 2017.08 [pentest] [使用 Burp 和自定义的Sqlmap Tamper 脚本实现 Second Order SQLi 漏洞利用](https://pentest.blog/exploiting-second-order-sqli-flaws-by-using-burp-custom-sqlmap-tamper/)
- 2017.07 [360] [BurpSuite插件：利用BurpSuite Spider收集子域名和相似域名](https://www.anquanke.com/post/id/86512/)
- 2017.07 [polaris] [BurpSuite插件：利用BurpSuite Spider收集子域名和相似域名](http://polaris-lab.com/index.php/archives/349/)
- 2017.07 [hackingarticles] [Fuzzing SQL,XSS and Command Injection using Burp Suite](http://www.hackingarticles.in/fuzzing-sqlxss-command-injection-using-burp-suite/)
- 2017.07 [freebuf] [Burp Suite扫描器漏洞扫描功能介绍及简单教程](http://www.freebuf.com/sectool/141435.html)
- 2017.07 [hackerone] [Hey Hackers: We’ve got your free Burp Suite Professional license right here](https://www.hackerone.com/blog/Hey-Hackers-Weve-got-your-free-Burp-Suite-Professional-license-right-here)
- 2017.07 [hackingarticles] [Vulnerability Analysis in Web Application using Burp Scanner](http://www.hackingarticles.in/vulnerability-analysis-web-application-using-burp-scanner/)
- 2017.07 [aliyun] [Burpsuite handshake alert: unrecognized_name解决办法](https://xz.aliyun.com/t/1080)
- 2017.07 [4hou] [用VirtualBox、INetSim和Burp配置一个恶意软件分析实验室](http://www.4hou.com/technology/5655.html)
- 2017.07 [vulners] [2 years of Vulners and new plugin for Burp Scanner](https://blogvulners.wordpress.com/2017/07/07/2-years-of-vulners-and-new-plugin-for-burp-scanner/)
- 2017.07 [intrinsec] [Burp extension « Scan manual insertion point »](https://securite.intrinsec.com/2017/07/03/burp-extension-scan-manual-insertion-point/)
- 2017.06 [hackingarticles] [How to Spider Web Applications using Burpsuite](http://www.hackingarticles.in/spider-web-applications-using-burpsuite/)
- 2017.06 [4hou] [使用 Burp Infiltrator 进行漏洞挖掘](http://www.4hou.com/tools/5815.html)
- 2017.06 [8090] [渗透测试神器Burp Suite v1.6.17（破解版）](http://www.8090-sec.com/archives/8674)
- 2017.06 [4hou] [将Burp Scanner漏洞结果转换为Splunk事件](http://www.4hou.com/technology/5703.html)
- 2017.06 [portswigger] [Behind enemy lines: bug hunting with Burp Infiltrator | Blog](https://portswigger.net/blog/behind-enemy-lines-bug-hunting-with-burp-infiltrator)
- 2017.06 [christophetd] [使用 VirtualBox，INetSim和 Burp 搭建自己的恶意软件分析实验室](https://blog.christophetd.fr/malware-analysis-lab-with-virtualbox-inetsim-and-burp/)
- 2017.05 [aliyun] [各位师傅们请问BurpSuite怎么同时传递多个页面](https://xz.aliyun.com/t/1147)
- 2017.05 [360] [Burp Suite Mobile Assistant](https://www.anquanke.com/post/id/86117/)
- 2017.05 [4hou] [NTLM认证失效时，如何使用Fiddler配合Burp Suite进行渗透测试？](http://www.4hou.com/technology/4797.html)
- 2017.05 [netspi] [Beautifying JSON in Burp](https://blog.netspi.com/beautifying-json-in-burp/)
- 2017.05 [mediaservice] [NTLM认证失效时，如何使用Fiddler配合Burp Suite进行渗透测试？](https://techblog.mediaservice.net/2017/05/fiddler-ntlm-authentication-when-burp-suite-fails/)
- 2017.05 [compass] [JWT Burp Extension](https://blog.compass-security.com/2017/05/jwt-burp-extension/)
- 2017.05 [trustwave] [Airachnid: Web Cache Deception Burp Extender](https://www.trustwave.com/Resources/SpiderLabs-Blog/Airachnid--Web-Cache-Deception-Burp-Extender/)
- 2017.05 [moxia] [【技术分享】Burp Suite扩展开发之Shodan扫描器（已开源）](http://www.moxia.org/Blog.php/index.php/archives/214)
- 2017.05 [elearnsecurity] [Developing Burp Suite Extensions](https://blog.elearnsecurity.com/developing-burp-suite-extensions.html)
- 2017.04 [securityblog] [Stunnel and Burp Pro](http://securityblog.gr/4329/stunnel-and-burp-pro/)
- 2017.04 [] [Build a Private Burp Collaborator Server on AWS with Terraform and Ansible](https://www.4armed.com/blog/burp-collaborator-terraform-ansible/)
- 2017.04 [aliyun] [Burp Suite收集到的录像、文档以及视频资料](https://xz.aliyun.com/t/1175)
- 2017.04 [360] [BurpSuite 代理设置的小技巧](https://www.anquanke.com/post/id/85925/)
- 2017.04 [freebuf] [如何通过BurpSuite检测Blind XSS漏洞](http://www.freebuf.com/articles/web/131545.html)
- 2017.04 [jerrygamblin] [Burp Settings File](https://jerrygamblin.com/2017/04/17/burp-settings-file/)
- 2017.04 [doyler] [Burp VERBalyzer v1.0 Release](https://www.doyler.net/security-not-included/burp-verbalyzer-release)
- 2017.04 [agarri] [Exploiting a Blind XSS using Burp Suite](http://www.agarri.fr/blog/../kom/archives/2017/04/04/exploiting_a_blind_xss_using_burp_suite/index.html)
- 2017.04 [agarri] [Exploiting a Blind XSS using Burp Suite](https://www.agarri.fr/blog/archives/2017/04/04/exploiting_a_blind_xss_using_burp_suite/index.html)
- 2017.04 [blackhillsinfosec] [Using Burp with ProxyCannon](https://www.blackhillsinfosec.com/using-burp-proxycannon/)
- 2017.03 [4hou] [利用Burp“宏”自动化另类 SQLi](http://www.4hou.com/technology/3664.html)
- 2017.03 [freebuf] [Burpsuite+SQLMAP双璧合一绕过Token保护的应用进行注入攻击](http://www.freebuf.com/sectool/128589.html)
- 2017.03 [360] [使用burp macros和sqlmap绕过csrf防护进行sql注入](https://www.anquanke.com/post/id/85593/)
- 2017.02 [zsec] [Learning the Ropes 101: Burp Suite Intro](https://blog.zsec.uk/ltr101-burp-suite-intro/)
- 2017.02 [cyberis] [Creating Macros for Burp Suite](https://www.cyberis.co.uk/burp_macros.html)
- 2017.02 [polaris] [使用BurpSuite攻击JavaScript Web服务代理](http://polaris-lab.com/index.php/archives/150/)
- 2017.02 [netspi] [Attacking JavaScript Web Service Proxies with Burp](https://blog.netspi.com/attacking-javascript-web-service-proxies-burp/)
- 2017.02 [freebuf] [使用Burpsuite代理和pypcap抓包进行抢红包的尝试](http://www.freebuf.com/sectool/125969.html)
- 2017.02 [polaris] [BurpSuite和Fiddler串联使用解决App测试漏包和速度慢的问题](http://polaris-lab.com/index.php/archives/15/)
- 2017.01 [securityinnovation] [Solve the Software Security Authorization Testing Riddle with AuthMatrix for Burp Suite](https://blog.securityinnovation.com/solve-the-software-security-authorization-testing-riddle-with-authmatrix-for-burp-suite)
- 2017.01 [freebuf] [使用Frida配合Burp Suite追踪API调用](http://www.freebuf.com/articles/web/125260.html)
- 2017.01 [hackingarticles] [Hack the Basic HTTP Authentication using Burpsuite](http://www.hackingarticles.in/hack-basic-http-authentication-using-burpsuite/)
- 2017.01 [hackingarticles] [Sql Injection Exploitation with Sqlmap and Burp Suite (Burp CO2 Plugin)](http://www.hackingarticles.in/sql-injection-exploitation-sqlmap-burp-suite-burp-co2-plugin/)
- 2017.01 [360] [超越检测：利用Burp Collaborator执行SQL盲注](https://www.anquanke.com/post/id/85297/)
- 2017.01 [360] [使用Burp的intruder功能测试有csrf保护的应用程序](https://www.anquanke.com/post/id/85289/)
- 2017.01 [polaris] [BurpSuite插件开发Tips：请求响应参数的AES加解密](http://polaris-lab.com/index.php/archives/40/)
- 2017.01 [silentsignal] [Beyond detection: exploiting blind SQL injections with Burp Collaborator](https://blog.silentsignal.eu/2017/01/03/beyond-detection-exploiting-blind-sql-injections-with-burp-collaborator/)
- 2016.12 [polaris] [BurpSuite插件分享：图形化重算sign和参数加解密插件](http://polaris-lab.com/index.php/archives/19/)
- 2016.12 [360] [Burp Suite扩展开发之Shodan扫描器（已开源）](https://www.anquanke.com/post/id/85209/)
- 2016.12 [rapid7] [Burp Series: Intercepting and modifying made easy](https://blog.rapid7.com/2016/12/09/burp-series-intercepting-and-modifying-made-easy/)
- 2016.12 [polaris] [BurpSuite 实战指南](http://polaris-lab.com/index.php/archives/136/)
- 2016.12 [360] [BurpSuite 实战指南（附下载地址）](https://www.anquanke.com/post/id/85086/)
- 2016.12 [aliyun] [BurpSuite实战指南](https://xz.aliyun.com/t/1306)
- 2016.12 [freebuf] [burpsuite_pro_v1.7.11破解版（含下载）](http://www.freebuf.com/sectool/121992.html)
- 2016.12 [hackers] [Web App Hacking: Hacking Form Authentication with Burp Suite](https://www.hackers-arise.com/single-post/2016/12/05/Web-App-Hacking-Hacking-Form-Authentication-with-Burp-Suite)
- 2016.12 [360] [burpsuite_pro_v1.7.11破解版(含下载地址)](https://www.anquanke.com/post/id/85052/)
- 2016.12 [] [burpsuite_pro_v1.7.11破解版(含下载地址)](http://www.91ri.org/16532.html)
- 2016.11 [nxadmin] [Burpsuite抓包Android模拟器(AVD)设置](http://www.nxadmin.com/mobile-sec/1511.html)
- 2016.11 [jerrygamblin] [Automated Burp Suite Scanning and Reporting To Slack.](https://jerrygamblin.com/2016/11/12/automated-burp-suite-scanning-and-reporting-to-slack/)
- 2016.11 [360] [Burp Suite插件开发之SQL注入检测（已开源）](https://www.anquanke.com/post/id/84882/)
- 2016.11 [freebuf] [渗透测试神器Burp Suite v1.7.08发布（含下载）](http://www.freebuf.com/sectool/118802.html)
- 2016.10 [averagesecurityguy] [Recon-ng + Google Dorks + Burp = ...](https://averagesecurityguy.github.io/2016/10/21/recon-ng-dorks-burp/)
- 2016.10 [kalilinuxtutorials] [Burpsuite – Use Burp Intruder to Bruteforce Forms](http://kalilinuxtutorials.com/burp-intruder-bruteforce-forms/)
- 2016.10 [hackingarticles] [SMS Bombing on Mobile using Burpsuite](http://www.hackingarticles.in/sms-bombing-mobile-using-burpsuite/)
- 2016.09 [hackingarticles] [Hijacking Gmail Message on Air using Burpsuite](http://www.hackingarticles.in/hijacking-gmail-message-air-using-burpsuite/)
- 2016.09 [securify] [Burp Suite security automation with Selenium and Jenkins](https://securify.nl/en/blog/SFY20160901/burp-suite-security-automation-with-selenium-and-jenkins.html)
- 2016.09 [hackingarticles] [Brute Force Website Login Page using Burpsuite (Beginner Guide)](http://www.hackingarticles.in/brute-force-website-login-page-using-burpsuite-beginner-guide/)
- 2016.09 [securityblog] [Simple python script to make multiple raw requests from Burp](http://securityblog.gr/3634/simple-python-script-to-make-multiple-raw-requests-from-burp/)
- 2016.09 [freebuf] [新手教程：如何使用Burpsuite抓取手机APP的HTTPS数据](http://www.freebuf.com/articles/terminal/113940.html)
- 2016.08 [bogner] [Burp.app – Making Burp a little more OS X like](https://bogner.sh/2016/08/burp-app-making-burp-a-bit-more-os-x-like/)
- 2016.08 [] [Configuring Google Chrome to Proxy Through Burp Suite](https://www.4armed.com/blog/google-chrome-proxy-through-burp-suite/)
- 2016.07 [portswigger] [Introducing Burp Infiltrator | Blog](https://portswigger.net/blog/introducing-burp-infiltrator)
- 2016.07 [] [Burpsuite之Burp Collaborator模块介绍](http://www.91ri.org/16159.html)
- 2016.06 [timothydeblock] [When not to use Burp Suite](http://www.timothydeblock.com/eis/49)
- 2016.06 [freebuf] [BurpSuite插件开发Tips：请求响应参数的AES加解密](http://www.freebuf.com/articles/terminal/106673.html)
- 2016.06 [securityblog] [Using Burp Intruder to Test CSRF Protected Applications](http://securityblog.gr/3446/using-burp-intruder-to-test-csrf-protected-applications/)
- 2016.06 [insinuator] [SAMLReQuest Burpsuite Extention](https://insinuator.net/2016/06/samlrequest-burpsuite-extention/)
- 2016.05 [jerrygamblin] [BurpBrowser](https://jerrygamblin.com/2016/05/31/burpbrowser/)
- 2016.05 [safebuff] [ImageTragick using BurpSuite and Metasploit](http://blog.safebuff.com/2016/05/26/ImageTragick-using-BurpSuite-and-Metasploit/)
- 2016.05 [freebuf] [BurpSuite日志分析过滤工具，加快SqlMap进行批量扫描的速度](http://www.freebuf.com/sectool/104855.html)
- 2016.05 [] [再谈Burp破解](http://www.91ri.org/15799.html)
- 2016.05 [silentsignal] [Detecting ImageTragick with Burp Suite Pro](https://blog.silentsignal.eu/2016/05/13/detecting-imagetragick-with-burp-suite-pro/)
- 2016.04 [freebuf] [Burpsuite插件开发（二）：信息采集插件](http://www.freebuf.com/sectool/102673.html)
- 2016.04 [toolswatch] [Burp Suite Professional v1.7.02 Beta](http://www.toolswatch.org/2016/04/burp-suite-professional-v1-7-02-beta/)
- 2016.04 [freebuf] [针对非Webapp测试的Burp技巧（二）：扫描、重放](http://www.freebuf.com/articles/web/100875.html)
- 2016.04 [freebuf] [针对非Webapp测试的Burp技巧(一)：拦截和代理监听](http://www.freebuf.com/articles/terminal/100908.html)
- 2016.04 [portswigger] [Introducing Burp Projects | Blog](https://portswigger.net/blog/introducing-burp-projects)
- 2016.04 [parsiya] [Thick Client Proxying - Part 4: Burp in Proxy Chains](https://parsiya.net/blog/2016-04-07-thick-client-proxying---part-4-burp-in-proxy-chains/)
- 2016.04 [parsiya] [Thick Client Proxying - Part 4: Burp in Proxy Chains](https://parsiya.net/blog/2016-04-07-thick-client-proxying-part-4-burp-in-proxy-chains/)
- 2016.04 [breakpoint] [Web Hacking with Burp Suite 101](https://breakpoint-labs.com/blog/web-hacking-with-burp-suite-101/)
- 2016.04 [parsiya] [Thick Client Proxying - Part 3: Burp Options and Extender](https://parsiya.net/blog/2016-04-02-thick-client-proxying---part-3-burp-options-and-extender/)
- 2016.04 [hack] [Advanced Burp Suite](https://hack-ed.net/2016/04/02/advanced-burp-suite/)
- 2016.04 [parsiya] [Thick Client Proxying - Part 3: Burp Options and Extender](https://parsiya.net/blog/2016-04-02-thick-client-proxying-part-3-burp-options-and-extender/)
- 2016.03 [freebuf] [Burp Suite新手指南](http://www.freebuf.com/articles/web/100377.html)
- 2016.03 [parsiya] [Thick Client Proxying - Part 2: Burp History, Intruder, Scanner and More](https://parsiya.net/blog/2016-03-29-thick-client-proxying---part-2-burp-history-intruder-scanner-and-more/)
- 2016.03 [parsiya] [Thick Client Proxying - Part 2: Burp History, Intruder, Scanner and More](https://parsiya.net/blog/2016-03-29-thick-client-proxying-part-2-burp-history-intruder-scanner-and-more/)
- 2016.03 [freebuf] [如何编写burpsuite联动sqlmap的插件](http://www.freebuf.com/sectool/100093.html)
- 2016.03 [parsiya] [Thick Client Proxying - Part 1: Burp Interception and Proxy Listeners](https://parsiya.net/blog/2016-03-27-thick-client-proxying---part-1-burp-interception-and-proxy-listeners/)
- 2016.03 [parsiya] [Thick Client Proxying - Part 1: Burp Interception and Proxy Listeners](https://parsiya.net/blog/2016-03-27-thick-client-proxying-part-1-burp-interception-and-proxy-listeners/)
- 2016.03 [portswigger] [Using Burp Suite to audit and exploit an eCommerce application | Blog](https://portswigger.net/blog/using-burp-suite-to-audit-and-exploit-an-ecommerce-application)
- 2016.03 [freebuf] [渗透测试神器Burpsuite Pro v1.6.38（含下载）](http://www.freebuf.com/sectool/99127.html)
- 2016.03 [360] [使用burp进行java反序列化攻击](https://www.anquanke.com/post/id/83571/)
- 2016.03 [netspi] [Java Deserialization Attacks with Burp](https://blog.netspi.com/java-deserialization-attacks-burp/)
- 2016.02 [] [对burpsuite_pro逆向的一点心得](http://www.91ri.org/15264.html)
- 2016.02 [parsiya] [Installing Burp Certificate Authority in Windows Certificate Store](https://parsiya.net/blog/2016-02-21-installing-burp-certificate-authority-in-windows-certificate-store/)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 00 - Intro](https://www.youtube.com/watch?v=AVzC7ETqpDo)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 06 - Sequencer and Scanner](https://www.youtube.com/watch?v=G-v581pXerE)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 04 - Repeater Module](https://www.youtube.com/watch?v=9Zh_7s5csCc)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 03 - Proxy Module](https://www.youtube.com/watch?v=PDTwYFkjQBE)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 05 - Target and Spider](https://www.youtube.com/watch?v=dCKPZUSOlr8)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 08 - Congrats](https://www.youtube.com/watch?v=8Mh5sMb_D2Q)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 02 - General Concept](https://www.youtube.com/watch?v=udl4oqr_ylM)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 01 - Environment Setup](https://www.youtube.com/watch?v=yqnUOdr0eVk)
- 2016.02 [THER] [Learn Burp Suite, the Nr. 1 Web Hacking Tool - 07 - Intruder and Comparer](https://www.youtube.com/watch?v=7OXe8THhmao)
- 2016.02 [gracefulsecurity] [Introduction to Burp Suite Pro](https://www.gracefulsecurity.com/introduction-to-burp-suite-pro/)
- 2016.02 [bishopfox] [Burp, Collaborate, and Listen: A Pentester Reviews the Latest Burp Suite Addition](https://www.bishopfox.com/blog/2016/02/burp-collaborate-listen-pentester-reviews-latest-burp-suite-addition/)
- 2016.02 [xxlegend] [如何让Burpsuite监听微信公众号](http://xxlegend.com/2016/02/01/如何让Burpsuite监听微信公众号/)
- 2016.02 [xxlegend] [Burpsuite 插件开发之RSA加解密](http://xxlegend.com/2016/02/01/Burpsuite插件开发之RSA加解密/)
- 2016.02 [xxlegend] [Burpsuite 插件开发之RSA加解密](http://xxlegend.com/2016/02/01/Burpsuite插件开发之RSA加解密/)
- 2016.02 [xxlegend] [如何让Burpsuite监听微信公众号](http://xxlegend.com/2016/02/01/如何让Burpsuite监听微信公众号/)
- 2016.01 [hack] [Burp Suite For Beginners](https://hack-ed.net/2016/01/09/burp-suite-for-beginners/)
- 2016.01 [freebuf] [Burpsuite插件开发之RSA加解密](http://www.freebuf.com/articles/security-management/92376.html)
- 2016.01 [blackhillsinfosec] [Pentesting ASP.NET Cookieless Sessions with Burp](https://www.blackhillsinfosec.com/pentesting-asp-net-cookieless-sessions-with-burp/)
- 2015.12 [BSidesCHS] [BSidesCHS 2015: Building Burp Extensions - Jason Gillam](https://www.youtube.com/watch?v=v7Yjdi9NvOY)
- 2015.12 [nsfocus] [Burpsuite插件开发之RSA加解密](http://blog.nsfocus.net/burpsuite-plugin-development-rsa-encryption-decryption/)
- 2015.12 [blackhillsinfosec] [Using Simple Burp Macros to Automate Testing](https://www.blackhillsinfosec.com/using-simple-burp-macros-to-automate-testing/)
- 2015.12 [toolswatch] [Sleepy Puppy Burp Extension for XSS v1.0](http://www.toolswatch.org/2015/12/sleepy-puppy-burp-extension-for-xss-v1-0/)
- 2015.12 [jerrygamblin] [Proxying BurpSuite through TOR](https://jerrygamblin.com/2015/12/18/proxying-burpsuite-through-tor/)
- 2015.12 [mediaservice] [Scanning for Java Deserialization Vulnerabilities in web applications with Burp Suite](https://techblog.mediaservice.net/2015/12/scanning-for-java-deserialization-vulnerabilities-in-web-applications-with-burp-suite/)
- 2015.12 [toolswatch] [[New Tool] SAML Raider v1.1.1 – SAML2 Burp Extension](http://www.toolswatch.org/2015/12/new-tool-saml-raider-v1-1-1-saml2-burp-extension/)
- 2015.12 [sans] [New Burp Feature - ClickBandit](https://isc.sans.edu/forums/diary/New+Burp+Feature+ClickBandit/20475/)
- 2015.12 [portswigger] [Burp Clickbandit: A JavaScript based clickjacking PoC generator | Blog](https://portswigger.net/blog/burp-clickbandit-a-javascript-based-clickjacking-poc-generator)
- 2015.12 [nabla] [Burp and iOS 9 App Transport Security](https://nabla-c0d3.github.io/blog/2015/12/01/burp-ios9-ats/)
- 2015.11 [gracefulsecurity] [Burp Suite vs CSRF Tokens: Round Two](https://www.gracefulsecurity.com/burp-suite-vs-csrf-tokens-round-two/)
- 2015.11 [gracefulsecurity] [Burp Suite vs CSRF Tokens Part 2: CSRFTEI for Remote Tokens](https://www.gracefulsecurity.com/burp-vs-csrf-tokens-part-2-code/)
- 2015.11 [gracefulsecurity] [Burp Suite vs CSRF Tokens](https://www.gracefulsecurity.com/burp-suite-vs-csrf-tokens/)
- 2015.11 [gracefulsecurity] [Burp Suite vs CSRF Tokens: CSRFTEI](https://www.gracefulsecurity.com/burp-suite-vs-csrf-tokens-csrftei/)
- 2015.11 [gracefulsecurity] [Burp Suite Extensions: Installing Jython and adding an Extension](https://www.gracefulsecurity.com/burp-suite-extensions-installing-jython-and-adding-an-extension/)
- 2015.11 [gracefulsecurity] [Burp Macros: Automatic Re-authentication](https://www.gracefulsecurity.com/burp-macros-re-authentication/)
- 2015.10 [g0tmi1k] [DVWA Brute Force (Low Level) - HTTP GET Form [Hydra, Patator, Burp]](http://blog.g0tmi1k.com/dvwa/bruteforce-low/)
- 2015.10 [parsiya] [Proxying Hipchat Part 2: So You Think You Can Use Burp?](https://parsiya.net/blog/2015-10-09-proxying-hipchat-part-2-so-you-think-you-can-use-burp/)
- 2015.10 [freebuf] [J2EEScan：J2EE安全扫描（Burp插件）](http://www.freebuf.com/sectool/80535.html)
- 2015.09 [freebuf] [渗透测试神器Burpsuite Pro v1.6.24（含下载）](http://www.freebuf.com/sectool/77272.html)
- 2015.09 [freebuf] [BurpSuite下一代渗透检测工具：BurpKit](http://www.freebuf.com/sectool/77436.html)
- 2015.08 [portswigger] [Burp Suite training courses | Blog](https://portswigger.net/blog/burp-suite-training-courses)
- 2015.08 [portswigger] [New release cycle for Burp Suite Free Edition | Blog](https://portswigger.net/blog/new-release-cycle-for-burp-suite-free-edition)
- 2015.08 [portcullis] [Burp Extension](https://labs.portcullis.co.uk/blog/burp-extension/)
- 2015.08 [freebuf] [本地文件包含漏洞检测工具 – Burp国产插件LFI scanner checks](http://www.freebuf.com/sectool/75118.html)
- 2015.07 [websecurify] [The Rebirth Of REBurp](https://blog.websecurify.com/2015/07/the-rebirth-of-reburp.html)
- 2015.07 [secist] [使用burp进行java反序列化攻击](http://www.secist.com/archives/309.html)
- 2015.07 [compass] [SAML Burp Extension](https://blog.compass-security.com/2015/07/saml-burp-extension/)
- 2015.07 [nvisium] [Intro to BurpSuite, Part VI: Burpsuite Sequencer](https://nvisium.com/blog/2015/07/09/intro-to-burpsuite-part-vi-burpsuite/)
- 2015.07 [] [小技巧：Burp Suite 插件库 BApp Store](http://www.91ri.org/13377.html)
- 2015.06 [gracefulsecurity] [Burp Suite Keyboard Shortcuts!](https://www.gracefulsecurity.com/burp-suite-keyboard-shortcuts/)
- 2015.06 [acunetix] [Pre-seeding a crawl using output from Fiddler, Burp, Selenium and HAR files](https://www.acunetix.com/blog/articles/pre-seeding-a-crawl-using-output-from-fiddler-burp-selenium-and-har-files/)
- 2015.06 [freebuf] [可绕过WAF的Burp Suite插件 – BypassWAF](http://www.freebuf.com/sectool/69988.html)
- 2015.05 [netspi] [Debugging Burp Extensions](https://blog.netspi.com/debugging-burp-extensions/)
- 2015.05 [idontplaydarts] [Detecting low entropy tokens with massive bloom filters in Burp](https://www.idontplaydarts.com/2015/05/low-entropy-tokens-massive-bloom-filters-burp-http/)
- 2015.05 [portswigger] [New Burp Suite testing methodologies | Blog](https://portswigger.net/blog/new-burp-suite-testing-methodologies)
- 2015.05 [freebuf] [渗透测试神器Burp Suite v1.6.17（含破解版下载）](http://www.freebuf.com/sectool/66521.html)
- 2015.05 [portswigger] [Burp Suite now reports blind XXE injection | Blog](https://portswigger.net/blog/burp-suite-now-reports-blind-xxe-injection)
- 2015.04 [toolswatch] [Burp Suite Professional v1.6.13 Released](http://www.toolswatch.org/2015/04/burp-suite-professional-v1-6-13-released/)
- 2015.04 [mediaservice] [Pentesting with Serialized Java Objects and Burp Suite](https://techblog.mediaservice.net/2015/04/pentesting-with-serialized-java-objects-and-burp-suite/)
- 2015.04 [portswigger] [Introducing Burp Collaborator | Blog](https://portswigger.net/blog/introducing-burp-collaborator)
- 2015.04 [freebuf] [渗透测试神器Burp Suite v1.6.12破解版下载](http://www.freebuf.com/sectool/63469.html)
- 2015.02 [sans] [BURP 1.6.10 Released](https://isc.sans.edu/forums/diary/BURP+1610+Released/19305/)
- 2015.01 [portswigger] [Burp Suite Support Center | Blog](https://portswigger.net/blog/burp-suite-support-center)
- 2015.01 [portswigger] [Burp Suite Pro price held for 2015 | Blog](https://portswigger.net/blog/burp-suite-pro-price-held-for-2015)
- 2014.12 [insinuator] [Getting 20k Inline-QR-Codes out of Burp](https://insinuator.net/2014/12/getting-20k-inline-qr-codes-out-of-burp/)
- 2014.11 [liftsecurity] [Static Analysis and Burp Suite](https://blog.liftsecurity.io/2014/11/18/static-analysis-and-burp-suite/)
- 2014.10 [buer] [Detecting Burp Suite – Part 2 of 3: Callback Exposure](https://buer.haus/2014/10/13/detecting-burp-suite-part-2-of-3-callback-exposure/)
- 2014.10 [portswigger] [Burp integrates with WebInspect | Blog](https://portswigger.net/blog/burp-integrates-with-webinspect)
- 2014.09 [freebuf] [渗透神器合体：在BurpSuite中集成Sqlmap](http://www.freebuf.com/sectool/45239.html)
- 2014.09 [compass] [BurpSentinel on Darknet](https://blog.compass-security.com/2014/09/burpsentinel-on-darknet/)
- 2014.08 [insinuator] [ERNW’s Top 9 Burp Plugins](https://insinuator.net/2014/08/ernws-top-9-burp-plugins/)
- 2014.08 [liftsecurity] [Burp Extender With Scala](https://blog.liftsecurity.io/2014/08/23/burp-extender-with-scala/)
- 2014.08 [nvisium] [Intro to BurpSuite V: Extracting Intrusions](https://nvisium.com/blog/2014/08/13/intro-to-burpsuite-v-extracting/)
- 2014.08 [appsecconsulting] [Running Stubborn Devices Through Burp Suite via OSX Mountain Lion and Above](https://appsecconsulting.com/blog/running-stubborn-devices-through-burp-suite-via-osx-mountain-lion-and-above)
- 2014.08 [nvisium] [iOS Assessments with Burp + iFunBox + SQLite](https://nvisium.com/blog/2014/08/06/ios-assessments-with-burp-ifunbox-sqlite/)
- 2014.08 [milo2012] [Extended functionality for Burp Plugin – Carbonator](https://milo2012.wordpress.com/2014/08/04/extended-functionality-for-burp-plugin-carbonator/)
- 2014.07 [portswigger] [Burp gets new JavaScript analysis capabilities | Blog](https://portswigger.net/blog/burp-gets-new-javascript-analysis-capabilities)
- 2014.07 [nvisium] [Intro to BurpSuite Part IV: Being Intrusive](https://nvisium.com/blog/2014/07/23/intro-to-burpsuite-part-iv-being/)
- 2014.07 [liftsecurity] [Introducing Burpbuddy](https://blog.liftsecurity.io/2014/07/15/introducing-burpbuddy/)
- 2014.07 [buer] [Detecting Burp Suite – Part 1 of 3: Info Leak](https://buer.haus/2014/07/13/detecting-burp-suite-part-1-of-3-info-leak/)
- 2014.07 [notsosecure] [Pentesting Web Service with anti CSRF token using BurpPro](https://www.notsosecure.com/pentesting-web-service-with-csrf-token-with-burp-pro/)
- 2014.06 [robert] [Howto install and use the Burp Suite as HTTPS Proxy on Ubuntu 14.04](https://robert.penz.name/856/howto-install-and-use-the-burp-suite-as-https-proxy-on-ubuntu-14-04/)
- 2014.06 [parsiya] [Piping SSL/TLS Traffic from SoapUI to Burp](https://parsiya.net/blog/2014-06-25-piping-ssl/tls-traffic-from-soapui-to-burp/)
- 2014.06 [sensepost] [Associating an identity with HTTP requests – a Burp extension](https://sensepost.com/blog/2014/associating-an-identity-with-http-requests-a-burp-extension/)
- 2014.05 [sans] [Assessing SOAP APIs with Burp](https://isc.sans.edu/forums/diary/Assessing+SOAP+APIs+with+Burp/18175/)
- 2014.05 [nvisium] [Intro to BurpSuite: Part III - It's all about Repetition!](https://nvisium.com/blog/2014/05/09/intro-to-burpsuite-part-iii-its-all/)
- 2014.04 [freebuf] [国产BurpSuite插件 Assassin V1.1发布](http://www.freebuf.com/sectool/32746.html)
- 2014.04 [freebuf] [国产BurpSuite 插件 Assassin V1.0发布](http://www.freebuf.com/sectool/32153.html)
- 2014.04 [toolswatch] [Burp Suite Professional v1.6 Released](http://www.toolswatch.org/2014/04/burp-suite-professional-v1-6-released/)
- 2014.04 [portswigger] [Burp Suite Free Edition v1.6 released | Blog](https://portswigger.net/blog/burp-suite-free-edition-v1-6-released)
- 2014.03 [freebuf] [知名渗透测试套件BurpSuite Pro v1.6 beta破解版公布](http://www.freebuf.com/sectool/29161.html)
- 2014.03 [nvisium] [Burp App Store](https://nvisium.com/blog/2014/03/14/burp-app-store/)
- 2014.02 [nvisium] [Intro to Burp Part II: Sighting in your Burp Scope](https://nvisium.com/blog/2014/02/21/intro-to-burp-part-ii-sighting-in-your/)
- 2014.02 [silentsignal] [Testing websites using ASP.NET Forms Authentication with Burp Suite](https://blog.silentsignal.eu/2014/02/20/testing-websites-using-asp-net-forms-auth-with-burp-suite/)
- 2014.02 [nvisium] [Using Burp Intruder to Test CSRF Protected Applications](https://nvisium.com/blog/2014/02/14/using-burp-intruder-to-test-csrf/)
- 2014.02 [trustwave] [“Reversing” Non-Proxy Aware HTTPS Thick Clients w/ Burp](https://www.trustwave.com/Resources/SpiderLabs-Blog/%E2%80%9CReversing%E2%80%9D-Non-Proxy-Aware-HTTPS-Thick-Clients-w/-Burp/)
- 2014.02 [nvisium] [Challenges of Mobile API Signature Forgery with Burp Intruder](https://nvisium.com/blog/2014/02/07/challenges-of-mobile-api-signature/)
- 2014.02 [portswigger] [Burp Suite Pro shines in new survey | Blog](https://portswigger.net/blog/burp-suite-pro-shines-in-new-survey)
- 2014.01 [nvisium] [Accurate XSS Detection with BurpSuite and PhantomJS](https://nvisium.com/blog/2014/01/31/accurate-xss-detection-with-burpsuite/)
- 2014.01 [nvisium] [Android Assessments with GenyMotion + Burp](https://nvisium.com/blog/2014/01/24/android-assessments-with-genymotion-burp/)
- 2014.01 [sethsec] [Writing and Debugging BurpSuite Extensions in Python](https://sethsec.blogspot.com/2014/01/writing-and-debugging-burpsuite.html)
- 2014.01 [sethsec] [Re-launch - A focus on Web Application Pen Testing, Burp Extensions, etc](https://sethsec.blogspot.com/2014/01/re-launch-focus-on-web-application-pen.html)
- 2014.01 [nvisium] [Intro To Burp Suite Part I: Setting Up BurpSuite with Firefox and FoxyProxy](https://nvisium.com/blog/2014/01/10/setting-up-burpsuite-with-firefox-and/)
- 2014.01 [portswigger] [Burp Suite Pro price held for 2014 | Blog](https://portswigger.net/blog/burp-suite-pro-price-held-for-2014)
- 2013.12 [freebuf] [Java编写代理服务器(Burp拦截Demo)一](http://www.freebuf.com/articles/web/21832.html)
- 2013.12 [freebuf] [burpsuite_pro_v1.5.20破解版下载](http://www.freebuf.com/sectool/21446.html)
- 2013.12 [appsecconsulting] [So You Want to Build a Burp Plugin?](https://appsecconsulting.com/blog/so-you-want-to-build-a-burp-plugin)
- 2013.12 [directdefense] [Multiple NONCE (one-time token) Value Tracking with Burp Extender](https://www.directdefense.com/multiple-nonce-one-time-token-value-tracking-burp-extender/)
- 2013.11 [freebuf] [burpsuite_pro_v1.5.18 破解版](http://www.freebuf.com/sectool/18483.html)
- 2013.11 [freebuf] [burpsuite_pro_v1.5.11 破解版](http://www.freebuf.com/sectool/16340.html)
- 2013.10 [debasish] [Fuzzing Facebook for $$$ using Burpy](http://www.debasish.in/2013/10/fuzzing-facebook-for-using-burpy.html)
- 2013.10 [agarri] [Exploiting WPAD with Burp Suite and the "HTTP
Injector" extension](http://www.agarri.fr/blog/../kom/archives/2013/10/22/exploiting_wpad_with_burp_suite_and_the_http_injector_extension/index.html)
- 2013.10 [agarri] [Exploiting WPAD with Burp Suite and the "HTTP
Injector" extension](https://www.agarri.fr/blog/archives/2013/10/22/exploiting_wpad_with_burp_suite_and_the_http_injector_extension/index.html)
- 2013.10 [portswigger] [Burp through the ages | Blog](https://portswigger.net/blog/burp-through-the-ages)
- 2013.09 [portswigger] [SSL pass through in Burp | Blog](https://portswigger.net/blog/ssl-pass-through-in-burp)
- 2013.08 [freebuf] [BurpSuite权限提升漏洞检测插件——The Burp SessionAuth](http://www.freebuf.com/sectool/11905.html)
- 2013.08 [toolswatch] [The Burp SessionAuth – Extension for Detection of Possible Privilege escalation vulnerabilities](http://www.toolswatch.org/2013/08/the-burp-sessionauth-extension-for-detection-of-possible-privilege-escalation-vulnerabilities/)
- 2013.07 [cyberis] [Testing .NET MVC for JSON Request XSS - POST2JSON Burp Extension](https://www.cyberis.co.uk/2013/07/testing-net-mvc-for-json-request-xss.html)
- 2013.06 [portswigger] [Burp Suite confirmed as best value web security scanner | Blog](https://portswigger.net/blog/burp-suite-confirmed-as-best-value-web-security-scanner)
- 2013.06 [raz0r] [Radamsa Fuzzer Extension for Burp Suite](https://raz0r.name/releases/burp-radamsa/)
- 2013.06 [sec] [How to rapidly build a Burp session handling extension using JavaScript](https://sec-consult.com/en/blog/2013/06/how-to-rapidly-build-a-burp-session-handling-extension-using-javascript/)
- 2013.06 [freebuf] [angelc0de原创burpsuite系列培训教程（下载）](http://www.freebuf.com/video/10591.html)
- 2013.06 [freebuf] [BurpSuite系列使用视频教程（下载）](http://www.freebuf.com/video/10468.html)
- 2013.05 [] [Burp Suite处理“不支持代理”的客户端](http://www.91ri.org/5976.html)
- 2013.05 [] [Burp通过注射点dump数据库](http://www.91ri.org/5872.html)
- 2013.05 [trustwave] [Introducing the Burp Notes Extension](https://www.trustwave.com/Resources/SpiderLabs-Blog/Introducing-the-Burp-Notes-Extension/)
- 2013.04 [pediy] [[原创]利用sqlmap和burpsuite绕过csrf token进行SQL注入](https://bbs.pediy.com/thread-168302.htm)
- 2013.03 [portswigger] [Burp Suite is on a feature roll! | Blog](https://portswigger.net/blog/burp-suite-is-on-a-feature-roll)
- 2013.03 [security] [Penetration Test pWnOS v2.0 with BurpSuite](http://security-is-just-an-illusion.blogspot.com/2013/03/penetration-test-pwnos-v20-with.html)
- 2013.03 [freebuf] [使用Burp攻击Web Services](http://www.freebuf.com/articles/web/7592.html)
- 2013.03 [netspi] [Hacking Web Services with Burp](https://blog.netspi.com/hacking-web-services-with-burp/)
- 2013.03 [] [Burpsuite_pro_v1.5.01多平台破解版](http://www.91ri.org/5378.html)
- 2013.02 [freebuf] [Burpsuite教程与技巧之HTTP brute暴力破解](http://www.freebuf.com/articles/web/7457.html)
- 2013.02 [freebuf] [Burpsuite_pro_v1.5.01多平台破解版](http://www.freebuf.com/sectool/7464.html)
- 2013.02 [freebuf] [AuthTrans(原创工具)+BurpSuite的暴力美学-破解Http Basic认证](http://www.freebuf.com/articles/web/7450.html)
- 2013.02 [pentestlab] [SQL Injection Authentication Bypass With Burp](https://pentestlab.blog/2013/02/25/sql-injection-authentication-bypass-with-burp/)
- 2013.01 [freebuf] [[下载]burpsuite_pro_v1.5_crack更新](http://www.freebuf.com/sectool/6917.html)
- 2013.01 [rapid7] [Video Tutorial: Introduction to Burp-Suite 1.5 Web Pen Testing Proxy](https://blog.rapid7.com/2013/01/15/video-tutorial-introduction-to-burp-suite-15-web-pen-testing-proxy/)
- 2013.01 [websecurify] [Loading Burp Files Inside Websecurify Suite Video](https://blog.websecurify.com/2013/01/loading-burp-files-inside-websecurify-suite-video.html)
- 2013.01 [websecurify] [Reading Burp Files From Websecurify Suite](https://blog.websecurify.com/2013/01/reading-burp-files-from-websecurify-suite.html)
- 2013.01 [netspi] [Tool release: AMF Deserialize Burp plugin](https://blog.netspi.com/tool-release-amf-deserialize-burp-plugin/)
- 2012.12 [pentestlab] [Local File Inclusion Exploitation With Burp](https://pentestlab.blog/2012/12/26/local-file-inclusion-exploitation-with-burp/)
- 2012.12 [freebuf] [iPhone上使用Burp Suite捕捉HTTPS通信包方法](http://www.freebuf.com/articles/web/6577.html)
- 2012.12 [portswigger] [Sample Burp Suite extension: Intruder payloads | Blog](https://portswigger.net/blog/sample-burp-suite-extension-intruder-payloads)
- 2012.12 [pentestlab] [Brute Force Attack With Burp](https://pentestlab.blog/2012/12/21/brute-force-attack-with-burp/)
- 2012.12 [portswigger] [Sample Burp Suite extension: custom scanner checks | Blog](https://portswigger.net/blog/sample-burp-suite-extension-custom-scanner-checks)
- 2012.12 [portswigger] [Sample Burp Suite extension: custom scan insertion points | Blog](https://portswigger.net/blog/sample-burp-suite-extension-custom-scan-insertion-points)
- 2012.12 [portswigger] [Sample Burp Suite extension: custom editor tab | Blog](https://portswigger.net/blog/sample-burp-suite-extension-custom-editor-tab)
- 2012.12 [portswigger] [Sample Burp Suite extension: custom logger | Blog](https://portswigger.net/blog/sample-burp-suite-extension-custom-logger)
- 2012.12 [portswigger] [Sample Burp Suite extension: traffic redirector | Blog](https://portswigger.net/blog/sample-burp-suite-extension-traffic-redirector)
- 2012.12 [portswigger] [Sample Burp Suite extension: event listeners | Blog](https://portswigger.net/blog/sample-burp-suite-extension-event-listeners)
- 2012.12 [portswigger] [Sample Burp Suite extension: Hello World | Blog](https://portswigger.net/blog/sample-burp-suite-extension-hello-world)
- 2012.12 [portswigger] [Writing your first Burp Suite extension | Blog](https://portswigger.net/blog/writing-your-first-burp-suite-extension)
- 2012.12 [portswigger] [New Burp Suite Extensibility | Blog](https://portswigger.net/blog/new-burp-suite-extensibility)
- 2012.12 [freebuf] [Burpsuite sqlmap插件](http://www.freebuf.com/sectool/6426.html)
- 2012.11 [portswigger] [New Burp Suite Extensibility - preview | Blog](https://portswigger.net/blog/new-burp-suite-extensibility-preview)
- 2012.11 [freebuf] [渗透测试神器Burp弹药扩充-fuzzdb](http://www.freebuf.com/sectool/6181.html)
- 2012.11 [freebuf] [Burp Suite—BLIND SQL INJECTION](http://www.freebuf.com/articles/web/6154.html)
- 2012.11 [perezbox] [Spoofing an Admin’s Cookies Using Burp](https://perezbox.com/2012/11/pracapp-spoofing-an-admins-cookies-using-burp-suite/)
- 2012.11 [freebuf] [Burp Suite免费版本（Free Edition）v1.5发布](http://www.freebuf.com/sectool/6090.html)
- 2012.10 [portswigger] [Burp Suite Free Edition v1.5 released | Blog](https://portswigger.net/blog/burp-suite-free-edition-v1-5-released)
- 2012.10 [] [利用burpsuite获得免费空间](http://www.91ri.org/4522.html)
- 2012.10 [freebuf] [Burp Suite PayLoad下载](http://www.freebuf.com/sectool/6017.html)
- 2012.10 [] [使用BurpSuite来进行sql注入](http://www.91ri.org/4415.html)
- 2012.10 [netspi] [Pentesting Java Thick Applications with Burp JDSer](https://blog.netspi.com/pentesting-java-thick-applications-with-burp-jdser/)
- 2012.10 [toolswatch] [Burp Suite v1.5rc2 released](http://www.toolswatch.org/2012/10/burp-suite-v1-5rc2-released/)
- 2012.09 [trustwave] [Adding Anti-CSRF Support to Burp Suite Intruder](https://www.trustwave.com/Resources/SpiderLabs-Blog/Adding-Anti-CSRF-Support-to-Burp-Suite-Intruder/)
- 2012.09 [] [用Burp_suite快速处理上传截断](http://www.91ri.org/4091.html)
- 2012.09 [portswigger] [All new Burp help | Blog](https://portswigger.net/blog/all-new-burp-help)
- 2012.09 [] [使用burp suite探测Web目录](http://www.91ri.org/4064.html)
- 2012.09 [freebuf] [BurpSuite教程与技巧之SQL Injection](http://www.freebuf.com/articles/5560.html)
- 2012.08 [freebuf] [Burp Suite V1.4.12发布: 新增破解Android SSL功能](http://www.freebuf.com/sectool/5347.html)
- 2012.08 [toolswatch] [Burp Suite v1.4.12 in the wild with the support of Android SSL Analysis](http://www.toolswatch.org/2012/08/burp-suite-v1-4-12-in-the-wild-with-the-support-of-android-ssl-analysis/)
- 2012.07 [raz0r] [Прокачиваем Burp Suite](https://raz0r.name/articles/extending-burp-suite/)
- 2012.07 [console] [Setting up a Burp development environment](http://console-cowboys.blogspot.com/2012/07/setting-up-burp-development-environment.html)
- 2012.06 [freebuf] [burpsuite_pro_v1.4.07破解版](http://www.freebuf.com/sectool/4771.html)
- 2012.06 [freebuf] [burpsuite v1.4.10发布](http://www.freebuf.com/sectool/4768.html)
- 2012.06 [toolswatch] [Burp Suite Professional v1.4.08 Released](http://www.toolswatch.org/2012/06/burp-suite-professional-v1-4-08-released/)
- 2012.06 [toolswatch] [Burp Suite Professional v1.4.09 Released](http://www.toolswatch.org/2012/06/burp-suite-professional-v1-4-09-released/)
- 2012.06 [toolswatch] [Burp Suite Professional v1.4.10 Released](http://www.toolswatch.org/2012/06/burp-suite-professional-v1-4-10-released/)
- 2012.06 [milo2012] [Automating SQL Injection with Burp, Sqlmap and GDS Burp API](https://milo2012.wordpress.com/2012/06/26/automating-sql-injection-with-burp-sqlmap-and-gds-burp-api/)
- 2012.06 [freebuf] [[连载]Burp Suite详细使用教程-Intruder模块详解(3)](http://www.freebuf.com/articles/4184.html)
- 2012.06 [portswigger] [Burp gets a makeover | Blog](https://portswigger.net/blog/burp-gets-a-makeover)
- 2012.06 [freebuf] [[连载]Burp Suite详细使用教程-Intruder模块详解(2)](http://www.freebuf.com/sectool/3693.html)
- 2012.06 [websec] [Using Burp to exploit a Blind SQL Injection](https://websec.ca/blog/view/using-burp-to-exploit-blind-sql-injection)
- 2012.06 [freebuf] [[技巧]Burp Intruder中的Timing选项的使用](http://www.freebuf.com/sectool/3369.html)
- 2012.06 [secproject] [Burp Suite Beautifier Extension](https://soroush.secproject.com/blog/2012/06/burp-suite-beautifier-extension/)
- 2012.05 [freebuf] [[技巧]使用Burpsuite辅助Sqlmap进行POST注入测试](http://www.freebuf.com/sectool/2311.html)
- 2012.05 [freebuf] [Burp Suite详细使用教程-Intruder模块详解](http://www.freebuf.com/sectool/2079.html)
- 2012.05 [freebuf] [Burp Suite python扩展 – Burpy](http://www.freebuf.com/sectool/2170.html)
- 2012.05 [portswigger] [Burp Suite user forum | Blog](https://portswigger.net/blog/burp-suite-user-forum)
- 2012.05 [freebuf] [Burpsuite系列视频教程不加密版第一部分公布下载](http://www.freebuf.com/articles/1467.html)
- 2012.05 [freebuf] [burpsuite_pro_v1.4.01破解版](http://www.freebuf.com/sectool/1266.html)
- 2012.04 [firebitsbr] [Pentest tool: Gason: A plugin to run sqlmap into burpsuite.](https://firebitsbr.wordpress.com/2012/04/22/pentest-tool-gason-a-plugin-to-run-sqlmap-into-burpsuite/)
- 2012.04 [toolswatch] [Burp Suite Professional v1.4.07 Released](http://www.toolswatch.org/2012/04/burp-suite-professional-v1-4-07-released/)
- 2012.03 [toolswatch] [Burp Suite Professional v1.4.06 Released](http://www.toolswatch.org/2012/03/burp-suite-professional-v1-4-06-released/)
- 2012.01 [idontplaydarts] [Extending Burp Suite to solve reCAPTCHA](https://www.idontplaydarts.com/2012/01/extending-burp-suite-to-solve-recaptcha/)
- 2011.12 [milo2012] [OWASP Ajax Crawling Tool (Good Companion Tool to Burpsuite)](https://milo2012.wordpress.com/2011/12/26/owasp-ajax-crawling-tool-good-companion-tool-to-burpsuite/)
- 2011.12 [insinuator] [Use Python for Burp plugins with pyBurp](https://insinuator.net/2011/12/use-python-for-burp-plugins-with-pyburp/)
- 2011.12 [toolswatch] [Burp Suite Professional v1.4.05 released](http://www.toolswatch.org/2011/12/burp-suite-professional-v1-4-05-released/)
- 2011.11 [portswigger] [Burp is voted #1 web scanner | Blog](https://portswigger.net/blog/burp-is-voted-1-web-scanner)
- 2011.11 [digi] [Burp Intruder Attack Types](https://digi.ninja/blog/burp_intruder_types.php)
- 2011.10 [toolswatch] [Burp Suite Professional v1.4.02 released](http://www.toolswatch.org/2011/10/burp-suite-professional-v1-4-02-released/)
- 2011.10 [portswigger] [Breaking encrypted data using Burp | Blog](https://portswigger.net/blog/breaking-encrypted-data-using-burp)
- 2011.06 [cyberis] ['Invisible Intercept' Function of Burp](https://www.cyberis.co.uk/2011/06/intercept-function-of-burp.html)
- 2011.06 [console] [Burp Intruder Time fields](http://console-cowboys.blogspot.com/2011/06/burp-intruder-time-fields.html)
- 2011.06 [toolswatch] [Burp Suite Free Edition v1.4 released (Support of IPv6)](http://www.toolswatch.org/2011/06/burp-suite-free-edition-v1-4-released-support-of-ipv6/)
- 2011.06 [portswigger] [Burp Suite Free Edition v1.4 released | Blog](https://portswigger.net/blog/burp-suite-free-edition-v1-4-released)
- 2011.05 [console] [Web Hacking  Video Series #1 Automating SQLi with Burp Extractor](http://console-cowboys.blogspot.com/2011/05/web-hacking-video-series-1-automating.html)
- 2011.04 [depthsecurity] [Blind SQL Injection & BurpSuite - Like a Boss](https://depthsecurity.com/blog/blind-sql-injection-burpsuite-like-a-boss)
- 2011.03 [portswigger] [Burp v1.4 beta now available | Blog](https://portswigger.net/blog/burp-v1-4-beta-now-available)
- 2011.03 [portswigger] [Burp v1.4 preview - Session handling: putting it all together | Blog](https://portswigger.net/blog/burp-v1-4-preview-session-handling-putting-it-all-together)
- 2011.03 [portswigger] [Burp v1.4 preview - Macros | Blog](https://portswigger.net/blog/burp-v1-4-preview-macros)
- 2011.03 [portswigger] [Burp v1.4 preview - Session handling | Blog](https://portswigger.net/blog/burp-v1-4-preview-session-handling)
- 2011.03 [toolswatch] [Burp v1.4 preview – Comparing site maps](http://www.toolswatch.org/2011/03/burp-v1-4-preview-comparing-site-maps/)
- 2011.03 [portswigger] [Burp v1.4 preview - Testing access controls using your browser | Blog](https://portswigger.net/blog/burp-v1-4-preview-testing-access-controls-using-your-browser)
- 2011.03 [portswigger] [Burp v1.4 preview - Comparing site maps | Blog](https://portswigger.net/blog/burp-v1-4-preview-comparing-site-maps)
- 2010.09 [netspi] [Fuzzing Parameters in CSRF Resistant Applications with Burp Proxy](https://blog.netspi.com/fuzzing-parameters-in-csrf-resistant-applications-with-burp-proxy/)
- 2010.08 [gdssecurity] [Constricting the Web: The GDS Burp API](https://blog.gdssecurity.com/labs/2010/8/10/constricting-the-web-the-gds-burp-api.html)
- 2010.01 [portswigger] [Burp Suite v1.3 released | Blog](https://portswigger.net/blog/burp-suite-v1-3-released)
- 2009.11 [portswigger] [Burp Suite v1.3 preview | Blog](https://portswigger.net/blog/burp-suite-v1-3-preview)
- 2009.11 [gdssecurity] [WCF Binary Soap Plug-In for Burp](https://blog.gdssecurity.com/labs/2009/11/19/wcf-binary-soap-plug-in-for-burp.html)
- 2009.11 [portswigger] [GIAC paper on Burp Intruder | Blog](https://portswigger.net/blog/giac-paper-on-burp-intruder)
- 2009.04 [portswigger] [Burp problems after Windows update | Blog](https://portswigger.net/blog/burp-problems-after-windows-update)
- 2009.04 [portswigger] [Using Burp Extender | Blog](https://portswigger.net/blog/using-burp-extender)
- 2008.12 [portswigger] [Burp Suite v1.2 released | Blog](https://portswigger.net/blog/burp-suite-v1-2-released)
- 2008.11 [portswigger] [[MoBP] Burp Extender extended | Blog](https://portswigger.net/blog/mobp-burp-extender-extended)
- 2008.11 [raz0r] [Эффективный и быстрый пентестинг веб-приложений с Burp Suite](https://raz0r.name/obzory/effektivnyj-i-bystryj-pentesting-veb-prilozhenij-s-burp-suite/)
- 2008.11 [portswigger] [[MoBP] The all new Burp Spider | Blog](https://portswigger.net/blog/mobp-the-all-new-burp-spider)
- 2008.11 [portswigger] [The Month of Burp Pr0n | Blog](https://portswigger.net/blog/the-month-of-burp-pr0n)
- 2008.05 [portswigger] [Burp Sequencer 101 | Blog](https://portswigger.net/blog/burp-sequencer-101)
- 2008.02 [gdssecurity] [A "Deflate" Burp Plug-In](https://blog.gdssecurity.com/labs/2008/2/19/a-deflate-burp-plug-in.html)
- 2007.12 [portswigger] [Burp Suite v1.1 released | Blog](https://portswigger.net/blog/burp-suite-v1-1-released)
- 2007.11 [gdssecurity] [Beta version of the new Burp Suite released](https://blog.gdssecurity.com/labs/2007/11/27/beta-version-of-the-new-burp-suite-released.html)
- 2007.10 [portswigger] [Introducing Burp Sequencer | Blog](https://portswigger.net/blog/introducing-burp-sequencer)
- 2007.09 [portswigger] [Burp Suite feature requests - thank you | Blog](https://portswigger.net/blog/burp-suite-feature-requests-thank-you)


# 贡献
内容为系统自动导出, 有任何问题请提issue