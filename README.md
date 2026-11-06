# LuminaVPN

macOS 与 Windows 的白名单网络工程预览版本，提供 CLI 和桌面界面。CLI 与本机配置目录暂沿用 `netlaunch` / `NetLaunch` 名称。运行包自带规则核心、OpenConnect 及所需运行组件，使用时不需要安装 Go、Python、Node 或 Homebrew。

本版为工程预览：Mac 提供原生网络生命周期；Windows 不带构建标签的 CLI 只提供离线维护，`windows_home` 和 `windows_validation` 保留有限时长的 CLI 生命周期。新的 Windows 桌面包使用 `windows_client` 后台服务，实验包另外带 `windows_client_validation`。用 `version --json` 确认程序模式；Windows 客户端的真实安装、网络接管与恢复仍需在目标机器验证，编译和单元测试不能替代这些验证。使用前可用 `config validate`、`plan`、`doctor` 检查配置和环境。

## 桌面工程预览

`desktop/` 提供 Electron、React 和 TypeScript 客户端，采用 Jade Workspace 界面。Windows 客户端接入初始化、订阅同步、节点导入与选择、规则编辑、公司认证、独立通道开关、停止与恢复和诊断。界面读取后台的实时状态；服务不可达或证据过期时显示未知，不把保存的状态当作网络正常的证明。

Windows 安装器以管理员权限安装固定目录的后台服务，界面以普通用户运行，启动界面不会自动连接。公司与个人通道可分别开启；日用连接持续到手动停止、故障恢复或系统退出，实验连接有不可续期的硬截止，最长 45 分钟。关闭窗口进入托盘；明确退出会先停止并确认恢复。界面崩溃时后台保留连接，重新打开后接回；后台自身故障由独立恢复服务处理。密码和动态码不保存，短期公司会话使用当前用户的 DPAPI 加密，最多按原创建时间复用两小时。

Windows 后台只管理已登记的配置目录，首版安装登记当前用户的默认目录。选择未登记目录会保留原偏好和连接；旧偏好指向未登记目录时，可显式恢复默认目录，接回服务确认的运行。切换其它已登记目录前须停止并确认恢复。诊断页可显示应用之外的独立恢复入口，显示入口不会执行恢复。Mac 和 Windows 离线构建保留只读桌面能力，配置、连接和认证继续使用原 CLI；配置目录不存在时不会自动创建。

开发需要 Node.js 22.12+ 与 Go 1.26+；运行打包应用不需要安装开发工具。在 `desktop/` 执行：

```sh
npm ci
npm run dev
npm run package:mac
```

Go 不在 PATH 时，通过 `NETLAUNCH_GO` 指定构建工具。构建只读取固定 runtime；Windows 客户端须在 Windows x64 原生构建，以 `LUMINA_BUILD_RUNTIME` 指向符合 Windows 清单的 runtime，在 `desktop/` 执行 `npm run package:win` 或 `npm run package:win:validation`。输出位于已忽略的 `.local/windows-client-packages/`。两个模式都固定为全机安装，打包时校验三个 Go 程序、运行组件、后台安装接口与包内字节；当前为未签名开发包。本机安装预检未通过时，完整有效的接口观测仍可用于构建，但会明确告警，并在包外保存 `build-host-readiness.json`；构建成功不表示本机可安装。实际安装器会重新执行原生预检，失败时仍在续办和旧卸载之前退出。这些变量仅用于构建，发货应用不接受执行路径或页面 URL 覆盖。Windows 使用的规则核心补丁和重建输入见 `scripts/patches/`。

`npm run test:electron` 使用虚构配置检查只读桌面行为，并在本机实包存在时验证打包资源和窗口崩溃恢复。Windows 默认检查 `win-unpacked/LuminaVPN.exe`；验证已安装程序时，可将 `LUMINA_TEST_WINDOWS_EXE` 设为该程序的绝对路径。测试仅为新建的配置对象设置私有权限，不修改已有配置或系统网络。

Mac `.app` 输出到已忽略的 `.local/desktop-packages/mac-arm64/`。使用 `scripts/check-desktop-package.py APP_PATH` 检查 ASAR 内容、运行组件摘要和恢复资源。`npm run sign:preview:mac` 验证运行组件签名并对 Electron 包做本地 ad hoc 签名；不会改变已校验的 runtime 字节，也不提供正式发布签名、公证或系统信任保证。当前关闭窗口隐藏到菜单栏；退出界面保留由 CLI 建立的网络运行。

## 网络规则

- 公司精确域名与明确 IPv4 网段经公司 VPN。公司 DNS 也经公司 VPN。
- 个人流量经订阅或本地文件导入的代理节点。可选择导入受支持的个人分流规则；订阅中的 DNS、TUN、接口和链式代理设置不继承。
- 其他目标从当前物理网卡直连。
- 公司目标在公司通道关闭、未认证或失效时保持阻断。Mac 与旧 CLI 模式的个人通道从 REJECT 开始，检查通过后开放；Windows 客户端在个人通道手动关闭，或所有可用候选的独立健康检查均明确失败时允许直连，单个网站失败、结果缺失和检查取消不会触发直连。
- `gateway.corp.example.com` 在示例的公司白名单中，覆盖其 `8443` 端口。白名单不依赖 Wi-Fi 或热点类型。

公司授权和固定个人目标允许精确域名及 IPv4 `/24`–`/32` 网段；额外个人规则支持精确域名、域名后缀及上述窄网段。公司后缀授权和 IPv6 白名单尚不支持。Windows 家用构建已有网络接管实现；每次新版本仍需按变更范围验收。关闭核心 IPv6 并不代表关闭系统 IPv6；应用自带解析或缓存 IP 也可能无法命中域名规则。本版不承诺核心退出后的系统级永久阻断。

Windows 客户端以共享基础规则配合手动选择的办公或家庭覆盖；覆盖只调整个人与直连目标，公司名单始终优先且必须经公司 VPN。名单之外默认直连，不自动扩大公司保护范围。首版系统接管处理 IPv4，并以独立 WFP 规则阻断非回环 IPv6；停止接管并恢复系统网络后，这些分流与 IPv6 保护会一并撤销。

## 首次配置

运行包中提供同名的 Mac `.command` 和 Windows `.cmd` 入口：初始化、公司认证、同步订阅、检查配置、检查环境、启动、状态、停止与恢复、版本信息、诊断导出。初始化入口不带参数时只创建示例，仍需填写本机私有设置；也可从终端传入 `--file`。入口使用程序旁的 runtime 和默认 profile，不负责停止或恢复其他 VPN/代理客户端。下列命令以 Mac 写法展示，Windows 对应使用 `netlaunch.exe`。

外部用户需要准备：获准使用的公司 VPN 入口及其 IPv4、公司 DNS 与资源清单、支持的个人代理订阅（或节点文件），以及三个出口的 HTTPS 健康检查地址。公司账号和动态码只在本机认证时输入。普通个人订阅不能推断公司白名单或公司 VPN 配置。

推荐将 `examples/bootstrap.json` 复制到仓库外，改成自己的私密配置：

1. `policy` 填公司 VPN、DNS、公司目标与本地固定目标。示例中的 `example.com`、`192.0.2.1` 和 `192.0.2.53` 均需替换。健康检查 URL 必须属于对应固定目标。
2. `subscriptions.nodes` 填自己的 HTTPS 订阅 URL，或使用 `file` 指向本地 YAML/JSON；二者只选一个。相对文件路径以随身配置所在目录为基准。含 token 的 URL 也属于凭据，不能提交。
3. 订阅含规则时可设 `use_rules: true`，将订阅的代理组名称在 `groups` 中映射为 `personal`、`direct` 或 `reject`。所有映射到 `personal` 的规则共用本机选择的节点池；不复制原订阅的多组选择、链式代理或地区选择逻辑。

```sh
./netlaunch init --file '/absolute/path/to/bootstrap.private.json'
./netlaunch sync
./netlaunch plan
./netlaunch doctor
./netlaunch check-runtime
```

`init` 只创建私有本地配置，不下载订阅、不切换网络，已有配置不会覆盖。Mac 默认目录是 `~/Library/Application Support/NetLaunch/`；可在每条命令使用 `--profile DIR` 指定独立目录。随身配置本身也应限制为仅自己可读。它包含公司设置、规则来源和订阅入口；下载的节点密钥写入私有缓存，公司密码与 VPN 会话不包含在随身配置中。

`sync` 获取并校验全部显式来源，然后原子替换一份私有缓存，包含来源原文、内容摘要、解析版本和节点/规则结果；任一来源不可用或校验失败则保留旧缓存。来源原文也可能包含凭据，不可分享整个缓存。普通 `up` 按 `interval_minutes`（默认 60 分钟）检查是否需要刷新；下载失败时，只有旧来源内容能通过当前策略校验才会复用。间隔控制启动时刷新，本版没有后台定时刷新；运行时执行 `sync` 也只在下次启动生效。`plan` 不联网，只读取缓存；输出含公司策略和内部地址，不应直接公开。

修改本地白名单或 `personal_rules` 不再要求重新下载订阅：程序会用已缓存的内容重新验证规则、节点和入口冲突。修改格式、组映射或 `use_rules` 会在本地重新解析；改变订阅 URL（包括 token）或文件路径且没有对应缓存时仍需 `sync`。仅修改刷新间隔不会改变解析结果。旧版 v1 缓存仍可供原配置使用，但需成功执行一次 `sync` 升级为 v2，才能离线修改策略；旧程序不能读取新缓存。

规则优先级依次为：公司固定目标 → 本地固定个人目标和直连健康检查目标 → `policy.personal_rules` 本地覆盖 → 订阅规则 → 其余直连。同一层按文件顺序取首次命中。订阅不能增加公司授权，也不能覆盖前面的固定目标。DNS 分流保持同样的域名优先级。

节点文件支持含 `proxies` 数组的 Clash/Mihomo YAML 或 JSON；协议支持 VLESS、Hysteria2，入口可使用 IPv4 或精确域名。不支持的协议、无效条目和关闭证书验证的节点会计数并跳过。URI 列表与 Base64 节点订阅尚不支持。

规则支持 `rules` 或 `payload` 数组中的 `DOMAIN`、`DOMAIN-SUFFIX`、IPv4 `/24`–`/32` `IP-CIDR`。额外来源可在 `subscriptions.rules` 中配置 `url` 或 `file`，`format` 支持 `classical`、`domain`（`+.` 表示后缀）和 `ipcidr`。默认组名映射为 PROXY/PERSONAL → personal、DIRECT → direct、REJECT → reject；其他组名需要显式映射。不支持的规则会计数并跳过，整份规则源没有可用规则时更新失败。GEOSITE、GEOIP、MATCH、进程规则、组合规则、IPv6 和宽网段尚不导入；因此导入结果不等同于原订阅全部行为。不会自动追踪 `rule-providers` / `proxy-providers` 链接，额外来源需明确填写。

`sync` 按原因汇总跳过的条目，例如不支持的规则类型、未映射的组和不合法的授权范围。缓存保留来源编号与原始条目位置，不在摘要中输出订阅地址或原文。需要完整导入某个规则源时，在该 source 上设置 `strict_rules: true`；出现任何规则跳过便拒绝更新，保留旧缓存。节点源只有启用 `use_rules` 时才应用此项规则检查。

HTTPS 下载正常校验证书，不跟随重定向，单源限制 4 MiB；订阅必须在当前网络下可获取。首次导入时如尚无可用代理，可先导出本地节点文件启动。此流程不会调整系统代理以下载订阅。

也可以保留纯离线方式：`init` 创建示例策略，或 `init --file policy.private.json` 导入已写好的策略；再运行 `import --file subscription.yaml`。`import` 只导入节点，不导入规则。已配置订阅来源的 profile 使用 `sync`，不能混用 `import`。

节点测速只评价路径并用于排序（HTTP 200–599 表示收到最终响应）；选中节点还须通过本地代理入口完成配置中的个人 HTTPS 检查。检查失败时个人通道先回到 REJECT；明确的 TCP/TLS/响应传输故障会使节点进入冷却。服务状态不符合预期、核心控制接口故障、取消或未测到结果不作为节点故障累计。关闭的个人入口保留导致关闭的诊断，避免把自身 REJECT 造成的连接失败误报成新故障。三个通道的系统 TUN 检查仍全部通过后才显示 `ready`，不会自动改投其他出口。

探针可显式设置 `purpose: "path"` 或 `"service"`：path 验证连接、TLS 和最终 HTTP 响应（系统检查还核对 TUN 出口），允许 403、405、503 等响应；service 还要求返回符合预期的状态，默认 200–399，可用 `expected_status: [204, 401]` 指定最多 32 个不重复的 200–599 状态码。HEAD 请求不跟随跳转，不检查业务登录或响应正文。省略 purpose 时，公司/直连按 path、个人按 service；因此现有个人入口要求仍保留，并一致应用于该探针的系统检查。新增字段需使用本次新版，两端旧版严格配置解析器不会接受。

公司绑定检查与系统路径检查各有最多 6 秒的探测批次预算，最多并发 4 个目标；未完成项为 unknown。个人节点排序每轮最多 8 个节点、6 秒预算，轮换其余候选；当前节点和待确认候选优先。预算限制探测 I/O，不表示所有原生资源操作和文件锁都有同样上限。

`plan` 仅显示策略，不显示节点凭据；`doctor` 只读检查运行组件、物理网络、端口和冲突。发现已有 OpenConnect、系统代理/PAC 或其他 TUN 默认路由时拒绝启动。运行包不会自动退出 Clash、停止已有 VPN 或修改 Codex 配置。旧网络管理器的交接需在明确恢复办法后进行。

macOS 的 `doctor` 会在 `port_checks` 中区分当前用户可绑定的端口和 `requires_privileged_check`。普通用户无权绑定低端口，也可能不能复用刚关闭的管理员进程连接，因此这类结果不会被误报为确定占用。管理员启动阶段仍会在启动子进程或修改网络前逐一实际绑定检查；真实冲突会阻止启动。`ready_for_start` 仅表示可进入启动流程，不表示网络已经连接。

### 离线检查白名单和规则

```sh
./netlaunch config validate
./netlaunch config validate --file '/absolute/path/to/policy.candidate.json'
./netlaunch rules explain git.corp.example.com
./netlaunch rules explain download.example.org --file '/absolute/path/to/policy.candidate.json'
```

这些命令支持 `--profile DIR`，不联网、不请求管理员权限、不修改配置。`config validate` 有节点缓存时检查完整有效策略与节点入口冲突；尚无缓存时只检查本地策略和来源设置，明确返回 `scope: policy_only`、`nodes_checked: false`，不能视为已经可以启动。候选文件必须是 policy JSON，bootstrap 使用 `init`。

`rules explain` 与核心编译器共用同一份有序规则计划，输出胜出规则、来源和被覆盖的匹配项；`index` 为来源内从 1 开始的条目序号，内置规则为 0。公司/个人固定规则之后的 `guard` 是原有拒绝保护规则。配置了订阅时必须存在匹配缓存；纯手工节点模式可直接解释本地规则。解释是静态计划，不做 DNS 查询，也不证明实际连通；实际连接仍受认证、DNS 租约、选点和系统能力约束。输出含查询目标及匹配规则，分享前应检查内部地址。

`check-runtime` 可在初始化或导入节点前运行：先校验完整运行组件，再分别启动 Mihomo 和 OpenConnect 的版本命令。每个命令最多等待 5 秒，失败后停止，不重试；不读取个人节点或 VPN 会话，不请求管理员权限，也不改变网络。Windows 还会加载已校验的 Wintun 库并检查必需导出符号，不调用驱动或网卡接口。通过仅表示两个客户端能报告预期版本、相关库可以加载，不能代表驱动初始化、认证或网络接管通过。Windows 若报告执行失败，需结合系统安全记录判断原因；程序不会调整 Smart App Control。

校验失败会指出字段路径，如 `company.domains[1]`（数组从 0 开始，即第二项），错误消息不回显被拒绝的值。JSON 语法或类型错误在能定位时报告从 1 开始的行号和字节列号；未知字段只报告结构错误，不回显字段名。节点或订阅缓存的兼容性错误仍按其所在阶段报告。

### 预览、应用和回退配置

```sh
./netlaunch config diff --file '/absolute/path/to/policy.candidate.json'
./netlaunch config apply --file '/absolute/path/to/policy.candidate.json'
./netlaunch config history
./netlaunch config rollback
```

`diff` 对比字段值和有序规则计划，不联网、不修改文件；输出可能包含公司域名和内部地址，应保留在本机。`apply` 在本地用现有节点缓存验证候选策略，成功后保存旧、新版本并原子替换 `policy.json`。没有可用节点缓存或来源内容时先完成 `import` / `sync`；`apply` 不自动下载。默认仅在下次启动生效，现有运行保留启动时的配置，输出 `restart_required` 表示是否仍有运行需要重启。

要立即生效，使用 `config apply --file POLICY.json --restart`，或 `config rollback --restart`。这会先恢复旧运行的网络，再经过正常环境检查和认证启动新运行，期间连接会中断；支持 `--runtime DIR` 和对应 Windows 构建的会话期限选项。候选启动失败且网络已恢复时，自动还原旧策略，保持停止状态，排查后再 `up`；网络恢复失败则保留事务和恢复材料，先 `down` 再 `config rollback`。未完成事务会阻止 `up`、`sync`、`import` 和新的 `apply`。重启需要具备原生生命周期的构建，普通 Windows 构建仍只支持离线配置变更。

`history` 列出已保存的完整 SHA-256 版本号；`rollback` 默认恢复上一版，也可用 `--revision SHA256` 指定。未完成事务只允许回到该次变更的原始版本。版本文件仅保存策略，不包含节点密钥、认证会话或原生网络状态，但公司域名和 DNS 等策略内容仍属私密材料，不应上传 GitHub。回退会按当前节点/来源缓存重新验证，不复活旧 VPN 会话。手工修改了有效策略后，默认回退恢复最近托管版本；若文件损坏或与未完成事务冲突，命令拒绝覆盖，应保留文件并对照历史修复。不要在事务执行期间手工编辑 profile。

## 启动与停止

```sh
./netlaunch up
./netlaunch status
./netlaunch down
```

也可使用包内的双击入口。`up` 会先完成检查；需要时打开本机公司认证终端，随后请求一次 macOS 管理员授权。只有三个通道的系统路径检查都通过才显示 `ready`。

`status` 的 `channels.company`、`channels.personal`、`channels.direct` 分别包含 `state`、`reason`、`checked_at` 和需要时的 `next_action`；个人通道失败不再直接表示公司不可用。新探测证据还分别给出 `path_state`（verified/failed/unknown）和 `service_state`（healthy/failed/not_checked/unknown）。服务返回不符时可以同时显示路径 verified、服务 failed；healthy 只代表配置的 HTTP 状态符合预期。`lifecycle` 表示启动、运行或停止阶段，`phase` 保留总体状态。网络/VPN 代次/节点变化会使旧健康证据失效，超过 90 秒未复核的 ready 和细分证据显示为 unknown；旧格式状态文件继续兼容读取。

输入的密码与动态码不保存；私有配置目录中仅缓存已认证 VPN 会话，最长复用两小时。服务器可提前使其失效。需要重新认证时执行：

```sh
./netlaunch auth --force
```

批量调试时可使用 `up --prepare-only`：完成前置检查、本机认证与私有运行材料准备，显示 `prepared` 后退出，不请求管理员权限、不改变网络。实验监督程序随后可在同一个已授权管理员任务内启动已准备的运行、检查状态并恢复，避免每个诊断步骤各自弹窗。`prepared` 不表示连接成功；日常使用仍执行普通 `up`。

运行中的启动器会读取新的本地会话并重新建立自己拥有的 VPN。会话、节点和运行状态文件采用私有权限；切勿分享整个配置目录或运行目录。

公司 VPN 进程意外退出后，两端使用共享重连策略：撤销旧授权与租约，再按 10、20、40 秒退避，之后每 60 秒尝试一次；公司通道连续就绪 30 秒后重置退避。明确的认证拒绝会等待新的本机会话，切换网络或唤醒不会解除这个限制。启动阶段认证失败并完成恢复后，`status` 仍提示 `run_auth`；执行 `auth` 后再启动会复用新的有效会话。重新连接不使用超过两小时的缓存会话，已建立的连接不因这个缓存期限主动断开。

原生权限、组件加载、证书或 hook 故障一旦被明确识别，不作为普通传输故障无限重试；退出到恢复流程后根据状态处理。两个平台保留各自的进程与接口操作：Mac 对存活的 OpenConnect 仍使用原有重连信号，Windows 重建自己拥有的 VPN 接口。上述退避针对需要启动新 VPN 进程的情况。

公司精确域名的 DNS 租约正在更新时，两端最多等待 2 秒；等待不延长旧 TTL，也不允许过期地址、未知域名或未授权裸 IP 连接。新拨号仍检查当前 VPN 代次及原生路由/保护规则。每次子进程启动使用独立私有日志，诊断只读取有界尾部并输出固定原因码，旧尝试的迟到退出不会影响新尝试。

启动器记录自己拥有的进程、接口、路由和 DNS 改动。停止或主进程异常退出时，由独立看门狗执行恢复；检测到同名路由或 DNS 已被外部修改时报告 `recovery_failed`，不覆盖外部修改。详细恢复记录位于管理员专属的 `/Library/Application Support/NetLaunch/`。

### 断线时的本地恢复

`up` 在请求授权前会打印本次专用的 `恢复网络.command` 路径。保留终端窗口，连接两分钟内未自动恢复时：

1. 双击该文件，或打开包内 `停止与恢复.command`。
2. 等待显示恢复完成；如出现系统授权窗口，在本机完成授权。
3. 通过原来使用的入口重新启动旧 VPN/Clash（若已为本次交接手动关闭）。

恢复入口不依赖网络，也不重新要求公司认证。运行目录与管理员恢复记录会保留到重启之后；本版尚未安装开机恢复服务，异常重启后需手动运行恢复入口。它仅恢复 NetLaunch 的改动，不负责重启此前手动关闭的其他软件。若报告恢复不完整，保留运行目录并再次执行 `down`；不要手工删除日志或路由。

### 历史运行清理

在管理员终端中执行 `netlaunch runs cleanup --profile DIR --run DIR/runs/netlaunch-ID` 预览可清理的文件数和字节数，确认后用同一命令加 `--apply` 执行。macOS 使用 `sudo ./netlaunch` 并明确传入普通用户的配置目录。命令只处理指定的一个历史运行，不按目录年龄批量删除，也不会停止进程或修改网络。

只有管理员状态已记录恢复完成、所有记录的进程 ID 均不在使用、Windows 资源日志全部恢复时才允许清理。当前配置引用和 Windows 全局引用的运行、缺失恢复记录、未启动的 prepared 运行都会保留。清理删除两侧的 runtime 副本、日志和残留节点/会话/core 配置；冻结启动器、状态/配置快照、STOP、恢复入口和锁文件继续保留，目录本身不会删除。默认预览只建立互斥锁，不删除内容。中途失败可重试；不要手动删除剩余恢复记录。

## 工程开发

新运行使用 v2 恢复存储：管理员目录中的 `run-spec.json` 保存一次不可变配置与启动身份，`state.json` 保存当前网络绑定、进程和资源恢复记录，并用摘要绑定该配置。每秒心跳改写独立的 `heartbeat.json`，不再重写完整配置或占用原生状态锁；`status.updated` 表示最近一次状态快照更新，不是实时心跳。旧 v1 运行继续按原格式恢复，不原地迁移；请保留每个运行自己的冻结程序、配置记录和日志，不要用旧程序直接处理 v2 状态。

心跳分别记录进程存活与控制循环进展。运行就绪后，后台心跳不能掩盖超过 35 秒未推进的主循环；首次启动阶段给原生准备保留 90 秒进展窗口，原有睡眠唤醒宽限和 Windows 硬期限继续保留。独立恢复先验证并停止本次拥有的协调进程，再取得状态锁恢复资源，避免卡住的进程长期占锁；Mac 外部恢复会对完整身份匹配的协调进程使用 SIGKILL，子进程和网络资源仍依原有恢复日志处理，该原生变化需在 Mac 实机验收。任何原生变更仍必须先同步保存恢复意图，心跳拆分没有把这些记录改为异步写入。

`status` 的旧 `stale` 键保留为 `snapshot_stale` 的兼容别名，并明确输出 `stale_scope: saved_snapshot`、`snapshot_age_seconds` 和 `runtime_liveness: not_checked`。它只标识非 stopped/prepared 快照是否超过 40 秒或时间无效，不能据此断言协调器卡住。进程与主循环超时仍由独立看门狗读取心跳判断；普通状态命令不会为读取管理员心跳弹出授权窗口。

探针状态还带 `probe_scope`：`system_tun` 表示系统入口检查，`mixed_ingress` 表示本地代理入口检查。后者不能证明系统 TUN 接管已通过。固定核心的测速接口兼容性由 `TestPinnedCoreSeparatesPathLatencyFromServiceStatus` 检查；设置 `NETLAUNCH_TEST_RUNTIME` 后运行 engine 测试可执行回环 fixture。对应接口契约可查 [Mihomo v1.19.32 delay API](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/hub/route/proxies.go)；组件升级需要重新运行实际 fixture，不能仅凭编译成功判断兼容。

```sh
go test ./...
go vet ./...
NETLAUNCH_TEST_RUNTIME="$PWD/runtime" go test ./internal/app -run TestBundledCoreWithoutTUN -count=1
NETLAUNCH_TEST_CORE="$PWD/runtime/bin/mihomo" go test ./internal/lease -run TestCorePreservesDomainAcrossLeaseRotation -count=1
NETLAUNCH_GO=/path/to/go ./scripts/package-macos.sh
NETLAUNCH_GO=/path/to/go sh ./scripts/package-windows.sh
```

Windows 可以直接用 PowerShell 构建家用包，无需安装 Unix shell：

```powershell
.\scripts\package-windows.ps1 -Mode home -Runtime 'C:\path\to\runtime' -Go 'C:\path\to\go.exe'
```

脚本默认是 offline 模式，`-Mode validation` 产生开发验证包；不安装或启动网络。原生脚本拒绝复用已存在的同名输出目录，保留上一次产物供手动归档。输入 runtime 清单必须与仓库固定清单相同，归档前校验所有组件摘要。脚本产出的 ZIP、SHA256 和中间目录都在忽略的 `dist/` 下。构建工具版本、源码和组件清单应一同记录；这里的“重新构建”不承诺 ZIP 时间戳等元数据逐字节一致。

## 版本与诊断

`version` 输出单行版本号；`version --json` 还包含目标系统/架构、Go 版本、可用时的 Git 修订与工作区修改标记、构建模式和编译时能力。没有修订信息时省略该字段，不假装是正式发布。home 默认 8 小时、最长 12 小时，validation 要求显式期限且最长 45 分钟；Mac 模式单独标记 experimental。能力字段描述代码支持，不代表当前网络已经通过验证，也不把 Mac 的路由/绑定保护等同于 Windows WFP。

`diagnostics export` 向标准输出写入允许分享的 JSON，可指定 `--profile` 或 `--run`。示例：

```powershell
.\netlaunch.exe version --json
.\netlaunch.exe diagnostics export | Set-Content -Encoding utf8 .\diagnostics.public.json
```

Mac 可用 `./netlaunch diagnostics export > diagnostics.public.json`。诊断只读取保存的状态，保留固定的阶段、原因码、建议动作、探测范围和快照年龄；不导出公司域名、IP、节点名称、订阅入口、用户路径、原始错误、日志或认证材料。未知字段/枚举不会直接透传，过期探测结果会降为 unknown。没有当前运行或状态不可读时，用明确分类输出，仍能获得导出程序的版本信息。

`exporter_build` 是执行导出命令的程序版本，可能不同于当前运行中冻结的程序；`scope: saved_status` 与 `runtime_liveness: not_checked` 表示它没有查询后台进程、主动探测网络或验证恢复是否完成。`snapshot_age_seconds` 仅表示快照年龄，不能作为卡住的判据。诊断导出不调用 doctor、读取配置/日志或尝试联网；原始 `status`、`plan`、`doctor` 输出与私有运行目录不享有相同的分享约束。

Go 最低版本为 1.26；本机开发工具链可以放在已忽略的 `.tools/`。`scripts/package-macos.sh` 从本地 `runtime/` 打包已固定的 Mac arm64 组件，运行组件版本及校验值在 `scripts/runtime-manifest.macos-arm64.json`。归档只收录明确列出的程序、公共示例、许可与入口脚本。Windows 交叉打包脚本默认读取 `.local/windows-runtime/`，也可通过 `NETLAUNCH_WINDOWS_RUNTIME` 指定组件目录；对应固定清单为 `scripts/runtime-manifest.windows-amd64.json`。`NETLAUNCH_WINDOWS_MODE=offline|home|validation` 选择构建模式，默认 offline；包名包含模式。两端包名从同一版本常量生成，不再各自手改版本。

Windows 底层 `platform.BoundDial` 使用 `IP_UNICAST_IF` 建立指定网卡的 TCP/IPv4 连接。它只接受数字 IPv4 地址，绑定失败不会退回默认网卡；创建路由、识别 VPN 连接代次和安装保护规则由上层生命周期负责。Windows `auth` 已接入本机控制台和会话缓存，运行包包含 OpenConnect、DLL、Wintun 以及 `certs/ca-bundle.crt` 的完整校验组件。普通构建的 `up/down` 保持关闭，home/validation 构建开放有限时长生命周期。

Windows 默认配置位置为原生用户目录下的 `.netlaunch`。私有存储使用受保护 DACL、原子文件替换和文件锁；权限不满足要求时拒绝使用，不自动更改父目录的权限。`winnet` 通过 Windows API 识别物理出口并记录网卡索引、LUID、路由属性，进程识别使用原生句柄、创建时间和用户 SID。Smart App Control 拦截的开发产物需要受信任签名或合适的开发环境才能实测。

Windows 的管理员恢复日志使用原生 ProgramData 目录下的 `NetLaunch`，权限仅授予 Administrators 与 SYSTEM。`winstate` 在修改路由或 DNS 前持久化恢复意图，并保留“自动 DNS”状态；崩溃后可从尚未提交完成的意图继续恢复。`winproc` 先创建挂起子进程，将其加入随拥有者退出而关闭的 Job，再发布身份并恢复执行。Windows 的启动、认证回调、公司入口、停止与独立看门狗主体已经接入代码。家用与验证构建通过独立看门狗保护实际接管，普通构建保持关闭。公司路由已配对到规则核心的 TUN，优先级同时计算接口与路由 metric；公司 DNS 也使用此路径。WFP 将候选 VPN 的 IPv4 出口限制为管理员保护目录内协调器的 TCP 连接，阻断该接口上的其他应用、非 TCP 与 IPv6 连接。每次建立公司连接前后重新检查保护规则和路由所有权。恢复会先删除 VPN 路由，再删除成对的 TUN 路由，最后移除 WFP；删除失败时保留对应保护。首次启动先创建未接管默认路由的 TUN，再启动 VPN，健康检查通过后接管默认流量。

`lease` 提供独立于健康检查的公司 DNS 续期与连接授权：每次新建连接检查有效期，更新 VPN 连接代次时撤销旧查询与连接。Mac 的 `up` 已接入 `companyproxy` 本地认证入口：域名按当前租约重新选址，只允许明确的公司网段和 DNS TCP/53 使用原始 IP，并在拨号前检查 VPN 接口身份及所拥有的路由。DNS 地址改变时，先撤销旧地址的新连接授权，再准备路由、发布新地址。Mac 同时核对系统启动和唤醒标识，睡眠后即使网卡地址不变也要求 VPN 重新建立连接代次；DNS 有效期包含睡眠时间。睡眠后重新认证是否必要由公司服务器决定；Windows 主流程使用原生电源通知；本次架构改造的睡眠恢复仍应随目标平台版本验收。

公司域名不能通过向核心写入 `hosts` 来同步地址：该模式可能使下游仅收到 IP。现有策略关闭 `use-hosts` 和 `use-system-hosts`；后续公司出口必须保留原始精确域名，按当前租约重新选址。回环测试不代表普通应用的 TUN 接管或 VPN 睡眠恢复已通过。

模块边界：`subscription` 管理显式来源与受限规则导入，`policy` 管理授权与配置生成，`dnswire` 解析受限 DNS 报文，`lease` 管理地址有效期和连接代次，`selector` 管理个人节点优选，`auth/securefile` 管理本地会话与私有存储，`platform/socketbind` 管理系统适配，`engine` 管理生命周期与恢复，`app` 提供用户入口。

Windows 开发时可用 `go build -o .local/winprobe.exe ./cmd/winprobe` 构建独立试验入口，并在管理员终端执行。`idle --timeout 60s` 只测试恢复进程；添加 `--stage adapter|native|pair|mutation --runtime <完整组件目录>` 后，会先冻结可执行文件和已校验的 Wintun 库、启动独立恢复进程，然后打印 ProgramData 下的本轮目录并等待。先确认该目录中的 `recover.cmd` 可离线访问，再从另一个管理员终端执行该目录的 `winprobe.exe begin --run <本轮目录名>`。超时范围为 1 秒至 2 分钟，从准备阶段开始计时；超时终止试验主进程后的非零退出码须结合 `probe-result.json` 判断恢复结果。

`adapter` 仅创建本轮测试网卡；`native` 检查指定网卡的文档 IPv4 地址、路由、DNS、TCP/UDP 和链路本地 IPv6 保护；`pair` 检查两张测试网卡的成对路由；`mutation` 在成对路由的基础上修改测试路由的 metric，检查拒绝新连接、拒删外部变更及保留捕获/保护规则，再按独立的测试修改记录清理。它们不认证公司 VPN，也不接管默认流量。`pair` 可选 `--fault pair-planned|pair-capture-applied|pair-vpn-applied|pair-retiring|pair-vpn-restored`；`mutation` 可选 `--fault route-replaced`。故障点会立即退出，以检查独立恢复。恢复遇到错误会保留诊断并有限重试，仍按原有所有权检查执行。结果仅证明对应受控场景，不会启用标准构建的 Windows 网络启动开关。

探针的 `probe-automatic-result.json` 保留首次自动恢复结论，`probe-result.json` 记录最近恢复结果并保留首次失败；后续手动恢复成功不会改写首次自动结论。资源最终已清理与限时正常关闭是两个独立结果。每轮私有目录还保存 Wintun 生命周期、精确网卡身份和 holder 结局；网卡处于 Down、进程退出或查询失败均不代表设备已移除。

完整生命周期的开发试验需用 `go build -tags windows_validation -o .local/netlaunch-validation.exe ./cmd/netlaunch` 单独构建，并在 `up` 时显式提供 `--validation-timeout`（1 秒至 45 分钟，可搭配 `--prepare-only`）。该时间从管理员保护目录中的协调器发布时开始计时，不能续期；独立看门狗先就绪，再允许协调器执行，期限到达即撤销本轮资源。标准构建仍关闭 Windows 网络启动。切换既有客户端时，还需预先准备独立的本机恢复任务，负责恢复这些客户端；候选程序的资源日志仅负责自己的变更。验证构建并不表示整体验收完成。

Windows 验证构建分别记录并接管物理网卡的 IPv4、IPv6 DNS，防止系统经另一协议栈解析而失去 TUN 所需的域名映射。IPv6 DNS 入口仅监听 `[::1]:53`，通过有并发和时间限制的 TCP/UDP 转发连接本机核心；端口冲突时拒绝启动。两类 DNS 各自保存原始自动或静态设置，恢复时分别检查外部改动，不修改全局 IPv6 开关或其他网卡的 DNS。

Windows 每次尝试重连 VPN 都分配新的虚拟网卡名称，避免复用仍在移除中的 Wintun 实例；恢复仍按记录中的 GUID、LUID 和进程身份处理资源。公司精确域名租约到期时，请求可在原请求期限内最多等待 2 秒获取下一份有效租约；等待期间不授权旧地址，也不延长 DNS TTL。原始 IP、未授权域名、网卡或保护规则校验失败不会因此获得额外授权。

Windows 遇到服务器拒绝缓存会话时，启动阶段立即回收资源并记录 `authentication_required`；运行中则撤回公司通道，等待显式 `auth` 更新后再尝试。退出结果绑定到当前子进程的启动尝试，旧进程的迟到结果不会覆盖新连接。

已完成本机环境验证后，可用 `go build -tags windows_home -o netlaunch-home.exe ./cmd/netlaunch` 构建家用预览版。其 `up` 默认在 8 小时后自动回收，也可用 `--session-timeout` 指定 1 秒至 12 小时；期限写入后不能续期，`down` 可提前停止。该构建保留独立看门狗、所有权校验和恢复日志。启动前需要处理其他客户端冲突，并为原客户端准备独立恢复入口；它不会自动管理任意第三方 VPN 或代理。此构建与 `windows_validation` 不能合用，普通构建仍保持原来的平台开关。

开发过程结果仅保存在 `.local/` 等 Git 忽略目录；不要提交验收文档、验收清单、验收报告或临时结果汇总。

## Git 与私密配置

仓库只存源码、虚构示例和必要的第三方许可信息。真实公司域名、VPN 入口、DNS、内部地址、订阅 URL、节点密钥、会话、生成配置、日志、运行组件和本机测试材料均留在仓库外或已忽略的私有目录。公共测试站点本身不是凭据；是否适合业务使用仍由用户选择。

可启用随仓库提供的提交检查：

```sh
git config --local core.hooksPath .githooks
git config --local lumina.privatePolicyFile '/absolute/path/to/bootstrap.private.json'
python3 scripts/check-staged.py --all
```

检查读取 Git 暂存区，阻止非源码路径、常见密钥和私密配置中的公司地址/订阅信息进入提交。可另设 `lumina.privateNodeFile` 指向本机节点缓存以匹配实际节点凭据。这是辅助检查，不是完整的泄密检测或合规认定；代码权属、公司政策和第三方分发许可仍需分别确认。仓库暂未指定项目自身的开源许可证。
