# LuminaVPN

macOS 与 Windows 的白名单网络 CLI 工程预览版本。CLI 与本机配置目录暂沿用 `netlaunch` / `NetLaunch` 名称。Mac 运行包自带 Mihomo、OpenConnect 及所需动态库，使用时不需要安装 Go、Python、Node 或 Homebrew。

本版为工程预览：Mac 提供原生网络生命周期，Windows 的网络启动尚未开放。此前 Python 预实验的结论用于指导实现，不能替代这个版本的验证。建议先用 `plan`、`doctor` 检查配置和环境。

## 网络规则

- 公司精确域名与明确 IPv4 网段经公司 VPN。公司 DNS 也经公司 VPN。
- 个人流量经订阅或本地文件导入的代理节点。可选择导入受支持的个人分流规则；订阅中的 DNS、TUN、接口和链式代理设置不继承。
- 其他目标从当前物理网卡直连。
- 公司和个人通道均从 REJECT 开始，健康检查通过后开放。通道失效不会改投另一出口。
- `gateway.corp.example.com` 在示例的公司白名单中，覆盖其 `8443` 端口。白名单不依赖 Wi-Fi 或热点类型。

公司授权和固定个人目标允许精确域名及 IPv4 `/24`–`/32` 网段；额外个人规则支持精确域名、域名后缀及上述窄网段。公司后缀授权和 IPv6 白名单尚不支持。原生 IPv6、家庭 Mac 及 Windows 网络接管留待后续实现或验证。关闭核心 IPv6 并不代表关闭系统 IPv6；应用自带解析或缓存 IP 也可能无法命中域名规则。本版不承诺核心退出后的系统级永久阻断。

## 首次配置

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

`sync` 获取并校验全部显式来源，然后原子替换一份节点与规则缓存；任一来源不可用或校验失败则保留旧缓存。普通 `up` 按 `interval_minutes`（默认 60 分钟）检查是否需要刷新，失败时可复用仍与当前配置匹配的旧缓存。间隔控制启动时刷新，本版没有后台定时刷新；运行时执行 `sync` 也只在下次启动生效。`plan` 不联网，只读取缓存；输出含公司策略和内部地址，不应直接公开。

规则优先级依次为：公司固定目标 → 本地固定个人目标和直连健康检查目标 → `policy.personal_rules` 本地覆盖 → 订阅规则 → 其余直连。同一层按文件顺序取首次命中。订阅不能增加公司授权，也不能覆盖前面的固定目标。DNS 分流保持同样的域名优先级。

节点文件支持含 `proxies` 数组的 Clash/Mihomo YAML 或 JSON；协议支持 VLESS、Hysteria2，入口可使用 IPv4 或精确域名。不支持的协议、无效条目和关闭证书验证的节点会计数并跳过。URI 列表与 Base64 节点订阅尚不支持。

规则支持 `rules` 或 `payload` 数组中的 `DOMAIN`、`DOMAIN-SUFFIX`、IPv4 `/24`–`/32` `IP-CIDR`。额外来源可在 `subscriptions.rules` 中配置 `url` 或 `file`，`format` 支持 `classical`、`domain`（`+.` 表示后缀）和 `ipcidr`。默认组名映射为 PROXY/PERSONAL → personal、DIRECT → direct、REJECT → reject；其他组名需要显式映射。不支持的规则会计数并跳过，整份规则源没有可用规则时更新失败。GEOSITE、GEOIP、MATCH、进程规则、组合规则、IPv6 和宽网段尚不导入；因此导入结果不等同于原订阅全部行为。不会自动追踪 `rule-providers` / `proxy-providers` 链接，额外来源需明确填写。

HTTPS 下载正常校验证书，不跟随重定向，单源限制 4 MiB；订阅必须在当前网络下可获取。首次导入时如尚无可用代理，可先导出本地节点文件启动。此流程不会调整系统代理以下载订阅。

也可以保留纯离线方式：`init` 创建示例策略，或 `init --file policy.private.json` 导入已写好的策略；再运行 `import --file subscription.yaml`。`import` 只导入节点，不导入规则。已配置订阅来源的 profile 使用 `sync`，不能混用 `import`。

节点测速用于排序；选中节点还须通过本地代理入口完成配置中的个人 HTTPS 检查。请求失败时，个人通道先回到 REJECT，失败节点经过冷却及连续健康检查后才能重新参与选择。启动阶段的个人系统路径检查失败也会触发重新选点；这不会将个人流量改投公司或直连出口。三个通道的系统 TUN 检查仍全部通过后才显示 `ready`。

`plan` 仅显示策略，不显示节点凭据；`doctor` 只读检查运行组件、物理网络、端口和冲突。发现已有 OpenConnect、系统代理/PAC 或其他 TUN 默认路由时拒绝启动。运行包不会自动退出 Clash、停止已有 VPN 或修改 Codex 配置。旧网络管理器的交接需在明确恢复办法后进行。

macOS 的 `doctor` 会在 `port_checks` 中区分当前用户可绑定的端口和 `requires_privileged_check`。普通用户无权绑定低端口，也可能不能复用刚关闭的管理员进程连接，因此这类结果不会被误报为确定占用。管理员启动阶段仍会在启动子进程或修改网络前逐一实际绑定检查；真实冲突会阻止启动。`ready_for_start` 仅表示可进入启动流程，不表示网络已经连接。

`check-runtime` 可在初始化或导入节点前运行：先校验完整运行组件，再分别启动 Mihomo 和 OpenConnect 的版本命令。每个命令最多等待 5 秒，失败后停止，不重试；不读取个人节点或 VPN 会话，不请求管理员权限，也不改变网络。Windows 还会加载已校验的 Wintun 库并检查必需导出符号，不调用驱动或网卡接口。通过仅表示两个客户端能报告预期版本、相关库可以加载，不能代表驱动初始化、认证或网络接管通过。Windows 若报告执行失败，需结合系统安全记录判断原因；程序不会调整 Smart App Control。

## 启动与停止

```sh
./netlaunch up
./netlaunch status
./netlaunch down
```

也可使用包内的双击入口。`up` 会先完成检查；需要时打开本机公司认证终端，随后请求一次 macOS 管理员授权。只有三个通道的系统路径检查都通过才显示 `ready`。

输入的密码与动态码不保存；私有配置目录中仅缓存已认证 VPN 会话，最长复用两小时。服务器可提前使其失效。需要重新认证时执行：

```sh
./netlaunch auth --force
```

批量调试时可使用 `up --prepare-only`：完成前置检查、本机认证与私有运行材料准备，显示 `prepared` 后退出，不请求管理员权限、不改变网络。实验监督程序随后可在同一个已授权管理员任务内启动已准备的运行、检查状态并恢复，避免每个诊断步骤各自弹窗。`prepared` 不表示连接成功；日常使用仍执行普通 `up`。

运行中的启动器会读取新的本地会话并重新建立自己拥有的 VPN。会话、节点和运行状态文件采用私有权限；切勿分享整个配置目录或运行目录。

启动器记录自己拥有的进程、接口、路由和 DNS 改动。停止或主进程异常退出时，由独立看门狗执行恢复；检测到同名路由或 DNS 已被外部修改时报告 `recovery_failed`，不覆盖外部修改。详细恢复记录位于管理员专属的 `/Library/Application Support/NetLaunch/`。

### 断线时的本地恢复

`up` 在请求授权前会打印本次专用的 `恢复网络.command` 路径。保留终端窗口，连接两分钟内未自动恢复时：

1. 双击该文件，或打开包内 `停止与恢复.command`。
2. 等待显示恢复完成；如出现系统授权窗口，在本机完成授权。
3. 通过原来使用的入口重新启动旧 VPN/Clash（若已为本次交接手动关闭）。

恢复入口不依赖网络，也不重新要求公司认证。运行目录与管理员恢复记录会保留到重启之后；本版尚未安装开机恢复服务，异常重启后需手动运行恢复入口。它仅恢复 NetLaunch 的改动，不负责重启此前手动关闭的其他软件。若报告恢复不完整，保留运行目录并再次执行 `down`；不要手工删除日志或路由。

## 工程开发

```sh
go test ./...
go vet ./...
NETLAUNCH_TEST_RUNTIME="$PWD/runtime" go test ./internal/app -run TestBundledCoreWithoutTUN -count=1
NETLAUNCH_TEST_CORE="$PWD/runtime/bin/mihomo" go test ./internal/lease -run TestCorePreservesDomainAcrossLeaseRotation -count=1
NETLAUNCH_GO=/path/to/go ./scripts/package-macos.sh
NETLAUNCH_GO=/path/to/go sh ./scripts/package-windows.sh
```

Go 最低版本为 1.26；本机开发工具链可以放在已忽略的 `.tools/`。`scripts/package-macos.sh` 从本地 `runtime/` 打包已固定的 Mac arm64 组件，运行组件版本及校验值在 `scripts/runtime-manifest.macos-arm64.json`。脚本不会收集个人配置、日志、会话或实验资料。Windows 交叉打包脚本默认读取 `.local/windows-runtime/`，也可通过 `NETLAUNCH_WINDOWS_RUNTIME` 指定组件目录；对应固定清单为 `scripts/runtime-manifest.windows-amd64.json`。Windows 工程包目前用于配置和环境检查，网络启动仍关闭。

Windows 目前可构建共享配置检查 CLI，底层 `platform.BoundDial` 使用 `IP_UNICAST_IF` 建立指定网卡的 TCP/IPv4 连接。它只接受数字 IPv4 地址，绑定失败不会退回默认网卡；不负责创建路由、识别 VPN 连接代次或安装保护规则。Windows `auth` 已接入本机控制台和会话缓存，工程包已包含 OpenConnect、DLL、Wintun 以及 `certs/ca-bundle.crt` 的完整校验运行组件；该包的原生加载、真实认证和系统接管仍待验证。原生 `up/down` 尚未开放。

Windows 默认配置位置为原生用户目录下的 `.netlaunch`。私有存储使用受保护 DACL、原子文件替换和文件锁；权限不满足要求时拒绝使用，不自动更改父目录的权限。`winnet` 通过 Windows API 识别物理出口并记录网卡索引、LUID、路由属性，进程识别使用原生句柄、创建时间和用户 SID。网络接管与持久恢复完成之前，这些底层接口不会开放 `up`。Smart App Control 拦截的开发产物需要受信任签名或合适的开发环境才能实测。

Windows 的管理员恢复日志使用原生 ProgramData 目录下的 `NetLaunch`，权限仅授予 Administrators 与 SYSTEM。`winstate` 在修改路由或 DNS 前持久化恢复意图，并保留“自动 DNS”状态；崩溃后可从尚未提交完成的意图继续恢复。`winproc` 先创建挂起子进程，将其加入随拥有者退出而关闭的 Job，再发布身份并恢复执行。Windows 的启动、认证回调、公司入口、停止与独立看门狗主体已经接入代码。实际接管仍关闭，等待原生整体验证。公司路由已配对到规则核心的 TUN，优先级同时计算接口与路由 metric；公司 DNS 也使用此路径。WFP 将候选 VPN 的 IPv4 出口限制为管理员保护目录内协调器的 TCP 连接，阻断该接口上的其他应用、非 TCP 与 IPv6 连接。每次建立公司连接前后重新检查保护规则和路由所有权。恢复会先删除 VPN 路由，再删除成对的 TUN 路由，最后移除 WFP；删除失败时保留对应保护。首次启动先创建未接管默认路由的 TUN，再启动 VPN，健康检查通过后接管默认流量。

`lease` 提供独立于健康检查的公司 DNS 续期与连接授权：每次新建连接检查有效期，更新 VPN 连接代次时撤销旧查询与连接。Mac 的 `up` 已接入 `companyproxy` 本地认证入口：域名按当前租约重新选址，只允许明确的公司网段和 DNS TCP/53 使用原始 IP，并在拨号前检查 VPN 接口身份及所拥有的路由。DNS 地址改变时，先撤销旧地址的新连接授权，再准备路由、发布新地址。Mac 同时核对系统启动和唤醒标识，睡眠后即使网卡地址不变也要求 VPN 重新建立连接代次；DNS 有效期包含睡眠时间。睡眠后重新认证是否必要由公司服务器决定；Windows 主流程已经接入原生电源通知，但实际睡眠恢复与网络接管仍待验证。

公司域名不能通过向核心写入 `hosts` 来同步地址：该模式可能使下游仅收到 IP。现有策略关闭 `use-hosts` 和 `use-system-hosts`；后续公司出口必须保留原始精确域名，按当前租约重新选址。回环测试不代表普通应用的 TUN 接管或 VPN 睡眠恢复已通过。

模块边界：`subscription` 管理显式来源与受限规则导入，`policy` 管理授权与配置生成，`dnswire` 解析受限 DNS 报文，`lease` 管理地址有效期和连接代次，`selector` 管理个人节点优选，`auth/securefile` 管理本地会话与私有存储，`platform/socketbind` 管理系统适配，`engine` 管理生命周期与恢复，`app` 提供用户入口。

Windows 开发时可用 `go build -o .local/winprobe.exe ./cmd/winprobe` 构建独立试验入口，并在管理员终端执行。`idle --timeout 60s` 只测试恢复进程；添加 `--stage adapter|native|pair|mutation --runtime <完整组件目录>` 后，会先冻结可执行文件和已校验的 Wintun 库、启动独立恢复进程，然后打印 ProgramData 下的本轮目录并等待。先确认该目录中的 `recover.cmd` 可离线访问，再从另一个管理员终端执行该目录的 `winprobe.exe begin --run <本轮目录名>`。超时范围为 1 秒至 2 分钟，从准备阶段开始计时；超时终止试验主进程后的非零退出码须结合 `probe-result.json` 判断恢复结果。

`adapter` 仅创建本轮测试网卡；`native` 检查指定网卡的文档 IPv4 地址、路由、DNS、TCP/UDP 和链路本地 IPv6 保护；`pair` 检查两张测试网卡的成对路由；`mutation` 在成对路由的基础上修改测试路由的 metric，检查拒绝新连接、拒删外部变更及保留捕获/保护规则，再按独立的测试修改记录清理。它们不认证公司 VPN，也不接管默认流量。`pair` 可选 `--fault pair-planned|pair-capture-applied|pair-vpn-applied|pair-retiring|pair-vpn-restored`；`mutation` 可选 `--fault route-replaced`。故障点会立即退出，以检查独立恢复。恢复遇到错误会保留诊断并有限重试，仍按原有所有权检查执行。结果仅证明对应受控场景，不会启用标准构建的 Windows 网络启动开关。

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
