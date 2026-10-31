# ARO

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

ARO 是面向 Linux 或 Windows 服务器开发者的智能体技能。它会重新盘点本机软件，
查询相关安全公告，用简短的说明解释实际风险，并生成供你审批的限定范围更新计划。

需要 **Python 3.11 或更高版本**。核心仅使用 Python 标准库，同时提供 Bash 和
PowerShell 启动脚本。ARO 不会自动安装运行依赖或可选扫描器。

## 安装

如果已安装 Node.js/npm，可使用 [Skills CLI](https://github.com/vercel-labs/skills/blob/main/docs/commands.md)：

```bash
npx skills add HHC225/ARO --skill aro
```

在安装界面中选择智能体和安装范围。能够读取 `SKILL.md` 并执行本地 Python 的
智能体也可以使用手动安装。在项目目录中运行：

```bash
git clone https://github.com/HHC225/ARO.git
mkdir -p .agents/skills
cp -R ARO/skills/aro .agents/skills/aro
```

根据客户端要求，将 `.agents/skills` 替换为 `.claude/skills` 或 `.codex/skills`。
必须复制包含脚本和参考文档的**整个** `skills/aro` 文件夹。也可以不复制，直接在
仓库中运行。Windows PowerShell 示例：

```powershell
git clone https://github.com/HHC225/ARO.git
New-Item -ItemType Directory -Force .agents/skills | Out-Null
Copy-Item -Recurse ARO/skills/aro .agents/skills/aro
```

安装命令会下载第三方代码，请在使用前检查。Skills 安装器自身的行为和遥测设置
与 ARO 扫描器相互独立。无需进行 ChatGPT 专用安装。

## 通过智能体使用

可以说：**“用 $aro 检查这台服务器和我的应用，简要解释风险，并生成需要我审批
的更新计划。”** 技能指令为英文，但智能体可以用你选择的语言解释结果。

首次检查会建立持久的软件清单。之后每次仍会重新盘点，记录新增、移除和版本变化。
每项结果用一行表示：**组件 · 当前版本 → 修复版本 · 实际风险及原因 · 来源链接**。
无法确定的版本、未知的暴露情况和来源查询失败都会明确保留。已知来自非公开来源的
npm/Cargo/Python 项目以未选中证据保留在本地清单中，不进行外部查询。

## 直接运行

`check --refresh` 会在存在有效缓存时仍重新获取当前安全公告，不能与 `--offline` 同时使用。

在仓库目录中运行：

```bash
python3 skills/aro/scripts/aro.py check --root /srv/my-app
python3 skills/aro/scripts/aro.py check --root /srv/my-app --format json
bash skills/aro/scripts/aro.sh check --root /srv/my-app
```

在 Windows 上，可根据安装情况使用 Python 3.11+ 的 `python` 或 `py -3` 命令：

```powershell
python skills/aro/scripts/aro.py check --root C:/apps/my-app
powershell -File skills/aro/scripts/aro.ps1 check --root C:/apps/my-app
```

如果已复制安装，请将上述路径替换为实际安装位置。

| 命令 | 用途 |
| --- | --- |
| `init` / `scan` | 只刷新本地软件清单，不查询公告 |
| `check` | 重新盘点并检查相关公告 |
| `sources` | 显示为当前清单选择的公告查询路线 |
| `config --show` | 显示生效配置 |
| `exposure` | 记录已确认的网络事实或组件可达性 |
| `plan --finding ID --target-version VERSION` | 保存范围明确的更新计划 |
| `apply --plan PATH --approve HASH` | 通过执行前校验后执行该批准计划 |

`--root PATH` 可以重复指定，路径会保存到配置中。如果没有已保存的路径，则在
文件数、深度和时间限制内扫描当前目录及平台常见应用位置。需要确定的项目覆盖范围
时，请显式指定路径。`--state-dir PATH` 可指定其他状态目录，`check --offline`
使用缓存而不发出公告请求，`--format json` 输出详细的结构化结果。

`check --fail-on high`、`critical`、`any` 或 `none` 用于设置发现问题时的失败阈值，
默认值为 `none`。退出码：`0` 表示完成且未达到阈值，`1` 表示发现达到阈值的问题，
`2` 表示错误或检查不完整，`3` 表示批准或过期计划被拒绝。不完整状态优先于发现阈值。
即使没有发现问题，也要查看覆盖范围。

## 检查范围与局限

ARO 收集可访问的操作系统/包管理器元数据、运行时、进程、监听端口、受支持项目的
manifest/lockfile 以及 Docker 元数据。已安装的 **Syft** 和 **Trivy** 可补充受支持
的 SBOM 和针对发行版的主机/容器检查。缺少工具、权限错误、扫描限制和版本不明都会
列为覆盖缺口。不保证发现所有自定义二进制文件或容器内部的全部软件包。

根据发现的软件选择生态系统公告、已知利用情况以及适用的厂商/发行版/运行时证据。
准确的适配器列表见[来源文档](skills/aro/references/sources.md)和 `sources` 结果。
发行版回移的安全修复应根据发行版证据判断，不能直接与上游版本号比较。没有 CVE
编号的公告也可能适用。

两个平台的已实现覆盖范围均受可访问元数据和工具限制：

| 对象 | 平台与支持的证据 | 公告来源 / 局限 |
| --- | --- | --- |
| Linux OS | dpkg、RPM 或 apk 包元数据 | 对已映射的 Debian/Ubuntu 发行版，使用原生源包名/版本直接查询 OSV，保留回移修复语义。其他发行版使用可选 Trivy；不支持的发行版仍为缺口。 |
| Windows OS | OS/build、已安装软件和更新元数据 | Windows Update Agent 只读搜索适用且未安装的安全更新。受已配置更新服务/策略限制；系统更新安装为手动操作。 |
| Python 项目 | Linux/Windows：固定版本的 `requirements*.txt`、`Pipfile.lock`、`poetry.lock`、`uv.lock`、已安装发行包元数据 | OSV PyPI。未解析的 manifest 范围为缺口。 |
| JavaScript 项目 | Linux/Windows：`package-lock.json`、`npm-shrinkwrap.json` | OSV npm。没有原生 Yarn/pnpm lockfile 解析器。 |
| 其他项目锁文件 | Linux/Windows：`Cargo.lock`、`go.mod`/`go.sum`、`composer.lock`、`Gemfile.lock`、`packages.lock.json`/`project.assets.json`、精确 `gradle.lockfile` 坐标 | OSV crates.io、Go、Packagist、RubyGems、NuGet、Maven。没有已解析锁文件的 Maven/Gradle manifest 为缺口；不提供完整 Maven resolver。仅有 `go.sum` 不能证明当前选中的依赖。 |
| 运行时 | 可确认的 Python、Node.js、Go 等版本 | 官方 CPython/Node/Go 记录；PHP/Ruby/.NET/Rust 仓库公告覆盖不完整。不支持 JDK 厂商匹配；发行版构建需要回移修复审查。 |
| 容器 / SBOM | 可访问的 Docker 元数据，以及已安装的 Syft/Trivy | 可选深层盘点及本地不可变镜像 ID 的 OS 问题。需要访问本地守护进程及可用扫描器数据库，不保证完整镜像覆盖。 |

CISA KEV 通过精确 CVE 标识补充已知利用信息；未收录不代表不存在利用。Windows WUA
搜索不会下载或安装更新，也不是完整的 MSRC CVE 适用性判断引擎。

**CGNAT 不能证明安全。** IPv6、隧道、反向代理、端口转发、局域网访问、本地提权
以及需要用户交互的攻击仍可能相关。ARO 会明确表示未知的暴露状态，不会自动把
主机级观察结果套用到所有组件的可达性上。仅限制入站连接不会降低出站客户端风险；
降低优先级还需要针对该发现的最新入站服务攻击路径证据。只记录已确认的事实，例如：

```bash
python3 skills/aro/scripts/aro.py exposure --cgnat confirmed --public-ipv4 no --public-ipv6 no --inbound-forwarding no --tunnels no
```

## 更新需要批准具体计划

从当前发现的问题和准确的目标版本生成计划：

```bash
python3 skills/aro/scripts/aro.py plan --finding FINDING_ID --target-version VERSION
python3 skills/aro/scripts/aro.py apply --plan /path/to/plan.json --approve FULL_PLAN_HASH
```

运行 `apply` 前，请检查实际计划中的精确参数、目标、依赖影响、工作目录、清单哈希、
有效期及恢复限制。批准仅适用于该文件和范围。如果软件状态发生变化，或计划过期、
被修改，则需要重新生成计划并审批。自动执行仅限于 apt/apk、运行 ARO 的 Python
环境中的 pip、具有 manifest/lockfile 且无歧义的直接 npm 依赖，以及已验证的准确
WinGet ID。pip 仅修改自身解释器/prefix，拒绝外部 prefix 的包；npm 拒绝嵌套、别名和
workspace 安装。apt/apk 会模拟依赖事务，并在实际执行前重新验证。pip 只使用预构建
wheel，不更新依赖；npm 禁用生命周期脚本，但可能
修改间接依赖和 lockfile。dnf/RPM、通用 Windows 系统更新、容器等目标提供手动指导。
计划在 30 分钟后过期。公告所列修复版本可能不可用或与应用不兼容，自动版本排序
也仅适用于受支持的版本格式。

ARO 会记录执行过程，并在成功或部分失败后再次盘点。ARO 不会自动提权，也不会
主动执行单独的服务或系统重启。但软件包/厂商安装钩子**可能重启服务**，因此批准范围
必须包括依赖变化及停机影响。在执行经过授权的应用健康检查前，服务健康状态仍为
未验证。包管理器成功退出本身不能证明漏洞已经完全修复。

## 状态、网络与隐私

状态保存在技能和被检查仓库之外：

- Linux：`${XDG_STATE_HOME:-~/.local/state}/aro`
- Windows：`%LOCALAPPDATA%/ARO`（未设置时使用 `~/AppData/Local/ARO`）

自动创建的 `config.json` 支持扫描路径、`exclude_packages` 包名 glob、网络观察、
缓存期限和扫描限制。使用 `config --show` 查看配置，其他更改通过编辑有效 JSON
完成。示例见[工作流程](skills/aro/references/workflow.md)。状态包括当前清单/报告、
公告缓存、不可修改的计划和补丁执行日志，请保密保存，不要提交到 Git。

检查只读取本地元数据，不修改已安装的软件或应用文件。查询公告可能会向配置的服务
披露**包名和版本**，但不会上传应用源代码或凭据。如果不能接受私有包名外泄，请在
首次在线检查前将其排除。本地报告可能含有路径和软件详细信息。

不需要智能体侧的浏览器，但脚本仍需要互联网连接或可用缓存。离线、缓存过旧和来源
失败的结果会保留数据时间及覆盖缺口。“未确认匹配项”仅描述已检查范围，不代表
服务器安全保证。外部路由器/防火墙策略、不支持的软件和无法访问的位置可能仍然未知。

开发和验证请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题报告见
[SECURITY.md](SECURITY.md)，MIT 许可证见 [LICENSE](LICENSE)。可分发技能位于
[`skills/aro`](skills/aro)，无需将仓库安装为 Python 包。
