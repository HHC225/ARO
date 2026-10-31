# ARO

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

ARO는 Linux 또는 Windows 서버를 운영하는 개발자를 위한 에이전트 스킬입니다.
현재 설치된 소프트웨어 지도를 새로 만들고, 관련 보안 권고를 확인하며, 실제
위험을 짧게 설명하고, 승인할 수 있는 구체적인 업데이트 계획을 작성합니다.

**Python 3.11 이상**이 필요합니다. 핵심 엔진은 Python 표준 라이브러리만
사용하며 Bash 및 PowerShell 실행 파일을 제공합니다. 필수 프로그램이나 선택적
스캐너를 자동으로 설치하지 않습니다.

## 설치

Node.js/npm이 있다면 [Skills CLI](https://github.com/vercel-labs/skills/blob/main/docs/commands.md)를 사용하세요.

```bash
npx skills add HHC225/ARO --skill aro
```

설치 화면에서 에이전트와 설치 범위를 선택합니다. `SKILL.md`를 읽고 로컬
Python을 실행할 수 있는 에이전트라면 직접 복사해서 사용할 수도 있습니다.
프로젝트 디렉터리에서 다음을 실행하세요.

```bash
git clone https://github.com/HHC225/ARO.git
mkdir -p .agents/skills
cp -R ARO/skills/aro .agents/skills/aro
```

클라이언트에 따라 `.agents/skills`를 `.claude/skills` 또는 `.codex/skills`로
바꾸세요. 스크립트와 참조 문서를 포함한 `skills/aro` **폴더 전체**를 복사해야
합니다. 복사하지 않고 저장소에서 바로 실행해도 됩니다. Windows PowerShell:

```powershell
git clone https://github.com/HHC225/ARO.git
New-Item -ItemType Directory -Force .agents/skills | Out-Null
Copy-Item -Recurse ARO/skills/aro .agents/skills/aro
```

설치 명령은 외부 코드를 내려받으므로 사용 전에 검토하세요. Skills 설치
프로그램의 동작과 텔레메트리 설정은 ARO 스캐너와 별개입니다. ChatGPT 전용
설치는 필요하지 않습니다.

## 에이전트로 사용

**“$aro로 이 서버와 앱을 점검하고, 위험을 짧게 설명한 다음, 내가 승인할
업데이트 계획을 만들어 줘.”**라고 요청하세요. 스킬 지침은 영어이지만 결과는
원하는 언어로 설명할 수 있습니다.

처음 실행하면 로컬 소프트웨어 지도가 생성됩니다. 이후에도 매번 다시 조사해
추가·제거·버전 변경을 기록합니다. 결과는 **구성 요소 · 현재 → 수정 버전 · 실제
위험과 이유 · 출처 링크** 형식의 짧은 줄로 전달합니다. 버전을 확인하지 못했거나
노출 여부가 불분명하거나 출처 조회에 실패했다면 그 한계를 표시합니다. 비공개 출처로 확인된 npm/Cargo/Python 항목은
로컬 지도에 미선택 근거로 남기며 외부 조회하지 않습니다.

## 직접 실행

`check --refresh`는 유효한 캐시가 있어도 최신 보안 정보를 다시 조회합니다. `--offline`과 함께 사용할 수 없습니다.

저장소 디렉터리에서 실행합니다.

```bash
python3 skills/aro/scripts/aro.py check --root /srv/my-app
python3 skills/aro/scripts/aro.py check --root /srv/my-app --format json
bash skills/aro/scripts/aro.sh check --root /srv/my-app
```

Windows에서는 필요에 따라 Python 3.11 이상을 `python` 또는 `py -3`로 실행합니다.

```powershell
python skills/aro/scripts/aro.py check --root C:/apps/my-app
powershell -File skills/aro/scripts/aro.ps1 check --root C:/apps/my-app
```

복사해서 설치했다면 위 경로를 실제 설치 위치로 바꾸세요.

| 명령 | 기능 |
| --- | --- |
| `init` / `scan` | 보안 권고 조회 없이 소프트웨어 지도 갱신 |
| `check` | 새로 조사한 뒤 관련 보안 권고 확인 |
| `sources` | 현재 소프트웨어에 선택된 권고 조회 경로 표시 |
| `config --show` | 적용된 설정 표시 |
| `exposure` | 확인된 네트워크 사실 또는 구성 요소 접근성 기록 |
| `plan --finding ID --target-version VERSION` | 정확한 범위의 업데이트 계획 저장 |
| `apply --plan PATH --approve HASH` | 사전 검증 후 해당 승인 계획 실행 |

`--root PATH`는 여러 번 지정할 수 있고 지정된 경로는 설정에 저장됩니다.
저장된 경로가 없으면 현재 디렉터리와 플랫폼별 일반 앱 위치를 파일 수·깊이·시간
제한 안에서 조사합니다. 프로젝트 범위를 확실히 하려면 경로를 직접 지정하세요.
`--state-dir PATH`로 상태 위치를 바꾸고, `check --offline`으로 외부 조회 없이
캐시를 사용하며, `--format json`으로 상세 결과를 확인할 수 있습니다.

`check --fail-on high`, `critical`, `any`, `none`으로 발견 사항의 실패 기준을
정합니다. 기본값은 `none`입니다. 종료 코드 `0`은 기준 미만으로 완료, `1`은 기준에
해당하는 발견 사항, `2`는 오류 또는 불완전한 점검, `3`은 승인/오래된 계획 거부를
뜻합니다. 불완전 상태가 발견 사항 기준보다 우선합니다. 발견 사항이 없어도
점검 범위를 확인하세요.

## 점검 범위와 한계

접근 가능한 OS/패키지 관리자 메타데이터, 런타임, 프로세스, 수신 포트, 지원하는
프로젝트 manifest/lockfile, Docker 메타데이터를 조사합니다. 이미 설치된 **Syft**와
**Trivy**는 지원하는 SBOM 및 배포판별 호스트/컨테이너 점검을 보완합니다. 도구 부재,
권한 오류, 탐색 한도, 미확인 버전은 점검 공백으로 표시합니다. 모든 사용자 정의
바이너리나 컨테이너 내부 패키지를 찾는다고 보장하지 않습니다.

발견한 소프트웨어에 맞춰 생태계 권고, 실제 악용 정보, 해당 공급업체/배포판/런타임
근거를 선택합니다. 정확한 어댑터는 [출처 문서](skills/aro/references/sources.md)와
`sources` 결과를 확인하세요. 배포판의 백포트 수정은 업스트림 버전 숫자가 아니라
배포판 근거로 판단해야 합니다. CVE 번호가 없는 권고도 유효할 수 있습니다.

두 플랫폼의 구현 범위는 접근 가능한 메타데이터와 도구에 따라 제한됩니다.

| 대상 | 플랫폼 및 지원 근거 | 권고 조회 경로 / 한계 |
| --- | --- | --- |
| Linux OS | dpkg, RPM, apk 패키지 메타데이터 | 지원되는 Debian/Ubuntu 릴리스는 네이티브 소스 패키지/버전으로 OSV 직접 조회(백포트 포함). 다른 배포판은 선택적 Trivy 사용. 미지원 릴리스는 공백으로 표시. |
| Windows OS | OS/build, 설치 소프트웨어, 업데이트 메타데이터 | Windows Update Agent로 적용 가능한 미설치 보안 업데이트를 읽기 전용 조회. 설정된 업데이트 서비스/정책에 따라 제한되며 OS 업데이트 설치는 수동. |
| Python 프로젝트 | Linux/Windows: 고정된 `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, 설치 배포 메타데이터 | OSV PyPI. 미확정 manifest 범위는 공백. |
| JavaScript 프로젝트 | Linux/Windows: `package-lock.json`, `npm-shrinkwrap.json` | OSV npm. Yarn/pnpm lockfile 네이티브 파서는 없음. |
| 기타 프로젝트 잠금 파일 | Linux/Windows: `Cargo.lock`, `go.mod`/`go.sum`, `composer.lock`, `Gemfile.lock`, `packages.lock.json`/`project.assets.json`, 정확한 `gradle.lockfile` 좌표 | OSV crates.io, Go, Packagist, RubyGems, NuGet, Maven. 확정 lock 없는 Maven/Gradle manifest는 공백이며 전체 Maven resolver는 아님. `go.sum`만으로 현재 선택된 의존성을 증명하지 않음. |
| 런타임 | 확인 가능한 Python, Node.js, Go 및 기타 버전 | 공식 CPython/Node/Go 자료. PHP/Ruby/.NET/Rust 저장소 피드는 부분적. JDK 공급업체 매칭 미지원이며 배포판 빌드는 백포트 검토 필요. |
| 컨테이너 / SBOM | 접근 가능한 Docker 메타데이터 및 이미 설치된 Syft/Trivy | 선택적 심층 조사와 로컬 고정 이미지 ID의 OS 발견 사항. 로컬 데몬 접근과 사용 가능한 스캐너 DB 필요. 이미지 전체 범위 보장 없음. |

CISA KEV는 정확한 CVE 식별자로 실제 악용 정보를 추가합니다. 목록에 없다고 악용되지
않는다는 뜻은 아닙니다. Windows WUA 조회는 업데이트를 내려받거나 설치하지 않으며
완전한 MSRC CVE 적용성 판정 엔진이 아닙니다.

**CGNAT는 안전하다는 증거가 아닙니다.** IPv6, 터널, 리버스 프록시, 포트 전달,
LAN 접근, 로컬 권한 상승, 사용자 상호작용 위험은 여전히 관련될 수 있습니다.
ARO는 모르는 노출 상태를 명시하고, 호스트 전체의 관찰값을 모든 구성 요소의
접근성으로 자동 적용하지 않습니다. 인바운드 제한만으로 아웃바운드 클라이언트 위험을
낮추지 않으며, 우선순위 하향에는 해당 발견 사항의 최신 인바운드 서비스 공격 경로 근거도
필요합니다. 확인된 사실만 기록하세요.

```bash
python3 skills/aro/scripts/aro.py exposure --cgnat confirmed --public-ipv4 no --public-ipv6 no --inbound-forwarding no --tunnels no
```

## 구체적인 계획을 승인한 뒤 업데이트

현재 발견 사항과 정확한 목표 버전으로 계획을 만듭니다.

```bash
python3 skills/aro/scripts/aro.py plan --finding FINDING_ID --target-version VERSION
python3 skills/aro/scripts/aro.py apply --plan /path/to/plan.json --approve FULL_PLAN_HASH
```

실행 전 실제 계획의 정확한 인수, 목표, 의존성 영향, 작업 디렉터리, 소프트웨어
지도 해시, 만료 시각, 복구 한계를 확인하세요. 승인은 그 파일과 범위에 적용됩니다.
설치 상태가 달라졌거나 계획이 만료·변조되었다면 새 계획과 승인이 필요합니다.
자동 실행은 apt/apk, ARO를 실행하는 인터프리터·prefix의 pip(외부 prefix 패키지 거부), manifest/lockfile이 있는
명확한 최상위 직접 npm 의존성(중첩·별칭·workspace 거부), 검증된 정확한 WinGet ID로
제한합니다. apt/apk는 의존성 트랜잭션을 시뮬레이션하고 실행 직전에 다시 검증합니다. pip는 의존성을
변경하지 않고 미리 빌드된 wheel만 사용합니다. npm은 lifecycle script를 비활성화하지만
간접 의존성과 lockfile을 변경할 수 있습니다. dnf/RPM, 일반 Windows OS 업데이트,
컨테이너 등 미지원 대상은 수동 안내를 제공합니다. 계획은 30분 후 만료됩니다.
권고의 수정 버전이 저장소에 없거나 앱과 호환되지 않을 수 있으며, 자동 버전 비교는
지원하는 버전 형식으로 제한합니다.

실행 결과를 기록하고 성공 또는 부분 실패 후 다시 조사합니다. ARO가 자동으로 권한을
높이거나 별도의 서비스 재시작·재부팅을 실행하지는 않습니다. 다만 패키지/공급업체의
설치 훅이 **서비스를 재시작할 수 있으므로** 승인 범위에 의존성 변경과 중단 시간을
포함해야 합니다. 승인된 앱 상태 점검을 실행하기 전까지 서비스 정상 여부는 미확인입니다.
패키지 관리자의 성공 종료만으로 해결 완료를 판단하지 않습니다.

## 상태, 통신, 개인정보

상태는 스킬과 점검 대상 저장소 외부에 저장합니다.

- Linux: `${XDG_STATE_HOME:-~/.local/state}/aro`
- Windows: `%LOCALAPPDATA%/ARO` (없으면 `~/AppData/Local/ARO`)

자동 생성되는 `config.json`에서 경로, `exclude_packages` 패키지 이름 glob,
네트워크 관찰값, 캐시 수명, 탐색 한도를 설정할 수 있습니다. `config --show`로
확인하고 다른 변경은 유효한 JSON으로 편집하세요. 예시는
[작업 흐름](skills/aro/references/workflow.md)에 있습니다. 상태에는 현재 지도/보고서,
권고 캐시, 변경 불가 계획, 패치 실행 기록이 포함되므로 비공개로 보관하고 Git에
넣지 마세요.

점검은 로컬 메타데이터를 읽으며 설치된 소프트웨어와 앱 파일을 변경하지 않습니다.
권고 서비스에는 **패키지 이름과 버전**이 전달될 수 있지만 앱 소스나 자격 증명을
업로드하지 않습니다. 공개하면 안 되는 패키지 이름은 첫 온라인 점검 전에 제외하세요.
로컬 결과에는 경로와 소프트웨어 상세 정보가 포함될 수 있습니다.

에이전트의 웹 브라우저는 필요 없지만 스크립트에는 인터넷 또는 사용 가능한 캐시가
필요합니다. 오프라인·오래된 캐시·출처 실패는 데이터 시각과 점검 공백을 그대로
표시합니다. “확인된 일치 없음”은 조사한 범위의 결과이며 서버의 안전 보장이
아닙니다. 외부 라우터/방화벽 정책, 미지원 소프트웨어, 접근할 수 없는 위치는
알 수 없는 상태로 남을 수 있습니다.

개발과 검증은 [CONTRIBUTING.md](CONTRIBUTING.md), 보안 문제 제보는
[SECURITY.md](SECURITY.md), MIT 라이선스는 [LICENSE](LICENSE)를 참고하세요.
배포 가능한 스킬은 [`skills/aro`](skills/aro)에 있으며 Python 패키지로 설치할 필요가
없습니다.
