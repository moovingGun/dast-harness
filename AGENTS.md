# AGENTS.md

AI 코딩 도구용 진입점. 사람도 읽어도 된다.
**내용을 여기 복사하지 않는다** — 두 벌이 되면 반드시 어긋난다. 아래 파일을 읽어라.

## 이 저장소에서 작업하기 전에 읽을 것

| 무엇을 하려는가 | 읽을 것 |
|---|---|
| **Python 에이전트**를 만든다 (`Agent` 상속) | **[AGENT_GUIDE.md](AGENT_GUIDE.md)** — 이것만 보고 시작할 수 있다 |
| **Claude 서브에이전트**를 만든다 (마크다운 + skill) | **[SUBAGENT_GUIDE.md](SUBAGENT_GUIDE.md)** — `probe`/`ingest` 사용법 |
| 그 밖의 모든 작업 | [CLAUDE.md](CLAUDE.md) — 저장소 작업 규칙 |
| 전체 구조·구현 상태 | [README.md](README.md) |

## 어기면 리뷰에서 되돌려지는 것 세 개

전문은 [CLAUDE.md](CLAUDE.md)에 있다. 이 셋만 미리 알아둬라.

1. **HTTP 요청을 직접 만들지 않는다.** `requests` / `httpx` / `urllib.request` 금지이고,
   서브에이전트라면 `curl` / `nmap` / `ffuf`도 금지다. Python은
   `dast_harness.agent_kit.AgentHttpClient`, 서브에이전트는 `dast-harness probe`만 쓴다. 이유: 에이전트는 타겟의 응답을
   읽고 다음 URL을 정하므로, 타겟 페이지에 심어진 지시를 따라 허가 범위 밖으로
   나갈 수 있다. 클라이언트가 매 요청 대상을 검증한다.
2. **`dast_harness/safety.py`를 수정하지 않는다.** 이 프로젝트의 유일한 안전
   경계다. 새 도구는 우회하지 말고 통과시킨다.
3. **결과 형식 계약을 지킨다.** `AgentFinding`/`AgentResult`를 쓰고
   `Agent.finish()`로 마무리한다. 위반하면 `AssertionError`가 난다.

## 확인 방법

```bash
python3 -m unittest discover -s tests    # 저장소 루트에서. 도커·스캐너 불필요
```

`pip install -e .`은 쓰지 않는다. 스크립트를 따로 돌릴 때는 `PYTHONPATH=.`를 붙인다.
