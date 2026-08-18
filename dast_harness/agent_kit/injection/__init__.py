"""injection 에이전트. **이 폴더만 떼어내면 그대로 옮겨진다.**

공용 계약(`..contract`, `..base`, `..http`) 외에는 아무것도 의존하지 않는다 —
recon이나 idor을 import하지 않는다.

    from dast_harness.agent_kit.injection import InjectionAgent

고칠 곳: 페이로드와 오류 시그니처는 `payloads.py`, 판정 로직은 `agent.py`.
자세한 건 이 폴더의 README.md.
"""

from .agent import InjectionAgent
from .payloads import PROBES, SQL_ERROR_SIGNATURES, Probe

__all__ = ["InjectionAgent", "PROBES", "SQL_ERROR_SIGNATURES", "Probe"]
