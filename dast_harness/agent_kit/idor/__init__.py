"""IDOR 에이전트. **이 폴더만 떼어내면 그대로 옮겨진다.**

공용 계약(`..contract`, `..base`, `..http`) 외에는 아무것도 의존하지 않는다 —
recon이나 injection을 import하지 않는다.

    from dast_harness.agent_kit.idor import IdorAgent

고칠 곳: id를 어떻게 바꿔볼지는 `strategies.py`, 판정 로직은 `agent.py`.
자세한 건 이 폴더의 README.md.
"""

from .agent import IdorAgent
from .strategies import STRATEGIES, Candidate, candidates_for

__all__ = ["IdorAgent", "STRATEGIES", "Candidate", "candidates_for"]
