"""Google OAuth 服務模組。"""
import secrets
import time
from typing import Dict


class StateManager:
    """管理 OAuth state tokens (CSRF 防護)。

    簡單的 in-memory 實作，適合開發環境。
    生產環境建議使用 Redis。
    """

    def __init__(self, ttl: int = 300):
        """初始化 state manager。

        Args:
            ttl: State token 存活時間（秒），預設 5 分鐘
        """
        self._states: Dict[str, float] = {}
        self._ttl = ttl

    def create(self) -> str:
        """建立新的 state token。

        Returns:
            隨機產生的 state token
        """
        state = secrets.token_urlsafe(32)
        self._states[state] = time.time()
        return state

    def verify(self, state: str) -> bool:
        """驗證並消費 state token。

        Args:
            state: 要驗證的 state token

        Returns:
            True 如果 state 有效且未過期，否則 False
        """
        if state not in self._states:
            return False

        created_at = self._states.pop(state)

        # 檢查是否過期
        if time.time() - created_at > self._ttl:
            return False

        return True

    def cleanup(self):
        """清理過期的 state tokens。"""
        now = time.time()
        expired_keys = [
            key for key, created_at in self._states.items()
            if now - created_at > self._ttl
        ]
        for key in expired_keys:
            del self._states[key]


# Global state manager instance
state_manager = StateManager()
