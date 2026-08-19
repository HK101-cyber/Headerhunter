"""Configuration management."""
from dataclasses import dataclass

@dataclass
class Config:
    threads: int = 10
    timeout: float = 15.0
    follow_redirects: bool = False
    verify_tls: bool = True
    user_agent: str = "HTTPHeaderHunter/1.1.0"
