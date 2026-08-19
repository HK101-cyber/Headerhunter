"""Async HTTP scanner."""
import asyncio
import httpx
from typing import List, Dict, Any
from headerhunter.models import ScanResult
from headerhunter.analyzer import analyze_headers
from headerhunter.config import Config

async def scan_targets(urls: List[str], rules: Dict[str, Any], config: Config) -> List[ScanResult]:
    results = [ScanResult(url=url) for url in urls]
    sem = asyncio.Semaphore(config.threads)
    limits = httpx.Limits(max_connections=config.threads, max_keepalive_connections=config.threads)
    async with httpx.AsyncClient(http2=True, verify=config.verify_tls, follow_redirects=config.follow_redirects, timeout=config.timeout, limits=limits, headers={"User-Agent": config.user_agent}) as client:
        async def process(i, url):
            async with sem:
                try:
                    r = await client.get(url)
                    res = results[i]
                    res.status_code, res.final_url, res.headers = r.status_code, str(r.url), dict(r.headers)
                    res.findings = analyze_headers(res.headers, rules)
                except httpx.ConnectTimeout: results[i].error = "Connection timeout"
                except httpx.ReadTimeout: results[i].error = "Read timeout"
                except httpx.ConnectError: results[i].error = "Connection error"
                except httpx.HTTPError as e: results[i].error = f"HTTP error: {type(e).__name__}"
                except Exception as e: results[i].error = f"Unexpected error: {type(e).__name__}"
        await asyncio.gather(*[asyncio.create_task(process(i, u)) for i, u in enumerate(urls)])
    return results
