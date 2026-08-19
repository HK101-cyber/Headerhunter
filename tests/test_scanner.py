import asyncio, httpx
from unittest.mock import AsyncMock, patch
from headerhunter.scanner import scan_targets
from headerhunter.config import Config
class MockResponse:
    def __init__(self, status_code=200, headers=None, url="http://example.com"):
        self.status_code, self.headers, self.url = status_code, headers or {}, url
def test_scanner_success_mock():
    with patch("headerhunter.scanner.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = MockResponse(200, {"Server": "Apache"}, "http://example.com")
        mock_client.return_value.__aenter__.return_value = mock_instance
        results = asyncio.run(scan_targets(["http://example.com"], {"rules": [{"name": "Server", "severity": "LOW", "check": "present"}]}, Config()))
        assert results[0].status_code == 200 and len(results[0].findings) == 1
def test_scanner_connection_failure():
    with patch("headerhunter.scanner.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client.return_value.__aenter__.return_value = mock_instance
        results = asyncio.run(scan_targets(["http://fail.com"], {}, Config()))
        assert results[0].error == "Connection error"
def test_scanner_result_order():
    with patch("headerhunter.scanner.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        async def mock_get(url):
            await asyncio.sleep(0.01 if "second" in url else 0.02)
            return MockResponse(url=url)
        mock_instance.get.side_effect = mock_get
        mock_client.return_value.__aenter__.return_value = mock_instance
        results = asyncio.run(scan_targets(["http://first", "http://second"], {}, Config(threads=2)))
        assert results[0].url == "http://first" and results[1].url == "http://second"
