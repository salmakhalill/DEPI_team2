import time
import socket
import asyncio
import httpx
import ipaddress
from urllib.parse import urlparse
from engine.models.http_context import HttpResponse
from engine.core.scan_context import ScanContext

class AsyncSafeHttpClient:
    """
    Enterprise-grade asynchronous HTTP Client.
    Integrates with ScanContext for request budgeting and incorporates 
    SSRF protection to prevent internal network scanning by default.
    """

    def __init__(self, max_concurrent: int = 15, timeout: int = 10, delay: float = 0.0, context: ScanContext = None, allow_local: bool = False):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.delay = delay
        self.context = context or ScanContext(target_url="")
        self.allow_local = allow_local
        
        # Initialize the underlying httpx client with global configurations
        self.client = httpx.AsyncClient(
            timeout=self.timeout, 
            verify=False,
            cookies=self.context.cookies if self.context else {}
        )

    def _is_safe_url(self, url: str) -> bool:
        """
        Validates whether the target URL resolves to a public IP address.
        Prevents Server-Side Request Forgery (SSRF) into internal infrastructure.
        """
        if self.allow_local:
            return True
            
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False
                
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Reject private, loopback, link-local, and multicast addresses
            is_internal = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast
            return not is_internal
        except Exception:
            return False

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        """
        Executes an asynchronous HTTP request after validating the scan budget
        and verifying the destination URL against SSRF rules.
        """
        start_time = time.time()
        
        # 1. Enforce Request Budget (Stop scanning if limit is reached)
        if not self.context.consume_budget():
            return HttpResponse(
                success=False, 
                error_message="Scan Budget Exceeded or Timeout Reached. Request Aborted."
            )
            
        # 2. Enforce SSRF Protection
        if not self._is_safe_url(url):
            return HttpResponse(
                success=False, 
                error_message="SSRF Blocked: Destination host is restricted."
            )

        # 3. Execute the Request with Concurrency Control
        async with self.semaphore:
            if self.delay > 0:
                await asyncio.sleep(self.delay)
            
            try:
                response = await self.client.request(method, url, **kwargs)
                elapsed = time.time() - start_time
                
                # Normalize headers for case-insensitive processing downstream
                normalized_headers = {k.lower(): v for k, v in response.headers.items()}
                
                return HttpResponse(
                    success=True,
                    status_code=response.status_code,
                    text=response.text,
                    headers=normalized_headers,
                    elapsed_time=elapsed
                )
                
            except Exception as e:
                elapsed = time.time() - start_time
                return HttpResponse(
                    success=False,
                    error_message=f"Request Failed: {str(e)}",
                    elapsed_time=elapsed
                )
                
    async def close(self) -> None:
        """Gracefully terminates the HTTP connection pool."""
        await self.client.aclose()