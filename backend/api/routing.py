from django.urls import re_path
from . import consumers

# Define WebSocket endpoint routing for live scan telemetry
websocket_urlpatterns = [
    # Example URL format: ws://127.0.0.1:8000/ws/scan/<scan_id>/
    re_path(r'ws/scan/(?P<scan_id>[\w-]+)/$', consumers.ScanProgressConsumer.as_asgi()),
]