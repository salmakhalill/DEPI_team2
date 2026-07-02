import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import api.routing 

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Initialize standard Django HTTP application
django_asgi_app = get_asgi_application()

# Route traffic based on the protocol type (HTTP vs WebSockets)
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(
            api.routing.websocket_urlpatterns
        )
    ),
})