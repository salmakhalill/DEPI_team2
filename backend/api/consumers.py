import json
from channels.generic.websocket import AsyncWebsocketConsumer

class ScanProgressConsumer(AsyncWebsocketConsumer):
    """
    Handles real-time WebSocket connections.
    Receives logs from the running Python Thread and pushes them to the React frontend.
    """
    
    async def connect(self):
        # Extract the scan ID from the URL to create a unique room
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.room_group_name = f'scan_{self.scan_id}'

        # Join the unique memory channel group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Clean up the memory group when the scan finishes or user disconnects
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def scan_telemetry(self, event):
        """
        Handler triggered by the Orchestrator thread using async_to_sync.
        """
        message = event['message']

        # Push the live log to the React dashboard
        await self.send(text_data=json.dumps({
            'message': message
        }))