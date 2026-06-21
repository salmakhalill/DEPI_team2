from django.urls import path
from .views import StartScanView, DownloadReportView

urlpatterns = [
    path('scan/start/', StartScanView.as_view(), name='start_scan'),
    path('scan/<uuid:scan_id>/report/', DownloadReportView.as_view(), name='download_report'),
]