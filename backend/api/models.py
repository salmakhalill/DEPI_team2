import uuid
from django.db import models

class Scan(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_url = models.URLField(max_length=500)
    status = models.CharField(max_length=20, default='Running', choices=[
        ('Running', 'Running'),
        ('Completed', 'Completed'),
        ('Failed', 'Failed')
    ])
    overall_threat_level = models.CharField(max_length=20, blank=True, null=True)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(blank=True, null=True)
    
    # Store the final Master JSON report here when the scan finishes
    full_report_json = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"Scan {self.target_url} - {self.status}"

class ScanFinding(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='findings')
    vulnerability_id = models.CharField(max_length=50) # e.g., VULN-06
    title = models.CharField(max_length=200)
    risk_level = models.CharField(max_length=50)
    affected_path = models.TextField()
    
    # We can store the detailed finding JSON (description, PoC, evidence) here
    details = models.JSONField()
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.risk_level})"