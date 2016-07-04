from django.db import models
from django.contrib.auth.models import User

class Alert(models.Model):
    alert_id = models.AutoField(primary_key=True)
    hostName = models.CharField(max_length=128)
    fileName = models.CharField(max_length=200)
    alertMessage = models.CharField(max_length=250)
    timeStamp = models.DateTimeField()
    created_by = models.ForeignKey(User, related_name='created_alert', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.hostName