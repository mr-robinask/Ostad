from django.db import models
from users.models import CustomUser, DonorProfile

class BloodRequest(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    )
    requester_name = models.CharField(max_length=100, help_text="Hospital or individual's name")
    patient_name = models.CharField(max_length=100)
    blood_group = models.CharField(max_length=3, choices=DonorProfile.BLOOD_GROUPS)
    units_required = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Request for {self.patient_name} ({self.blood_group})"

class DonationRecord(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    )
    donor = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="donations")
    units_donated = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.donor.username} - {self.status}"