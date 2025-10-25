from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Admin"
        DONOR = "DONOR", "Donor"

    role = models.CharField(max_length=50, choices=Role.choices, default=Role.DONOR)
    date_joined = models.DateTimeField(auto_now_add=True)

class DonorProfile(models.Model):
    BLOOD_GROUPS = [
        ('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'),
        ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-'),
    ]
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name="profile")
    blood_group = models.CharField(max_length=3, choices=BLOOD_GROUPS)
    phone_number = models.CharField(max_length=15)
    location = models.CharField(max_length=100, blank=True)
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} ({self.blood_group})"