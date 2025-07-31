from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created and not hasattr(instance, 'userprofile'):
        # Only create UserProfile if not created by registration view
        # Check if raw=False to exclude fixtures or bulk operations
        if not kwargs.get('raw', False):
            UserProfile.objects.create(user=instance, user_type='applicant')  # Default to 'applicant'