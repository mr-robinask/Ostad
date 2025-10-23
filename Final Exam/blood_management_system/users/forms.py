from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser, DonorProfile

class DonorRegistrationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'email')

class DonorProfileForm(forms.ModelForm):
    class Meta:
        model = DonorProfile
        fields = ('blood_group', 'phone_number', 'location')

# --- NEW FORMS FOR UPDATING PROFILE ---

class UserUpdateForm(forms.ModelForm):    
    email = forms.EmailField()
    
    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email')

class ProfileUpdateForm(forms.ModelForm):    
    class Meta:
        model = DonorProfile
        fields = ('phone_number', 'location', 'blood_group', 'is_available')
