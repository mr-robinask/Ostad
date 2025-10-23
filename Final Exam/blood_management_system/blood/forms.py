from django import forms
from .models import DonationRecord, BloodRequest

class DonationRequestForm(forms.ModelForm):
    class Meta:
        model = DonationRecord
        fields = ['units_donated']
        labels = { 'units_donated': 'Units (bags) to Donate' }

class BloodRequestForm(forms.ModelForm):    
    class Meta:
        model = BloodRequest
        fields = ['requester_name', 'patient_name', 'blood_group', 'units_required']