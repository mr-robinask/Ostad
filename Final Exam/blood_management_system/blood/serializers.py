from rest_framework import serializers
from .models import BloodRequest, DonationRecord

class BloodRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = BloodRequest
        fields = '__all__'

class DonationRecordSerializer(serializers.ModelSerializer):
    donor_username = serializers.CharField(source='donor.username', read_only=True)
    
    class Meta:
        model = DonationRecord
        fields = ['id', 'donor', 'donor_username', 'units_donated', 'status', 'created_at']
        read_only_fields = ['donor']