from rest_framework import serializers
from .models import CustomUser, DonorProfile

class DonorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DonorProfile
        fields = ['blood_group', 'phone_number', 'location', 'is_available']
        extra_kwargs = {
            'blood_group': {'required': True},
            'phone_number': {'required': True},
        }

class UserSerializer(serializers.ModelSerializer):
    profile = DonorProfileSerializer()

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'profile']

class UserRegistrationSerializer(serializers.ModelSerializer):
    profile = DonorProfileSerializer(required=True)
    
    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'email', 'first_name', 'last_name', 'profile']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        profile_data = validated_data.pop('profile')
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data.get('email', ''),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            role=CustomUser.Role.DONOR
        )
        DonorProfile.objects.create(user=user, **profile_data)
        return user