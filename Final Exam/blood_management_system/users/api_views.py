from rest_framework import generics, permissions
from .serializers import UserRegistrationSerializer, DonorProfileSerializer
from .models import DonorProfile
from django_filters.rest_framework import DjangoFilterBackend

class UserRegisterAPIView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

class DonorSearchAPIView(generics.ListAPIView):    
    queryset = DonorProfile.objects.filter(is_available=True)
    serializer_class = DonorProfileSerializer
    permission_classes = [permissions.AllowAny]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['blood_group', 'location']