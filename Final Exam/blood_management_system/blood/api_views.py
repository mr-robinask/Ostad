from rest_framework import viewsets, permissions
from .models import BloodRequest, DonationRecord, CustomUser
from .serializers import BloodRequestSerializer, DonationRecordSerializer

class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.role == CustomUser.Role.ADMIN

class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.role == CustomUser.Role.ADMIN:
            return True
        return obj.donor == request.user

class BloodRequestViewSet(viewsets.ModelViewSet):
    queryset = BloodRequest.objects.all()
    serializer_class = BloodRequestSerializer
    permission_classes = [IsAdminOrReadOnly] # Only admins can create/edit

class DonationRecordViewSet(viewsets.ModelViewSet):
    serializer_class = DonationRecordSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def get_queryset(self):
        if self.request.user.role == CustomUser.Role.ADMIN:
            return DonationRecord.objects.all()
        return DonationRecord.objects.filter(donor=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(donor=self.request.user)