from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import api_views

router = DefaultRouter()
router.register(r'requests', api_views.BloodRequestViewSet)
router.register(r'donations', api_views.DonationRecordViewSet, basename='donation')

urlpatterns = [
    path('', include(router.urls)),
]