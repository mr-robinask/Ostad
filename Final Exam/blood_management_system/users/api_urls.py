from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import api_views

urlpatterns = [
    path('register/', api_views.UserRegisterAPIView.as_view(), name='api-register'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # API endpoint for searching donors
    path('donors/search/', api_views.DonorSearchAPIView.as_view(), name='api-donor-search'),
]