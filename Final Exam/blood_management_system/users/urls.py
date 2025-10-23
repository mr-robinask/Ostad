from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', views.CustomLogoutView.as_view(), name='logout'),
    path('register/', views.RegisterDonorView.as_view(), name='register'),
    
    # This URL is the main redirect after login
    path('dashboard-redirect/', views.DashboardRedirectView.as_view(), name='dashboard-redirect'),
    path('profile/update/', views.UpdateProfileView.as_view(), name='update-profile'),
]