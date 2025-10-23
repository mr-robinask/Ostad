from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/admin/', views.AdminDashboardView.as_view(), name='dashboard-admin'),
    path('dashboard/donor/', views.DonorDashboardView.as_view(), name='dashboard-donor'),

    # Admin action URLs
    path('donation/update/<int:pk>/<str:status>/', views.UpdateDonationStatusView.as_view(), name='update-donation-status'),
    path('request/update/<int:pk>/<str:status>/', views.UpdateRequestStatusView.as_view(), name='update-request-status'),
]