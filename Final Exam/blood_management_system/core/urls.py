from django.contrib import admin
from django.urls import path, include, reverse_lazy
from django.views.generic import RedirectView

urlpatterns = [

    path('', RedirectView.as_view(url=reverse_lazy('login')), name='home'),

    path('admin/', admin.site.urls),

    # --- Template (Web) URLs ---
    path('', include('users.urls')),
    path('', include('blood.urls')),

    # --- API (DRF) URLs ---
    path('api/', include('users.api_urls')),
    path('api/', include('blood.api_urls')),
]