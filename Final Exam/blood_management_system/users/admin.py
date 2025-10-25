from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, DonorProfile

class DonorProfileInline(admin.StackedInline):
    model = DonorProfile
    can_delete = False
    verbose_name_plural = 'Donor Profile'

class CustomUserAdmin(UserAdmin):    
    inlines = (DonorProfileInline,)
    model = CustomUser
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'is_staff')
    
    # Add 'role' to the fieldsets
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('role',)}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('role',)}),
    )

admin.site.register(CustomUser, CustomUserAdmin)