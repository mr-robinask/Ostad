from django.contrib import admin
from .models import Job, Application, UserProfile

@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ('title', 'company_name', 'location', 'posted_by', 'created_at')

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ('job', 'applicant', 'applied_at', 'status')

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role')