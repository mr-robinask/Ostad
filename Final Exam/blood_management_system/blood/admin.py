from django.contrib import admin
from .models import BloodRequest, DonationRecord

@admin.register(BloodRequest)
class BloodRequestAdmin(admin.ModelAdmin):
    list_display = ('patient_name', 'blood_group', 'units_required', 'status', 'created_at')
    list_filter = ('status', 'blood_group')
    search_fields = ('patient_name', 'requester_name')
    list_editable = ('status',)

@admin.register(DonationRecord)
class DonationRecordAdmin(admin.ModelAdmin):
    list_display = ('donor', 'units_donated', 'status', 'created_at')
    list_filter = ('status', 'donor__profile__blood_group')
    search_fields = ('donor__username',)
    list_editable = ('status',)