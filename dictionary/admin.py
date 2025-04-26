# dictionary/admin.py
from django.contrib import admin
from .models import Staging, Dictionary, ActivityLog

@admin.register(Staging)
class StagingEntryAdmin(admin.ModelAdmin):
    list_display = [
        'word_kh', 'word_en',
        'word_kh_type', 'word_en_type',
        'review_status',
        'created_at', 'created_by',
    ]
    list_filter = [
        'review_status',
        'word_kh_type',
        'word_en_type',
    ]
    search_fields = ['word_kh', 'word_en', 'rejection_reason']

@admin.register(Dictionary)
class DictionaryEntryAdmin(admin.ModelAdmin):
    list_display = [
        'word_kh', 'word_en',
        'word_kh_type', 'word_en_type',
        'created_at', 'created_by'
    ]
    list_filter = [
        'word_kh_type',
        'word_en_type'
    ]
    search_fields = ['word_kh', 'word_en']

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ['username_kh', 'action', 'role', 'timestamp', 'word_kh', 'word_en']
    list_filter = ['action', 'role', 'timestamp']
    search_fields = ['username_kh', 'word_kh', 'word_en']
