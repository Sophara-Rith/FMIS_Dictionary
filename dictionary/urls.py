# dictionary/urls.py
from django.urls import path
from .views import (
    DictionaryEntryListView,
    DictionaryEntryDetailView,
    StagingEntryListView,
    StagingEntryCreateView,
    StagingEntryDetailView,
    StagingEntryUpdateView,
    StagingEntryDeleteView,
    StagingEntryApproveView,
    StagingEntryRejectView,
    BookmarkView,
    DictionarySyncAllView,
    DictionarySyncView,
    DictionarySearchView,
    StagingBulkImportView,
    ImportStatusView,
    DictionaryTemplateDownloadView
)

urlpatterns = [
    path('list/', DictionaryEntryListView.as_view(), name='dictionary-entry-list'),
    path('<int:pk>/', DictionaryEntryDetailView.as_view(), name='dictionary-entry-detail'),

    # Staging Entries Routes
    path('staging/list/', StagingEntryListView.as_view(), name='staging-entry-list'),
    path('staging/create/', StagingEntryCreateView.as_view(), name='staging-entry-create'),
    path('staging/<int:pk>/', StagingEntryDetailView.as_view(), name='staging-entry-detail'),
    path('staging/<int:pk>/update/', StagingEntryUpdateView.as_view(), name='staging-entry-update'),
    path('staging/<int:pk>/delete/', StagingEntryDeleteView.as_view(), name='staging-entry-delete'),

    # Staging Entry Approval Routes
    path('staging/<int:pk>/approve/', StagingEntryApproveView.as_view(), name='staging-entry-approve'),
    path('staging/<int:pk>/reject/', StagingEntryRejectView.as_view(), name='staging-entry-reject'),

    path('bookmarks/', BookmarkView.as_view(), name='bookmarks'),

    path('sync_all/', DictionarySyncAllView.as_view(), name='dictionary_sync_all'),
    path('sync/', DictionarySyncView.as_view(), name='dictionary_sync'),

    path('search/', DictionarySearchView.as_view(), name='dictionary-search'),

    path('staging/bulk_import/', StagingBulkImportView.as_view(), name='staging-bulk-import'),
    path('staging/import_status/<str:task_id>/', ImportStatusView.as_view(), name='import-status'),

    path('template/', DictionaryTemplateDownloadView.as_view(), name='dictionary-template-download')
]
