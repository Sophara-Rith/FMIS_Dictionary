# dictionary/urls.py
from django.urls import path
from .views import (
    DictionaryDeleteView,
    DictionaryEntryListView,
    DictionaryEntryDetailView,
    DictionaryUpdateView,
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
    path('list', DictionaryEntryListView.as_view(), name='dictionary-entry-list'),
    path('detail', DictionaryEntryDetailView.as_view(), name='dictionary-entry-detail'),
    path('update', DictionaryUpdateView.as_view(), name='dictionary-update'),
    path('drop', DictionaryDeleteView.as_view(), name='dictionary-delete'),

    # Staging Entries Routes
    path('staging/list', StagingEntryListView.as_view(), name='staging-entry-list'),
    path('staging/create/', StagingEntryCreateView.as_view(), name='staging-entry-create'),
    path('staging/detail', StagingEntryDetailView.as_view(), name='staging-entry-detail'),

    # Updated routes with explicit id parameter
    path('staging/update', StagingEntryUpdateView.as_view(), name='staging-entry-update'),
    path('staging/drop', StagingEntryDeleteView.as_view(), name='staging-entry-delete'),
    path('staging/approve', StagingEntryApproveView.as_view(), name='staging-entry-approve'),
    path('staging/reject', StagingEntryRejectView.as_view(), name='staging-entry-reject'),

    path('bookmarks/', BookmarkView.as_view(), name='bookmarks'),

    path('sync_all', DictionarySyncAllView.as_view(), name='dictionary_sync_all'),
    path('sync', DictionarySyncView.as_view(), name='dictionary_sync'),

    path('search', DictionarySearchView.as_view(), name='dictionary-search'),

    path('staging/bulk_input/', StagingBulkImportView.as_view(), name='staging-bulk-import'),

    path('template', DictionaryTemplateDownloadView.as_view(), name='dictionary-template-download'),
]
