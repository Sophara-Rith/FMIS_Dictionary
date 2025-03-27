# dictionary/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import StagingDictionaryEntryViewSet, DictionaryEntryViewSet, BookmarkView

router = DefaultRouter()
router.register(r'staging-entries', StagingDictionaryEntryViewSet, basename='staging-entry')
router.register(r'entries', DictionaryEntryViewSet, basename='dictionary-entry')

urlpatterns = [
    path('', include(router.urls)),
    path('bookmarks/', BookmarkView.as_view(), name='bookmarks'),
]
