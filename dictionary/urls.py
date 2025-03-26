# dictionary/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import StagingDictionaryEntryViewSet, DictionaryEntryViewSet

router = DefaultRouter()
router.register(r'staging-entries', StagingDictionaryEntryViewSet, basename='staging-entry')
router.register(r'entries', DictionaryEntryViewSet, basename='dictionary-entry')

urlpatterns = [
    path('', include(router.urls)),
]
