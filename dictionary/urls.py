# dictionary/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import DictionaryViewSet

router = DefaultRouter()
router.register(r'', DictionaryViewSet, basename='dictionary')

urlpatterns = [
    path('', include(router.urls)),
    path('sync/', DictionaryViewSet.as_view({'get': 'sync_all'}), name='dictionary-sync'),
]
