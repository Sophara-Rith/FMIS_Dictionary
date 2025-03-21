from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

# Swagger/OpenAPI Schema Configuration
schema_view = get_schema_view(
   openapi.Info(
      title="Dictionary API",
      default_version='v1',
      description="Dictionary API Documentation",
      terms_of_service="#",
      contact=openapi.Contact(email="contact@example.com"),
      license=openapi.License(name="Project License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # Admin site
    path('admin/', admin.site.urls),

    # User-related URLs
    path('api/users/', include('users.urls')),

    # Dictionary-related URLs
    path('api/dictionary/', include('dictionary.urls')),

    # JWT Token URLs
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Swagger/OpenAPI Documentation URLs
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
