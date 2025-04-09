# users/urls.py
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import (
    UserLoginView,
    UserRegisterView,
    UserDropView,
    UserUpdateView,
    UserListView,
    UserDetailView,
    MobileLoginView,
    PublicTestEndpoint,
    UserCommentSubmitView,
    UserCommentListView
)

urlpatterns = [
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('register/', UserRegisterView.as_view(), name='user-register'),

    path('drop/', UserDropView.as_view(), name='user-drop'),
    path('update/', UserUpdateView.as_view(), name='user-update'),
    path('list/', UserListView.as_view(), name='user-list'),
    path('detail/', UserDetailView.as_view(), name='user-detail'),

    path('mobile/login/', MobileLoginView.as_view(), name='mobile_login'),
    # path('mobile/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('test/', PublicTestEndpoint.as_view(), name='public_test'),

    path('comments/submit/', UserCommentSubmitView.as_view(), name='submit_comment'),
    path('comments/', UserCommentListView.as_view(), name='list_comments'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
