from django.urls import path
from .views import (
    UserLoginView,
    UserRegisterView,
    UserDropView,
    UserUpdateView,
    UserListView,
    UserDetailView,
    MobileLoginView
)

urlpatterns = [
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('register/', UserRegisterView.as_view(), name='user-register'),

    path('drop/', UserDropView.as_view(), name='user-drop'),
    path('update/', UserUpdateView.as_view(), name='user-update'),
    path('list/', UserListView.as_view(), name='user-list'),
    path('detail/', UserDetailView.as_view(), name='user-detail'),

    path('mobile/login/', MobileLoginView.as_view(), name='mobile_login'),
]
