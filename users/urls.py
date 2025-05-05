# users/urls.py
from django.urls import path
from .views import (
    ChangePasswordView,
    UserActivityLogView,
    UserLoginView,
    UserRegisterView,
    UserDropView,
    UserUpdateView,
    UserListView,
    UserDetailView,
    MobileLoginView,
    UserCommentView
)
#####################
urlpatterns = [
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('register/', UserRegisterView.as_view(), name='user-register'),

    path('drop', UserDropView.as_view(), name='user-drop'),
    path('update', UserUpdateView.as_view(), name='user-update'),
    path('list', UserListView.as_view(), name='user-list'),
    path('detail', UserDetailView.as_view(), name='user-detail'),

    path('mobile/login/', MobileLoginView.as_view(), name='mobile_login'),
    path('comment/', UserCommentView.as_view(), name='user-comment'),

    path('activity-log', UserActivityLogView.as_view(), name='user-activity-logs'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),

]
