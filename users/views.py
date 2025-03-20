import logging
from rest_framework import viewsets, permissions, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .serializers import UserSerializer, LoginSerializer, UserManagementSerializer

security_logger = logging.getLogger('security')

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action in ['create', 'list']:
            permission_classes = [permissions.IsAdminUser]
        elif self.action in ['retrieve', 'update', 'partial_update']:
            permission_classes = [permissions.IsAuthenticated]
        else:
            permission_classes = [permissions.IsAdminUser]
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.action in ['list', 'retrieve', 'update', 'partial_update']:
            return UserManagementSerializer
        return UserSerializer

    @action(detail=False, methods=['POST'], permission_classes=[permissions.AllowAny])
    def login(self, request, username):
        serializer = LoginSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            security_logger.info(f"Successful login: {username}")
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)

        except serializers.ValidationError as e:
            # Custom error handling for login failures
            security_logger.warning(f"Failed login attempt: {username}")
            return Response({
                'error': str(e.detail[0]),
                'status': 'failed'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['POST'], permission_classes=[permissions.IsAdminUser])
    def reset_login_attempts(self, request, pk=None):
        user = self.get_object()

        # Only admins can reset login attempts
        if request.user.role in ['ADMIN', 'SUPERUSER']:
            user.reset_login_attempts()
            return Response({
                'detail': 'Login attempts reset successfully.',
                'login_attempts': user.login_attempts
            }, status=status.HTTP_200_OK)

        return Response({
            'detail': 'Not authorized to reset login attempts.'
        }, status=status.HTTP_403_FORBIDDEN)

    @action(detail=True, methods=['POST'], permission_classes=[permissions.IsAdminUser])
    def suspend(self, request, pk=None):
        user = self.get_object()
        reason = request.data.get('reason', 'No reason provided')

        # Only admins can suspend users with lower or equal roles
        if request.user.role == 'SUPERUSER' or (request.user.role == 'ADMIN' and user.role == 'USER'):
            user.suspend_user(reason, request.user)
            return Response({'detail': 'User suspended successfully.'}, status=status.HTTP_200_OK)

        return Response({'detail': 'Not authorized to suspend this user.'}, status=status.HTTP_403_FORBIDDEN)

    @action(detail=True, methods=['POST'], permission_classes=[permissions.IsAdminUser])
    def unsuspend(self, request, pk=None):
        user = self.get_object()

        # Only admins can unsuspend users
        if request.user.role in ['ADMIN', 'SUPERUSER']:
            user.unsuspend_user()
            return Response({'detail': 'User unsuspended successfully.'}, status=status.HTTP_200_OK)

        return Response({'detail': 'Not authorized to unsuspend this user.'}, status=status.HTTP_403_FORBIDDEN)
