# views.py (authentication section)
from urllib import request
from django.http import HttpResponse
from rest_framework import status, viewsets, permissions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import logout
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth import get_user_model
from django.db.models import Q, Count
import uuid
import logging
from rest_framework.parsers import MultiPartParser, JSONParser
import pandas as pd
from io import BytesIO
import openpyxl
from rest_framework.views import APIView
from django.db.models import Count, Sum, Q, F, FloatField, Value
from django.db.models.functions import Coalesce, Cast
from .models import *
from .serializers import *

logger = logging.getLogger(__name__)
User = get_user_model()

# ==================== AUTHENTICATION VIEWS ====================
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import permissions

class LoginView(APIView):
    permission_classes = [permissions.AllowAny] 
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            # Log failed login attempt
            email = request.data.get('email', 'unknown')
            AuditLog.objects.create(
                event_type='USER_LOGIN',
                username=email,
                table_name='auth_user',  # ADD THIS
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4(),
                new_values={'email': email, 'status': 'failed'},
                operation='INSERT'  # ADD THIS
            )

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = serializer.validated_data['user']
       
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # Create user session - FIXED expires_at
        session = UserSession.objects.create(
            user=user,
            access_token=access_token,
            refresh_token=refresh_token,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            device_fingerprint=request.META.get('HTTP_USER_AGENT', '')[:64],
            expires_at=timezone.datetime.fromtimestamp(refresh.access_token.payload['exp'])  # Fixed
        )


      
        
        # Log successful login
        AuditLog.objects.create(
            event_type='USER_LOGIN',
            user=user,
            username=user.username,
            user_role=user.role,
            table_name='auth_user',  # ADD THIS
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4(),
            new_values={'email': user.email, 'status': 'success', 'role': user.role},
            operation='INSERT'  # ADD THIS
        )

        
        # Send notification if it's first login or unusual location
        if user.last_login is None:
            Notification.objects.create(
                notification_type='FIRST_LOGIN',
                title='Welcome to the System',
                message=f'Welcome {user.get_full_name()}! This is your first login.',
                recipient_type='User',
                recipient_id=user.id,
                priority='Normal',
                sent_by=user
            )
        
         # Return response
        return Response({
            'access': access_token,
            'refresh': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,  # Make sure your User model has a role field
                'phone': user.phone if hasattr(user, 'phone') else None,
            },
            'session_id': session.id
        }, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        refresh_token = serializer.validated_data['refresh_token']
        
        try:
            # Revoke the session
            session = UserSession.objects.get(
                refresh_token=refresh_token,
                user=request.user,
                revoked=False
            )
            session.revoked = True
            session.save()
            
            # Add token to blacklist
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass  # Token might already be blacklisted
            
            # Log logout
            AuditLog.objects.create(
                event_type='USER_LOGOUT',
                user=request.user,
                username=request.user.username,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4(),
                operation='DELETE'
            )
            
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
        except UserSession.DoesNotExist:
            return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)

class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        refresh_token = serializer.validated_data['refresh_token']
        
        try:
            # Verify session exists and is not revoked
            session = UserSession.objects.get(
                refresh_token=refresh_token,
                revoked=False,
                expires_at__gt=timezone.now()
            )
            
            # Refresh the token
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            
            # Update session
            session.access_token = new_access_token
            session.expires_at = refresh.access_token.payload['exp']
            session.save()
            
            return Response({
                'token': new_access_token,
                'refresh_token': str(refresh)
            }, status=status.HTTP_200_OK)
            
        except (UserSession.DoesNotExist, TokenError):
            return Response(
                {'error': 'Invalid or expired refresh token'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class ValidateTokenView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        # Get user session
        token = request.auth
        if not token:
            return Response({'error': 'No token provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Verify session exists and is not revoked
            session = UserSession.objects.get(
                access_token=str(token),
                revoked=False,
                expires_at__gt=timezone.now()
            )
            
            # Update last activity
            session.last_activity = timezone.now()
            session.save()
            
            user_data = UserSerializer(request.user).data
            return Response({'user': user_data}, status=status.HTTP_200_OK)
            
        except UserSession.DoesNotExist:
            return Response(
                {'error': 'Invalid or expired session'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.last_password_change = timezone.now()
        user.save()
        
        # Log password change
        from .models import PasswordHistory
        PasswordHistory.objects.create(
            user=user,
            password_hash=user.password,
            changed_by=user
        )
        
        # Log audit
        AuditLog.objects.create(
            event_type='USER_UPDATE',
            user=user,
            username=user.username,
            table_name='auth_user',
            record_id=user.id,
            operation='UPDATE',
            changed_fields=['password'],
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        # Revoke all other sessions for security
        UserSession.objects.filter(user=user, revoked=False).update(revoked=True)
        
        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)

# ==================== USER MANAGEMENT VIEWS ====================
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return super().get_serializer_class()
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Log user creation
        AuditLog.objects.create(
            event_type='USER_CREATE',
            user=request.user,
            username=request.user.username,
            table_name='auth_user',
            record_id=user.id,
            operation='INSERT',
            new_values={
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'created_by': request.user.username
            },
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        headers = self.get_success_headers(serializer.data)
        return Response(
            UserSerializer(user).data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def profile(self, request):
        serializer = ProfileSerializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['put'])
    def update_profile(self, request):
        serializer = ProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        AuditLog.objects.create(
            event_type='USER_UPDATE',
            user=request.user,
            username=request.user.username,
            table_name='auth_user',
            record_id=request.user.id,
            operation='UPDATE',
            changed_fields=list(request.data.keys()),
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        user = self.get_object()
        
        # Prevent self-deactivation
        if user == request.user:
            return Response(
                {'error': 'Cannot deactivate your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.is_active = False
        user.save()
        
        # Revoke all active sessions
        UserSession.objects.filter(user=user, revoked=False).update(revoked=True)
        
        AuditLog.objects.create(
            event_type='USER_UPDATE',
            user=request.user,
            username=request.user.username,
            table_name='auth_user',
            record_id=user.id,
            operation='UPDATE',
            changed_fields=['is_active'],
            new_values={'is_active': False},
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        return Response({'message': 'User deactivated successfully'})
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        user = self.get_object()
        user.is_active = True
        user.save()
        
        AuditLog.objects.create(
            event_type='USER_UPDATE',
            user=request.user,
            username=request.user.username,
            table_name='auth_user',
            record_id=user.id,
            operation='UPDATE',
            changed_fields=['is_active'],
            new_values={'is_active': True},
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        return Response({'message': 'User activated successfully'})
    
    @action(detail=False, methods=['get'])
    def by_role(self, request):
        role = request.query_params.get('role')
        if not role:
            return Response({'error': 'Role parameter required'}, status=400)
        
        users = User.objects.filter(role=role, is_active=True)
        serializer = self.get_serializer(users, many=True)
        return Response(serializer.data)

# ==================== IP WHITELIST VIEWS ====================
class IPWhitelistViewSet(viewsets.ModelViewSet):
    queryset = IPWhitelist.objects.all()
    serializer_class = IPWhitelistSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
        
        AuditLog.objects.create(
            event_type='CONFIG_CHANGE',
            user=self.request.user,
            username=self.request.user.username,
            table_name='IPWhitelist',
            operation='INSERT',
            new_values=serializer.data,
            ip_address=self.request.META.get('REMOTE_ADDR'),
            endpoint=self.request.path,
            http_method=self.request.method,
            request_id=uuid.uuid4()
        )
    
    def perform_update(self, serializer):
        old_instance = self.get_object()
        serializer.save()
        
        AuditLog.objects.create(
            event_type='CONFIG_CHANGE',
            user=self.request.user,
            username=self.request.user.username,
            table_name='IPWhitelist',
            record_id=old_instance.id,
            operation='UPDATE',
            old_values=IPWhitelistSerializer(old_instance).data,
            new_values=serializer.data,
            changed_fields=list(serializer.validated_data.keys()),
            ip_address=self.request.META.get('REMOTE_ADDR'),
            endpoint=self.request.path,
            http_method=self.request.method,
            request_id=uuid.uuid4()
        )
    
    @action(detail=True, methods=['post'])
    def toggle_status(self, request, pk=None):
        ip_entry = self.get_object()
        ip_entry.status = 'Active' if ip_entry.status != 'Active' else 'Inactive'
        ip_entry.save()
        
        AuditLog.objects.create(
            event_type='CONFIG_CHANGE',
            user=request.user,
            username=request.user.username,
            table_name='IPWhitelist',
            record_id=ip_entry.id,
            operation='UPDATE',
            changed_fields=['status'],
            new_values={'status': ip_entry.status},
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        return Response({'status': ip_entry.status})

# ==================== SESSION MANAGEMENT VIEWS ====================
class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Admins can see all sessions, users can only see their own
        if self.request.user.is_staff or self.request.user.role == 'system_admin':
            return UserSession.objects.filter(revoked=False).order_by('-login_time')
        return UserSession.objects.filter(user=self.request.user, revoked=False).order_by('-login_time')
    
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        session = self.get_object()
        
        # Check permissions
        if session.user != request.user and not (request.user.is_staff or request.user.role == 'system_admin'):
            return Response(
                {'error': 'You can only revoke your own sessions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        session.revoked = True
        session.save()
        
        AuditLog.objects.create(
            event_type='USER_LOGOUT',
            user=request.user,
            username=request.user.username,
            table_name='UserSession',
            record_id=session.id,
            operation='UPDATE',
            changed_fields=['revoked'],
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        return Response({'message': 'Session revoked successfully'})
    
    @action(detail=False, methods=['post'])
    def revoke_all(self, request):
        user_id = request.data.get('user_id')
        
        if user_id:
            # Revoke all sessions for specific user (admin only)
            if not (request.user.is_staff or request.user.role == 'system_admin'):
                return Response(
                    {'error': 'Permission denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
            sessions = UserSession.objects.filter(user_id=user_id, revoked=False)
            user = User.objects.get(id=user_id)
            username = user.username
        else:
            # Revoke all sessions for current user
            sessions = UserSession.objects.filter(user=request.user, revoked=False)
            username = request.user.username
        
        sessions.update(revoked=True)
        
        AuditLog.objects.create(
            event_type='USER_LOGOUT',
            user=request.user,
            username=request.user.username,
            table_name='UserSession',
            operation='UPDATE',
            new_values={'sessions_revoked': sessions.count(), 'user': username},
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        return Response({'message': f'{sessions.count()} sessions revoked'})

# ==================== DASHBOARD VIEWS ====================
class DashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        from django.db.models import Count, Q
        from datetime import datetime, timedelta
        
        user = request.user
        
        # Base statistics
        stats = {
            'total_students': 0,
            'total_teachers': 0,
            'total_staff': 0,
            'total_parents': 0,
            'active_sessions': 0,
            'pending_invoices': 0,
            'today_attendance': 0,
            'recent_activities': []
        }
        
        # Get counts based on user role
        if user.role in ['system_admin', 'principal', 'registrar']:
            stats['total_students'] = Student.objects.filter(status='Active', archived=False).count()
            stats['total_teachers'] = User.objects.filter(role='teacher', is_active=True).count()
            stats['total_staff'] = Staff.objects.filter(status='Active').count()
            stats['total_parents'] = Parent.objects.filter(is_active=True).count()
        elif user.role == 'teacher':
            # Teacher sees their class students
            from .models import ClassSubjectAllocation
            teacher_classes = ClassSubjectAllocation.objects.filter(
                teacher=user
            ).values_list('class_id', flat=True)
            stats['total_students'] = Student.objects.filter(
                current_class_id__in=teacher_classes,
                status='Active',
                archived=False
            ).count()
        
        # Active sessions (user's own sessions or all for admin)
        if user.role in ['system_admin', 'principal']:
            stats['active_sessions'] = UserSession.objects.filter(
                revoked=False,
                expires_at__gt=timezone.now()
            ).count()
        else:
            stats['active_sessions'] = UserSession.objects.filter(
                user=user,
                revoked=False,
                expires_at__gt=timezone.now()
            ).count()
        
        # Recent activities
        recent_activities = AuditLog.objects.all().order_by('-event_time')[:10]
        stats['recent_activities'] = [
            {
                'time': activity.event_time.strftime('%Y-%m-%d %H:%M'),
                'event': activity.get_event_type_display(),
                'user': activity.username or 'System',
                'details': activity.new_values or {}
            }
            for activity in recent_activities
        ]
        
        serializer = DashboardStatsSerializer(stats)
        return Response(serializer.data)

# ==================== MFA VIEWS ====================
class MFAView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get MFA status"""
        return Response({
            'mfa_enabled': request.user.mfa_enabled,
            'mfa_setup': bool(request.user.mfa_secret)
        })
    
    def post(self, request):
        """Enable/disable MFA"""
        serializer = MFAEnableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        enable = serializer.validated_data['enable']
        
        if enable and not request.user.mfa_secret:
            return Response(
                {'error': 'MFA not set up. Please set up MFA first.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        request.user.mfa_enabled = enable
        request.user.save()
        
        AuditLog.objects.create(
            event_type='USER_UPDATE',
            user=request.user,
            username=request.user.username,
            table_name='auth_user',
            record_id=request.user.id,
            operation='UPDATE',
            changed_fields=['mfa_enabled'],
            new_values={'mfa_enabled': enable},
            ip_address=request.META.get('REMOTE_ADDR'),
            endpoint=request.path,
            http_method=request.method,
            request_id=uuid.uuid4()
        )
        
        return Response({
            'message': f'MFA {"enabled" if enable else "disabled"} successfully',
            'mfa_enabled': request.user.mfa_enabled
        })

class MFASetupView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Generate MFA secret"""
        import pyotp
        import qrcode
        import base64
        from io import BytesIO
        
        # Generate secret
        secret = pyotp.random_base32()
        
        # Create TOTP URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=request.user.email,
            issuer_name="KOGWENO PRIMARY SCHOOL"
        )
        
        # Generate QR code
        qr = qrcode.make(uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        return Response({
            'secret': secret,
            'qr_code': f'data:image/png;base64,{qr_base64}',
            'uri': uri
        })
    
    def post(self, request):
        """Verify and save MFA setup"""
        serializer = MFASetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        import pyotp
        
        secret = request.data.get('secret')
        token = serializer.validated_data['token']
        
        totp = pyotp.TOTP(secret)
        if totp.verify(token):
            request.user.mfa_secret = secret
            request.user.save()
            
            AuditLog.objects.create(
                event_type='USER_UPDATE',
                user=request.user,
                username=request.user.username,
                table_name='auth_user',
                record_id=request.user.id,
                operation='UPDATE',
                changed_fields=['mfa_secret'],
                ip_address=request.META.get('REMOTE_ADDR'),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            return Response({'message': 'MFA set up successfully'})
        
        return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)

class MFAVerifyView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Verify MFA token for login"""
        serializer = MFAAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data['token']
        user_id = request.session.get('mfa_user_id')
        
        if not user_id:
            return Response(
                {'error': 'No pending MFA verification'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        import pyotp
        
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(token):
            # Clear MFA session
            request.session.pop('mfa_user_id', None)
            
            # Generate tokens as in regular login
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Create user session
            session = UserSession.objects.create(
                user=user,
                access_token=access_token,
                refresh_token=refresh_token,
                client_ip=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                device_fingerprint=request.META.get('HTTP_USER_AGENT', '')[:64],
                expires_at=refresh.access_token.payload['exp']
            )
            
            response_data = LoginResponseSerializer({
                'token': access_token,
                'refresh_token': refresh_token,
                'session_id': session.id,
                'user': user
            }).data
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)

# ==================== PUBLIC VIEWS ====================
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def system_status(request):
    """Check system status"""
    from django.db import connection
    
    try:
        # Check database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        # Check if there are any users
        user_count = User.objects.count()
        
        return Response({
            'status': 'ok',
            'database': 'connected',
            'users_count': user_count,
            'timestamp': timezone.now().isoformat(),
            'version': '1.0.0'
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

# ==================== NOTIFICATION VIEWS ====================
class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    from .models import Notification
    from .serializers import NotificationSerializer
    
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        
        # Get notifications for this user
        notifications = Notification.objects.filter(
            Q(recipient_type='User', recipient_id=user.id) |
            Q(recipient_type='Role', recipient_id=user.role) |
            Q(recipient_type='All')
        ).order_by('-sent_at')
        
        return notifications
    
    @action(detail=False, methods=['get'])
    def unread(self, request):
        notifications = self.get_queryset().filter(status='Unread')
        page = self.paginate_queryset(notifications)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(notifications, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        notification.status = 'Read'
        notification.read_at = timezone.now()
        notification.save()
        return Response({'message': 'Notification marked as read'})
    
    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        notifications = self.get_queryset().filter(status='Unread')
        updated = notifications.update(status='Read', read_at=timezone.now())
        return Response({'message': f'{updated} notifications marked as read'})
    
    
# Add to your existing views.py (after the authentication views)
# ==================== CLASS MANAGEMENT VIEWS ====================
class ClassViewSet(viewsets.ModelViewSet):
    """Class management views - added to existing views.py"""
    queryset = Class.objects.all().order_by('numeric_level', 'stream')
    serializer_class = ClassSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return ClassCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return ClassUpdateSerializer
        elif self.action == 'retrieve':
            return ClassDetailSerializer
        return super().get_serializer_class()
    
    def check_admin_permission(self, user):
        """Check if user can manage classes"""
        allowed_roles = ['system_admin', 'principal', 'director_studies', 'registrar']
        return user.role in allowed_roles
    
    def create(self, request, *args, **kwargs):
        """Create a new class - with audit logging"""
        # Check permission
        if not self.check_admin_permission(request.user):
            return Response(
                {'error': 'You do not have permission to create classes'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            class_instance = serializer.save()
            
            # Log audit - JUST LIKE LOGIN DOES
            AuditLog.objects.create(
                event_type='CLASS_CREATE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Class',
                record_id=class_instance.id,
                operation='INSERT',
                new_values={
                    'class_code': class_instance.class_code,
                    'class_name': class_instance.class_name,
                    'numeric_level': class_instance.numeric_level,
                    'capacity': class_instance.capacity,
                    'is_active': class_instance.is_active
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            # Send notification if class teacher assigned
            if class_instance.class_teacher:
                Notification.objects.create(
                    notification_type='CLASS_ASSIGNED',
                    title='Class Teacher Assignment',
                    message=f'You have been assigned as class teacher for {class_instance.class_name}',
                    recipient_type='User',
                    recipient_id=class_instance.class_teacher.id,
                    priority='Normal',
                    sent_by=request.user
                )
            
            return Response({
                'success': True,
                'message': 'Class created successfully',
                'data': ClassSerializer(class_instance).data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error creating class: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to create class',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, *args, **kwargs):
        """Update class - with audit logging"""
        if not self.check_admin_permission(request.user):
            return Response(
                {'error': 'You do not have permission to update classes'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        instance = self.get_object()
        old_values = ClassSerializer(instance).data
        
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            class_instance = serializer.save()
            
            # Log audit - capture changes
            changed_fields = list(request.data.keys())
            AuditLog.objects.create(
                event_type='CLASS_UPDATE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Class',
                record_id=instance.id,
                operation='UPDATE',
                old_values={k: old_values[k] for k in changed_fields if k in old_values},
                new_values={k: request.data[k] for k in changed_fields},
                changed_fields=changed_fields,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            return Response({
                'success': True,
                'message': 'Class updated successfully',
                'data': ClassSerializer(class_instance).data
            })
            
        except Exception as e:
            logger.error(f"Error updating class: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to update class',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, *args, **kwargs):
        """Delete class - with audit logging"""
        if not self.check_admin_permission(request.user):
            return Response(
                {'error': 'You do not have permission to delete classes'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        instance = self.get_object()
        
        # Check if class has students
        student_count = Student.objects.filter(current_class=instance).count()
        if student_count > 0:
            return Response({
                'success': False,
                'error': f'Cannot delete class with {student_count} students. Reassign students first.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        old_values = ClassSerializer(instance).data
        
        try:
            instance.delete()
            
            # Log deletion
            AuditLog.objects.create(
                event_type='CLASS_DELETE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Class',
                record_id=kwargs['pk'],
                operation='DELETE',
                old_values=old_values,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            return Response({
                'success': True,
                'message': 'Class deleted successfully'
            })
            
        except Exception as e:
            logger.error(f"Error deleting class: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to delete class',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Activate/Deactivate class - with audit logging"""
        if not self.check_admin_permission(request.user):
            return Response(
                {'error': 'You do not have permission to modify class status'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        instance = self.get_object()
        new_status = not instance.is_active
        
        try:
            instance.is_active = new_status
            instance.save()
            
            # Log status change
            AuditLog.objects.create(
                event_type='CLASS_UPDATE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Class',
                record_id=instance.id,
                operation='UPDATE',
                old_values={'is_active': not new_status},
                new_values={'is_active': new_status},
                changed_fields=['is_active'],
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            status_text = "activated" if new_status else "deactivated"
            return Response({
                'success': True,
                'message': f'Class {status_text} successfully',
                'data': ClassSerializer(instance).data
            })
            
        except Exception as e:
            logger.error(f"Error toggling class status: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to update class status',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get class statistics - like dashboard"""
        try:
            total_classes = Class.objects.count()
            active_classes = Class.objects.filter(is_active=True).count()
            
            # Get total capacity
            total_capacity = Class.objects.aggregate(total=models.Sum('capacity'))['total'] or 0
            
            # Get current student counts per class
            classes_with_counts = Class.objects.annotate(
                student_count=models.Count('current_students')
            )
            
            # Calculate average capacity
            avg_capacity = total_capacity / total_classes if total_classes > 0 else 0
            
            # Get classes by level
            classes_by_level = classes_with_counts.values('numeric_level').annotate(
                class_count=models.Count('id'),
                student_count=models.Sum('student_count')
            ).order_by('numeric_level')
            
            return Response({
                'success': True,
                'data': {
                    'total_classes': total_classes,
                    'active_classes': active_classes,
                    'total_capacity': total_capacity,
                    'average_capacity': round(avg_capacity, 1),
                    'classes_by_level': list(classes_by_level),
                    'classes': ClassSerializer(classes_with_counts, many=True).data
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting class statistics: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to get statistics'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==================== STAFF/TEACHER VIEWS ====================
class TeacherListView(APIView):
    """Get list of teachers for dropdown - similar to LoginView pattern"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # Get teachers (staff with teacher role)
            teachers = User.objects.filter(
                role='teacher',
                is_active=True
            ).order_by('first_name', 'last_name')
            
            teacher_list = []
            for teacher in teachers:
                # Get staff details if available
                staff_details = {}
                if hasattr(teacher, 'staff_profile'):
                    staff = teacher.staff_profile
                    staff_details = {
                        'staff_id': staff.staff_id,
                        'designation': staff.designation,
                        'department': staff.department
                    }
                
                teacher_list.append({
                    'id': teacher.id,
                    'username': teacher.username,
                    'email': teacher.email,
                    'first_name': teacher.first_name,
                    'last_name': teacher.last_name,
                    'phone': teacher.phone,
                    'full_name': f"{teacher.first_name} {teacher.last_name}",
                    **staff_details
                })
            
            return Response({
                'success': True,
                'data': teacher_list
            })
            
        except Exception as e:
            logger.error(f"Error getting teachers: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to get teacher list'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==================== SIMPLE CLASS API VIEWS ====================
class ClassListAPIView(APIView):
    """Simple class list view for your React frontend"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get all classes - matches your React frontend expectation"""
        try:
            classes = Class.objects.all().order_by('numeric_level', 'stream')
            
            # Add student count to each class
            class_list = []
            for cls in classes:
                student_count = Student.objects.filter(current_class=cls).count()
                class_list.append({
                    'id': cls.id,
                    'class_code': cls.class_code,
                    'class_name': cls.class_name,
                    'numeric_level': cls.numeric_level,
                    'stream': cls.stream,
                    'capacity': cls.capacity,
                    'current_students': student_count,
                    'class_teacher_id': cls.class_teacher.id if cls.class_teacher else None,
                    'class_teacher_name': f"{cls.class_teacher.first_name} {cls.class_teacher.last_name}" if cls.class_teacher else None,
                    'is_active': cls.is_active,
                    'created_at': cls.created_at
                })
            
            return Response({
                'success': True,
                'data': class_list
            })
            
        except Exception as e:
            logger.error(f"Error in ClassListAPIView: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to load classes'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ClassCreateAPIView(APIView):
    """Create class - matches your React frontend"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Check permission
        allowed_roles = ['system_admin', 'principal', 'director_studies', 'registrar']
        if request.user.role not in allowed_roles:
            return Response({
                'success': False,
                'error': 'You do not have permission to create classes'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Validate required fields
        required_fields = ['class_code', 'class_name', 'numeric_level']
        for field in required_fields:
            if field not in request.data:
                return Response({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Prepare data
            data = request.data.copy()
            
            # Set class teacher if provided
            if 'class_teacher_id' in data and data['class_teacher_id']:
                try:
                    teacher = User.objects.get(id=data['class_teacher_id'])
                    data['class_teacher'] = teacher.id
                except User.DoesNotExist:
                    return Response({
                        'success': False,
                        'error': 'Invalid teacher ID'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create class
            serializer = ClassCreateSerializer(data=data)
            if serializer.is_valid():
                class_instance = serializer.save(created_by=request.user)
                
                # AUDIT LOG - JUST LIKE LOGIN
                AuditLog.objects.create(
                    event_type='CLASS_CREATE',
                    user=request.user,
                    username=request.user.username,
                    user_role=request.user.role,
                    table_name='Class',
                    record_id=class_instance.id,
                    operation='INSERT',
                    new_values={
                        'class_code': class_instance.class_code,
                        'class_name': class_instance.class_name,
                        'numeric_level': class_instance.numeric_level,
                        'capacity': class_instance.capacity,
                        'is_active': class_instance.is_active
                    },
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    endpoint=request.path,
                    http_method=request.method,
                    request_id=uuid.uuid4()
                )
                
                # Build response data
                response_data = {
                    'id': class_instance.id,
                    'class_code': class_instance.class_code,
                    'class_name': class_instance.class_name,
                    'numeric_level': class_instance.numeric_level,
                    'stream': class_instance.stream,
                    'capacity': class_instance.capacity,
                    'current_students': 0,
                    'class_teacher_id': class_instance.class_teacher.id if class_instance.class_teacher else None,
                    'class_teacher_name': f"{class_instance.class_teacher.first_name} {class_instance.class_teacher.last_name}" if class_instance.class_teacher else None,
                    'is_active': class_instance.is_active,
                    'created_at': class_instance.created_at
                }
                
                return Response({
                    'success': True,
                    'message': 'Class created successfully',
                    'data': response_data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'error': 'Validation failed',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error creating class: {str(e)}")
            
            # Log error to audit
            AuditLog.objects.create(
                event_type='CLASS_CREATE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Class',
                operation='INSERT',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4(),
                error_message=str(e)
            )
            
            return Response({
                'success': False,
                'error': 'Failed to create class',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class ClassUpdateAPIView(APIView):
    """Update class - matches your React frontend"""
    permission_classes = [permissions.IsAuthenticated]
    
    def put(self, request, class_id):
        # Check permission
        allowed_roles = ['system_admin', 'principal', 'director_studies', 'registrar']
        if request.user.role not in allowed_roles:
            return Response({
                'success': False,
                'error': 'You do not have permission to update classes'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Get class instance
            class_instance = Class.objects.get(id=class_id)
            old_values = {
                'is_active': class_instance.is_active
            }
            
            # Update fields
            if 'is_active' in request.data:
                class_instance.is_active = request.data['is_active']
            
            if 'class_teacher_id' in request.data:
                if request.data['class_teacher_id']:
                    try:
                        teacher = User.objects.get(id=request.data['class_teacher_id'])
                        class_instance.class_teacher = teacher
                    except User.DoesNotExist:
                        return Response({
                            'success': False,
                            'error': 'Invalid teacher ID'
                        }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    class_instance.class_teacher = None
            
            # Save changes
            class_instance.save()
            
            # AUDIT LOG
            changed_fields = list(request.data.keys())
            AuditLog.objects.create(
                event_type='CLASS_UPDATE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Class',
                record_id=class_instance.id,
                operation='UPDATE',
                old_values=old_values,
                new_values=request.data,
                changed_fields=changed_fields,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            # Get updated student count
            student_count = Student.objects.filter(current_class=class_instance).count()
            
            response_data = {
                'id': class_instance.id,
                'class_code': class_instance.class_code,
                'class_name': class_instance.class_name,
                'numeric_level': class_instance.numeric_level,
                'stream': class_instance.stream,
                'capacity': class_instance.capacity,
                'current_students': student_count,
                'class_teacher_id': class_instance.class_teacher.id if class_instance.class_teacher else None,
                'class_teacher_name': f"{class_instance.class_teacher.first_name} {class_instance.class_teacher.last_name}" if class_instance.class_teacher else None,
                'is_active': class_instance.is_active
            }
            
            return Response({
                'success': True,
                'message': 'Class updated successfully',
                'data': response_data
            })
            
        except Class.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Class not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error updating class: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to update class',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class ClassDeleteAPIView(APIView):
    """Delete class - matches your React frontend"""
    permission_classes = [permissions.IsAuthenticated]
    
    def delete(self, request, class_id):
        # Check permission
        allowed_roles = ['system_admin', 'principal', 'director_studies', 'registrar']
        if request.user.role not in allowed_roles:
            return Response({
                'success': False,
                'error': 'You do not have permission to delete classes'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Get class instance
            class_instance = Class.objects.get(id=class_id)
            
            # Check if class has students
            student_count = Student.objects.filter(current_class=class_instance).count()
            if student_count > 0:
                return Response({
                    'success': False,
                    'error': f'Cannot delete class with {student_count} students'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Save old values for audit
            old_values = {
                'class_code': class_instance.class_code,
                'class_name': class_instance.class_name,
                'numeric_level': class_instance.numeric_level
            }
            
            # Delete the class
            class_instance.delete()
            
            # AUDIT LOG
            AuditLog.objects.create(
                event_type='CLASS_DELETE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Class',
                record_id=class_id,
                operation='DELETE',
                old_values=old_values,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            return Response({
                'success': True,
                'message': 'Class deleted successfully'
            })
            
        except Class.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Class not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error deleting class: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to delete class',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# ==================== TEACHER LIST API ====================
class TeacherListAPIView(APIView):
    """Get teachers for dropdown - matches your React frontend"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # Get active teachers
            teachers = User.objects.filter(
                role='teacher',
                is_active=True
            ).order_by('first_name', 'last_name')
            
            teacher_list = []
            for teacher in teachers:
                teacher_list.append({
                    'id': teacher.id,
                    'first_name': teacher.first_name,
                    'last_name': teacher.last_name,
                    'full_name': f"{teacher.first_name} {teacher.last_name}",
                    'email': teacher.email,
                    'phone': teacher.phone
                })
            
            return Response({
                'success': True,
                'data': teacher_list
            })
            
        except Exception as e:
            logger.error(f"Error getting teachers: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to get teacher list'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





logger = logging.getLogger(__name__)

# ==================== STUDENT MANAGEMENT VIEWS ====================
class StudentViewSet(viewsets.ModelViewSet):
    """Student CRUD operations with audit logging"""
    queryset = Student.objects.all().order_by('-admission_date')
    serializer_class = StudentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            allowed_roles = ['system_admin', 'principal', 'registrar', 'director_studies']
            return [permissions.IsAuthenticated()]  # Role check in perform methods
        return super().get_permissions()
    
    def get_serializer_class(self):
        if self.action == 'create':
            return StudentCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return StudentUpdateSerializer
        return super().get_serializer_class()
    
    def create(self, request, *args, **kwargs):
        # Check user role
        allowed_roles = ['system_admin', 'principal', 'registrar', 'director_studies']
        if request.user.role not in allowed_roles:
            return Response({
                'success': False,
                'error': 'You do not have permission to create students'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Validation failed',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Generate admission number if not provided
            if 'admission_no' not in request.data or not request.data['admission_no']:
                # Generate sequential admission number
                last_student = Student.objects.order_by('-admission_date').first()
                if last_student and last_student.admission_no:
                    # Parse last admission number
                    import re
                    match = re.match(r'([A-Z]+)-(\d{4})(\d{2})-(\d+)', last_student.admission_no)
                    if match:
                        prefix, year, month, sequence = match.groups()
                        next_sequence = int(sequence) + 1
                        admission_no = f"{prefix}-{year}{month}-{next_sequence}"
                    else:
                        # Default format
                        admission_no = f"ADM-{timezone.now().strftime('%Y%m')}-1"
                else:
                    admission_no = f"ADM-{timezone.now().strftime('%Y%m')}-1"
                
                request.data['admission_no'] = admission_no
            
            # Create student
            student = serializer.save(created_by=request.user)
            
            # AUDIT LOG
            AuditLog.objects.create(
                event_type='STUDENT_CREATE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Student',
                record_id=student.id,
                operation='INSERT',
                new_values={
                    'admission_no': student.admission_no,
                    'first_name': student.first_name,
                    'last_name': student.last_name,
                    'current_class_id': student.current_class_id,
                    'created_by': request.user.username
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            # Send notification to class teacher if assigned
            if student.current_class and student.current_class.class_teacher:
                Notification.objects.create(
                    notification_type='STUDENT_ADMITTED',
                    title='New Student Admitted',
                    message=f'{student.first_name} {student.last_name} has been admitted to your class',
                    recipient_type='User',
                    recipient_id=student.current_class.class_teacher.id,
                    priority='Normal',
                    sent_by=request.user
                )
            
            return Response({
                'success': True,
                'message': 'Student registered successfully',
                'data': StudentSerializer(student).data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error creating student: {str(e)}")
            
            # Log error
            AuditLog.objects.create(
                event_type='STUDENT_CREATE',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Student',
                operation='INSERT',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4(),
                error_message=str(e)
            )
            
            return Response({
                'success': False,
                'error': 'Failed to register student',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def list(self, request):
        """Get all students with optional filters"""
        try:
            queryset = self.get_queryset()
            
            # Apply filters
            status_filter = request.query_params.get('status')
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            class_filter = request.query_params.get('class_id')
            if class_filter:
                queryset = queryset.filter(current_class_id=class_filter)
            
            search_query = request.query_params.get('search')
            if search_query:
                queryset = queryset.filter(
                    Q(admission_no__icontains=search_query) |
                    Q(first_name__icontains=search_query) |
                    Q(last_name__icontains=search_query) |
                    Q(guardian_phone__icontains=search_query)
                )
            
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response({
                    'success': True,
                    'data': serializer.data
                })
            
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'success': True,
                'data': serializer.data
            })
            
        except Exception as e:
            logger.error(f"Error listing students: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to load students'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StudentBulkImportView(APIView):
    """Bulk import students from Excel file"""
    parser_classes = [MultiPartParser]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Check user role
        allowed_roles = ['system_admin', 'principal', 'registrar', 'director_studies']
        if request.user.role not in allowed_roles:
            return Response({
                'success': False,
                'error': 'You do not have permission to import students'
            }, status=status.HTTP_403_FORBIDDEN)
        
        if 'excelFile' not in request.FILES:
            return Response({
                'success': False,
                'error': 'No file uploaded'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        excel_file = request.FILES['excelFile']
        imported_count = 0
        errors = []
        
        try:
            # Read Excel file
            if excel_file.name.endswith('.xlsx'):
                df = pd.read_excel(excel_file, engine='openpyxl')
            else:
                df = pd.read_excel(excel_file)
            
            # Convert to list of dictionaries
            data_list = df.to_dict('records')
            
            # Process each row
            for i, row in enumerate(data_list, start=2):  # Start from row 2 (header is row 1)
                try:
                    # Clean the data
                    cleaned_data = {}
                    for key, value in row.items():
                        # Convert pandas NaN to None
                        if pd.isna(value):
                            cleaned_data[key] = None
                        else:
                            cleaned_data[key] = value
                    
                    # Generate admission number if not provided
                    if not cleaned_data.get('admission_no'):
                        last_student = Student.objects.order_by('-admission_date').first()
                        if last_student and last_student.admission_no:
                            import re
                            match = re.match(r'([A-Z]+)-(\d{4})(\d{2})-(\d+)', last_student.admission_no)
                            if match:
                                prefix, year, month, sequence = match.groups()
                                next_sequence = int(sequence) + 1 + imported_count
                                admission_no = f"{prefix}-{year}{month}-{next_sequence}"
                            else:
                                admission_no = f"ADM-{timezone.now().strftime('%Y%m')}-{1 + imported_count}"
                        else:
                            admission_no = f"ADM-{timezone.now().strftime('%Y%m')}-{1 + imported_count}"
                        cleaned_data['admission_no'] = admission_no
                    
                    # Validate and create student
                    serializer = StudentCreateSerializer(data=cleaned_data)
                    if serializer.is_valid():
                        student = serializer.save(created_by=request.user)
                        imported_count += 1
                        
                        # Log each student creation
                        AuditLog.objects.create(
                            event_type='STUDENT_IMPORT',
                            user=request.user,
                            username=request.user.username,
                            user_role=request.user.role,
                            table_name='Student',
                            record_id=student.id,
                            operation='INSERT',
                            new_values={
                                'admission_no': student.admission_no,
                                'first_name': student.first_name,
                                'last_name': student.last_name,
                                'source': 'bulk_import'
                            },
                            ip_address=request.META.get('REMOTE_ADDR'),
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            endpoint=request.path,
                            http_method=request.method,
                            request_id=uuid.uuid4()
                        )
                    else:
                        errors.append({
                            'row': i,
                            'admission_no': cleaned_data.get('admission_no', 'N/A'),
                            'errors': serializer.errors
                        })
                        
                except Exception as e:
                    errors.append({
                        'row': i,
                        'admission_no': cleaned_data.get('admission_no', 'N/A'),
                        'errors': str(e)
                    })
                    logger.error(f"Error importing row {i}: {str(e)}")
            
            # Log bulk import summary
            AuditLog.objects.create(
                event_type='BULK_IMPORT',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Student',
                operation='INSERT',
                new_values={
                    'imported_count': imported_count,
                    'total_rows': len(data_list),
                    'error_count': len(errors),
                    'file_name': excel_file.name
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4()
            )
            
            return Response({
                'success': True,
                'message': f'Successfully imported {imported_count} students',
                'importedCount': imported_count,
                'totalRows': len(data_list),
                'errorCount': len(errors),
                'errors': errors if errors else None
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error in bulk import: {str(e)}")
            
            AuditLog.objects.create(
                event_type='BULK_IMPORT',
                user=request.user,
                username=request.user.username,
                user_role=request.user.role,
                table_name='Student',
                operation='INSERT',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method,
                request_id=uuid.uuid4(),
                error_message=str(e)
            )
            
            return Response({
                'success': False,
                'error': 'Failed to import students',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class GenerateAdmissionNumberView(APIView):
    """Generate next admission number"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # Get last admission number
            last_student = Student.objects.order_by('-admission_date').first()
            
            if last_student and last_student.admission_no:
                import re
                match = re.match(r'([A-Z]+)-(\d{4})(\d{2})-(\d+)', last_student.admission_no)
                if match:
                    prefix, year, month, sequence = match.groups()
                    current_year = timezone.now().year
                    current_month = timezone.now().month
                    
                    # If year/month changed, reset sequence
                    if int(year) != current_year or int(month) != current_month:
                        next_sequence = 1
                        admission_no = f"{prefix}-{current_year}{current_month:02d}-{next_sequence}"
                    else:
                        next_sequence = int(sequence) + 1
                        admission_no = f"{prefix}-{year}{month}-{next_sequence}"
                else:
                    # Default format
                    admission_no = f"ADM-{timezone.now().strftime('%Y%m')}-1"
                    next_sequence = 1
            else:
                # First student
                admission_no = f"ADM-{timezone.now().strftime('%Y%m')}-1"
                next_sequence = 1
            
            # Also check highest sequence number to avoid duplicates
            all_students = Student.objects.all()
            highest_sequence = 0
            
            for student in all_students:
                if student.admission_no:
                    match = re.match(r'[A-Z]+-\d{6}-(\d+)', student.admission_no)
                    if match:
                        seq = int(match.group(1))
                        if seq > highest_sequence:
                            highest_sequence = seq
            
            if highest_sequence >= next_sequence:
                next_sequence = highest_sequence + 1
                # Reconstruct admission number with highest sequence
                current_year = timezone.now().year
                current_month = timezone.now().month
                admission_no = f"ADM-{current_year}{current_month:02d}-{next_sequence}"
            
            return Response({
                'success': True,
                'admission_no': admission_no,
                'next_sequence': next_sequence,
                'format': 'PREFIX-YYYYMM-SEQUENCE'
            })
            
        except Exception as e:
            logger.error(f"Error generating admission number: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to generate admission number'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StudentStatisticsView(APIView):
    """Get student statistics"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            total_students = Student.objects.count()
            active_students = Student.objects.filter(status='Active').count()
            male_students = Student.objects.filter(gender='Male').count()
            female_students = Student.objects.filter(gender='Female').count()
            
            # Count by class
            classes = Class.objects.all()
            class_distribution = []
            for cls in classes:
                count = Student.objects.filter(current_class=cls, status='Active').count()
                if count > 0:
                    class_distribution.append({
                        'class_id': cls.id,
                        'class_name': cls.class_name,
                        'class_code': cls.class_code,
                        'student_count': count
                    })
            
            # Recent admissions (last 30 days)
            thirty_days_ago = timezone.now() - timezone.timedelta(days=30)
            recent_admissions = Student.objects.filter(
                admission_date__gte=thirty_days_ago
            ).count()
            
            return Response({
                'success': True,
                'data': {
                    'total_students': total_students,
                    'active_students': active_students,
                    'male_students': male_students,
                    'female_students': female_students,
                    'recent_admissions': recent_admissions,
                    'class_distribution': class_distribution
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting student statistics: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to get statistics'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DownloadTemplateView(APIView):
    """Download Excel template for student import"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # Create sample data matching Student model
            sample_data = [{
                'admission_no': f'ADM-{timezone.now().strftime("%Y%m")}-1',
                'first_name': 'John',
                'middle_name': 'Kiprop',
                'last_name': 'Mwangi',
                'date_of_birth': '2010-05-15',
                'gender': 'Male',
                'nationality': 'Kenyan',
                'religion': 'Christian',
                'blood_group': 'O+',
                'address': '123 Main Street',
                'city': 'Nairobi',
                'country': 'Kenya',
                'phone': '0712345678',
                'email': 'john@example.com',
                'current_class': '1',  # Class ID
                'current_section': 'A',
                'stream': 'Science',
                'roll_number': '12',
                'admission_date': timezone.now().date().isoformat(),
                'admission_type': 'new',
                'father_name': 'Peter Mwangi',
                'father_phone': '0723456789',
                'father_email': 'peter@example.com',
                'father_occupation': 'Engineer',
                'mother_name': 'Mary Mwangi',
                'mother_phone': '0734567890',
                'mother_email': 'mary@example.com',
                'mother_occupation': 'Teacher',
                'guardian_name': 'Peter Mwangi',
                'guardian_relation': 'Father',
                'guardian_phone': '0723456789',
                'guardian_email': 'peter@example.com',
                'guardian_address': '123 Main Street',
                'medical_conditions': 'None',
                'allergies': 'Peanuts',
                'medication': 'None',
                'emergency_contact': '0723456789',
                'emergency_contact_name': 'Peter Mwangi',
                'previous_school': 'ABC Primary',
                'previous_class': 'Class 7',
                'transfer_certificate_no': 'TC12345',
                'status': 'Active',
                'expected_graduation_date': '2026-12-31'
            }]
            
            # Create DataFrame
            df = pd.DataFrame(sample_data)
            
            # Create Excel file in memory
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Template', index=False)
                
                # Auto-adjust column widths
                worksheet = writer.sheets['Template']
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 30)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
            
            output.seek(0)
            
            # Create response
            response = HttpResponse(
                output.getvalue(),
                content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            response['Content-Disposition'] = 'attachment; filename="student_import_template.xlsx"'
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating template: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to generate template'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#FEE =======================================VIEWS=============================
class FeeCategoryViewSet(viewsets.ModelViewSet):
    queryset = FeeCategory.objects.all().order_by('-created_at')
    serializer_class = FeeCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Search functionality
        search_term = self.request.query_params.get('search', '')
        if search_term:
            queryset = queryset.filter(
                Q(category_code__icontains=search_term) |
                Q(category_name__icontains=search_term) |
                Q(description__icontains=search_term)
            )
        
        # Filter by status
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        return queryset
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    def perform_update(self, serializer):
        serializer.save()
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get fee category statistics"""
        total_categories = FeeCategory.objects.count()
        active_categories = FeeCategory.objects.filter(is_active=True).count()
        mandatory_categories = FeeCategory.objects.filter(is_mandatory=True).count()
        
        stats_data = {
            'total': total_categories,
            'active_count': active_categories,
            'mandatory_count': mandatory_categories
        }
        
        serializer = CategoryStatsSerializer(data=stats_data)
        serializer.is_valid()
        return Response({
            'success': True,
            'message': 'Category statistics retrieved successfully',
            'data': serializer.data
        })

class FeeStructureViewSet(viewsets.ModelViewSet):
    queryset = FeeStructure.objects.all().order_by('-academic_year', '-created_at')
    serializer_class = FeeStructureSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Search functionality
        search_term = self.request.query_params.get('search', '')
        if search_term:
            queryset = queryset.filter(
                Q(academic_year__icontains=search_term) |
                Q(category__category_name__icontains=search_term) |
                Q(category__category_code__icontains=search_term) |
                Q(class_id__class_name__icontains=search_term)
            )
        
        # Filter by academic year
        academic_year = self.request.query_params.get('academic_year', '')
        if academic_year:
            queryset = queryset.filter(academic_year=academic_year)
        
        # Filter by term
        term = self.request.query_params.get('term', '')
        if term:
            queryset = queryset.filter(term=term)
        
        # Filter by class
        class_id = self.request.query_params.get('class_id', '')
        if class_id:
            queryset = queryset.filter(class_id_id=class_id)
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        return queryset.select_related('class_id', 'category', 'created_by')
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    def perform_update(self, serializer):
        serializer.save()
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get fee structure statistics"""
        total_structures = FeeStructure.objects.count()
        active_structures = FeeStructure.objects.filter(is_active=True).count()
        
        # Calculate total amount of active structures
        total_amount_result = FeeStructure.objects.filter(
            is_active=True
        ).aggregate(
            total_amount=Coalesce(Sum('amount'), Value(0, output_field=FloatField()))
        )
        
        stats_data = {
            'total': total_structures,
            'active_count': active_structures,
            'total_amount': total_amount_result['total_amount'] or 0
        }
        
        serializer = StructureStatsSerializer(data=stats_data)
        serializer.is_valid()
        return Response({
            'success': True,
            'message': 'Structure statistics retrieved successfully',
            'data': serializer.data
        })
    
    @action(detail=False, methods=['get'])
    def academic_years(self, request):
        """Get distinct academic years"""
        academic_years = FeeStructure.objects.values_list(
            'academic_year', flat=True
        ).distinct().order_by('-academic_year')
        
        # If no academic years exist, generate current academic year
        if not academic_years:
            current_year = timezone.now().year
            current_month = timezone.now().month
            if current_month >= 6:  # June or later
                academic_years = [f"{current_year}-{current_year + 1}"]
            else:
                academic_years = [f"{current_year - 1}-{current_year}"]
        
        return Response({
            'success': True,
            'message': 'Academic years retrieved successfully',
            'data': list(academic_years)
        })

class FeeTransactionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = FeeTransaction.objects.all().order_by('-payment_date', '-created_at')
    serializer_class = FeeTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Search functionality
        search_term = self.request.query_params.get('search', '')
        if search_term:
            queryset = queryset.filter(
                Q(transaction_no__icontains=search_term) |
                Q(student__admission_no__icontains=search_term) |
                Q(student__first_name__icontains=search_term) |
                Q(student__last_name__icontains=search_term) |
                Q(payment_reference__icontains=search_term)
            )
        
        # Filter by status
        status_filter = self.request.query_params.get('status', '')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by payment mode
        payment_mode = self.request.query_params.get('payment_mode', '')
        if payment_mode:
            queryset = queryset.filter(payment_mode=payment_mode)
        
        # Date range filter
        start_date = self.request.query_params.get('start_date', '')
        end_date = self.request.query_params.get('end_date', '')
        if start_date:
            queryset = queryset.filter(payment_date__gte=start_date)
        if end_date:
            queryset = queryset.filter(payment_date__lte=end_date)
        
        # Limit results
        limit = self.request.query_params.get('limit', None)
        if limit:
            try:
                limit = int(limit)
                queryset = queryset[:limit]
            except ValueError:
                pass
        
        return queryset.select_related('student', 'collected_by')
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get fee transaction statistics"""
        # Get all transactions
        all_transactions = FeeTransaction.objects.all()
        
        # Basic counts
        total_transactions = all_transactions.count()
        completed_transactions = all_transactions.filter(status='Completed').count()
        pending_transactions = all_transactions.filter(status='Pending').count()
        
        # Calculate total collected amount
        total_collected_result = all_transactions.filter(
            status='Completed'
        ).aggregate(
            total_collected=Coalesce(Sum('amount_kes'), Value(0, output_field=FloatField()))
        )
        
        stats_data = {
            'total_transactions': total_transactions,
            'completed_transactions': completed_transactions,
            'pending_transactions': pending_transactions,
            'total_collected': total_collected_result['total_collected'] or 0
        }
        
        serializer = TransactionStatsSerializer(data=stats_data)
        serializer.is_valid()
        return Response({
            'success': True,
            'message': 'Transaction statistics retrieved successfully',
            'data': serializer.data
        })

class FeeDashboardAPIView(APIView):
    """API endpoint for fee management dashboard data"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get all dashboard data in one call"""
        try:
            # Get category stats
            total_categories = FeeCategory.objects.count()
            active_categories = FeeCategory.objects.filter(is_active=True).count()
            mandatory_categories = FeeCategory.objects.filter(is_mandatory=True).count()
            
            # Get structure stats
            total_structures = FeeStructure.objects.count()
            active_structures = FeeStructure.objects.filter(is_active=True).count()
            total_amount_result = FeeStructure.objects.filter(
                is_active=True
            ).aggregate(
                total_amount=Coalesce(Sum('amount'), Value(0, output_field=FloatField()))
            )
            
            # Get transaction stats
            all_transactions = FeeTransaction.objects.all()
            total_transactions = all_transactions.count()
            completed_transactions = all_transactions.filter(status='Completed').count()
            pending_transactions = all_transactions.filter(status='Pending').count()
            total_collected_result = all_transactions.filter(
                status='Completed'
            ).aggregate(
                total_collected=Coalesce(Sum('amount_kes'), Value(0, output_field=FloatField()))
            )
            
            # Calculate collection rate
            collection_rate = 0
            if total_transactions > 0:
                collection_rate = (completed_transactions / total_transactions) * 100
            
            # Get recent transactions (last 10)
            recent_transactions = FeeTransaction.objects.select_related(
                'student', 'collected_by'
            ).order_by('-payment_date')[:10]
            
            # Get recent structures (last 5)
            recent_structures = FeeStructure.objects.select_related(
                'class_id', 'category'
            ).order_by('-created_at')[:5]
            
            # Get academic years for filters
            academic_years = FeeStructure.objects.values_list(
                'academic_year', flat=True
            ).distinct().order_by('-academic_year')
            
            # If no academic years, create current one
            if not academic_years:
                current_year = timezone.now().year
                current_month = timezone.now().month
                if current_month >= 6:
                    academic_years = [f"{current_year}-{current_year + 1}"]
                else:
                    academic_years = [f"{current_year - 1}-{current_year}"]
            
            data = {
                'categories': {
                    'total': total_categories,
                    'active_count': active_categories,
                    'mandatory_count': mandatory_categories
                },
                'structures': {
                    'total': total_structures,
                    'active_count': active_structures,
                    'total_amount': total_amount_result['total_amount'] or 0
                },
                'transactions': {
                    'total_transactions': total_transactions,
                    'completed_transactions': completed_transactions,
                    'pending_transactions': pending_transactions,
                    'total_collected': total_collected_result['total_collected'] or 0,
                    'collection_rate': round(collection_rate, 2)
                },
                'recent_transactions': FeeTransactionSerializer(
                    recent_transactions, many=True
                ).data,
                'recent_structures': FeeStructureSerializer(
                    recent_structures, many=True
                ).data,
                'academic_years': list(academic_years),
                'current_academic_year': academic_years[0] if academic_years else ''
            }
            
            return Response({
                'success': True,
                'message': 'Dashboard data retrieved successfully',
                'data': data
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'message': f'Error retrieving dashboard data: {str(e)}',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)