# middleware/ip_whitelist.py
from django.conf import settings
from django.http import HttpResponseForbidden
from django.utils import timezone
from school_app.models import IPWhitelist, AuditLog
import logging

logger = logging.getLogger(__name__)

class IPWhitelistMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0]
        else:
            client_ip = request.META.get('REMOTE_ADDR')
        
        # Skip IP check for localhost in development
        if client_ip in ['127.0.0.1', 'localhost'] and settings.DEBUG:
            return self.get_response(request)
        
        # Check if IP is whitelisted
        try:
            ip_record = IPWhitelist.objects.get(ip_address=client_ip)
            # Check time restrictions
            if not ip_record.is_active_now():
                logger.warning(f"IP {client_ip} access denied due to time restrictions")
                return HttpResponseForbidden(
                    "Access denied: Outside allowed access hours. "
                    f"Allowed: {ip_record.time_start} to {ip_record.time_end}"
                )
            
            # Update access count
            ip_record.increment_access_count()
            
            # Log successful access
            if ip_record.notify_on_access:
                AuditLog.objects.create(
                    event_type='IP_WHITELIST_ACCESS',
                    username=request.user.username if request.user.is_authenticated else 'Anonymous',
                    user_role=request.user.role if request.user.is_authenticated else None,
                    table_name='IPWhitelist',
                    operation='SELECT',
                    new_values={'ip_address': client_ip, 'user_agent': request.META.get('HTTP_USER_AGENT', '')},
                    ip_address=client_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    endpoint=request.path,
                    http_method=request.method
                )
            
        except IPWhitelist.DoesNotExist:
            # Check if IP is in blocked list
            if IPWhitelist.objects.filter(ip_address=client_ip, status='Blocked').exists():
                logger.warning(f"Blocked IP {client_ip} attempted access")
                return HttpResponseForbidden(
                    "Access denied: Your IP address has been blocked. "
                    "Please contact system administrator."
                )
            
            # Log unauthorized access attempt
            AuditLog.objects.create(
                event_type='UNAUTHORIZED_IP_ACCESS',
                username=request.user.username if request.user.is_authenticated else 'Anonymous',
                table_name='IPWhitelist',
                operation='BLOCK',
                new_values={'ip_address': client_ip, 'block_reason': 'Not in whitelist'},
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                http_method=request.method
            )
            
            logger.warning(f"Unauthorized IP {client_ip} attempted access")
            return HttpResponseForbidden(
                "Access denied: You are not authorized to access this system. "
                "Please contact system administrator."
            )
        
        return self.get_response(request)