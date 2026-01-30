# urls.py (authentication module)
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views 

router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='user')
router.register(r'ip-whitelist', views.IPWhitelistViewSet, basename='ip-whitelist')
router.register(r'sessions', views.UserSessionViewSet, basename='session')
router.register(r'notifications', views.NotificationViewSet, basename='notification')

fee_router = DefaultRouter()
fee_router.register(r'fees/categories', views.FeeCategoryViewSet, basename='fee-categories')
fee_router.register(r'fees/structures', views.FeeStructureViewSet, basename='fee-structures')
fee_router.register(r'fees/transactions', views.FeeTransactionViewSet, basename='fee-transactions')

urlpatterns = [
    # Authentication endpoints
    path('api/auth/login/', views.LoginView.as_view(), name='login'),
    path('api/auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('api/auth/refresh-token/', views.RefreshTokenView.as_view(), name='refresh-token'),
    path('api/auth/validate-token/', views.ValidateTokenView.as_view(), name='validate-token'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    
    # MFA endpoints
    path('api/auth/mfa/', views.MFAView.as_view(), name='mfa'),
    path('api/auth/mfa/setup/', views.MFASetupView.as_view(), name='mfa-setup'),
    path('api/auth/mfa/verify/', views.MFAVerifyView.as_view(), name='mfa-verify'),
    
    # Dashboard
    path('api/auth/dashboard/', views.DashboardView.as_view(), name='dashboard'),
    
    # System status
    path('api/auth/system-status/', views.system_status, name='system-status'),
    
    #classes management 
    path('api/classes/', views.ClassListAPIView.as_view(), name='class-list'),
    path('api/classes/create/', views.ClassCreateAPIView.as_view(), name='class-create'),
    path('api/classes/update/<int:class_id>/', views.ClassUpdateAPIView.as_view(), name='class-update'),
    path('api/classes/delete/<int:class_id>/', views.ClassDeleteAPIView.as_view(), name='class-delete'),
    path('api/teachers/', views.TeacherListAPIView.as_view(), name='teacher-list'),
    # Include router URLs
    path('', include(router.urls)),
    
     # Student management endpoints
    path('api/students/', views.StudentViewSet.as_view({'get': 'list', 'post': 'create'}), name='student-list'),
    path('api/students/import/', views.StudentBulkImportView.as_view(), name='student-import'),
    path('api/students/generate-admission-no/', views.GenerateAdmissionNumberView.as_view(), name='generate-admission-no'),
    path('api/students/statistics/', views.StudentStatisticsView.as_view(), name='student-statistics'),
    
    path('api/students/download-template/', views.DownloadTemplateView.as_view(), name='download-template'),
    
    # Fee Management URLs
    path('api/', include(fee_router.urls)),
    
    # Additional fee endpoints
    path('api/fees/dashboard/', views.FeeDashboardAPIView.as_view(), name='fee-dashboard'),
    path('api/fees/structures/academic-years/', 
         views.FeeStructureViewSet.as_view({'get': 'academic_years'}), 
         name='fee-academic-years'),
    path('api/fees/categories/stats/', 
         views.FeeCategoryViewSet.as_view({'get': 'stats'}), 
         name='fee-categories-stats'),
    path('api/fees/structures/stats/', 
         views.FeeStructureViewSet.as_view({'get': 'stats'}), 
         name='fee-structures-stats'),
    path('api/fees/transactions/stats/', 
         views.FeeTransactionViewSet.as_view({'get': 'stats'}), 
         name='fee-transactions-stats'),

]
