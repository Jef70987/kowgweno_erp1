# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from django.contrib import messages
from .models import *


admin.site.site_header = "KOGWENO ERP ADMINISTRATION"
admin.site.site_title = "Admin Portal"
admin.site.index_title = "Welcome to Admin Dashboard"
# ==================== CUSTOM ADMIN CLASSES ====================
class ReadOnlyAdminMixin:
    """Mixin to make admin read-only"""
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False

class ExportCsvMixin:
    """Mixin to add CSV export functionality"""
    def export_as_csv(self, request, queryset):
        import csv
        from django.http import HttpResponse
        import io
        
        field_names = [field.name for field in self.model._meta.fields]
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename={self.model.__name__}.csv'
        
        writer = csv.writer(response)
        writer.writerow(field_names)
        
        for obj in queryset:
            writer.writerow([getattr(obj, field) for field in field_names])
        
        return response
    
    export_as_csv.short_description = "Export Selected as CSV"

# ==================== USER MANAGEMENT ====================
class CustomUserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 
                   'department', 'is_active', 'last_login')
    list_filter = ('role', 'is_active', 'is_staff', 'department')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'phone')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'email', 'phone')}),
        ('Role & Department', {'fields': ('role', 'department')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 
                                   'groups', 'user_permissions')}),
        ('Security', {'fields': ('mfa_enabled', 'last_password_change', 
                                'failed_attempts', 'locked_until')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'role', 'password1', 'password2'),
        }),
    )
    
    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing an existing object
            return ('last_login', 'date_joined', 'last_password_change')
        return ()

class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'client_ip', 'login_time', 'last_activity', 
                   'expires_at', 'revoked')
    list_filter = ('revoked', 'login_time', 'expires_at')
    search_fields = ('user__username', 'client_ip', 'device_fingerprint')
    readonly_fields = ('id', 'access_token', 'refresh_token', 'login_time', 
                      'last_activity', 'expires_at')
    date_hierarchy = 'login_time'

# ==================== SECURITY & IP WHITELISTING ====================
class IPWhitelistAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ('ip_address', 'description', 'status', 'access_level', 
                   'user', 'last_used', 'is_active_display')
    list_filter = ('status', 'access_level', 'country', 'require_2fa')
    search_fields = ('ip_address', 'description', 'user__username', 'country', 'city')
    readonly_fields = ('created_at', 'updated_at', 'last_used', 'total_access_count')
    actions = ['export_as_csv', 'activate_selected', 'deactivate_selected']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('ip_address', 'description', 'status', 'access_level')
        }),
        ('User/Role Association', {
            'fields': ('user', 'allowed_roles')
        }),
        ('Time Restrictions', {
            'fields': ('allowed_days', 'time_start', 'time_end')
        }),
        ('Geolocation', {
            'fields': ('country', 'city', 'isp'),
            'classes': ('collapse',)
        }),
        ('Usage Tracking', {
            'fields': ('last_used', 'total_access_count', 'failed_attempts'),
            'classes': ('collapse',)
        }),
        ('Security Settings', {
            'fields': ('require_2fa', 'notify_on_access')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at', 'expires_at'),
            'classes': ('collapse',)
        }),
    )
    
    def is_active_display(self, obj):
        return obj.is_active_now()
    is_active_display.boolean = True
    is_active_display.short_description = 'Currently Active'
    
    def activate_selected(self, request, queryset):
        updated = queryset.update(status='Active')
        self.message_user(request, f'{updated} IP(s) activated successfully.')
    
    def deactivate_selected(self, request, queryset):
        updated = queryset.update(status='Inactive')
        self.message_user(request, f'{updated} IP(s) deactivated successfully.')
    
    activate_selected.short_description = "Activate selected IPs"
    deactivate_selected.short_description = "Deactivate selected IPs"

class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'changed_at', 'changed_by')
    list_filter = ('changed_at',)
    search_fields = ('user__username',)
    readonly_fields = ('changed_at',)
    date_hierarchy = 'changed_at'

# ==================== STUDENT MANAGEMENT ====================
class StudentAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ('admission_no', 'full_name', 'current_class', 'gender', 
                   'status', 'admission_date', 'created_at')
    list_filter = ('status', 'gender', 'current_class', 'admission_type', 'archived')
    search_fields = ('admission_no', 'first_name', 'last_name', 'phone', 'email', 
                    'guardian_phone', 'guardian_name')
    readonly_fields = ('student_uid', 'created_at', 'updated_at', 'archived_at')
    date_hierarchy = 'admission_date'
    actions = ['export_as_csv', 'archive_students', 'restore_students']
    
    fieldsets = (
        ('Core Information', {
            'fields': ('admission_no', 'student_uid', 'first_name', 'middle_name', 
                      'last_name', 'date_of_birth', 'gender', 'nationality', 
                      'religion', 'blood_group', 'user')
        }),
        ('Contact Information', {
            'fields': ('address', 'city', 'country', 'phone', 'email')
        }),
        ('Academic Information', {
            'fields': ('current_class', 'current_section', 'stream', 'roll_number', 
                      'admission_date', 'admission_type')
        }),
        ('Status', {
            'fields': ('status', 'status_reason', 'status_changed_date', 
                      'expected_graduation_date')
        }),
        ('Guardian Information', {
            'fields': ('father_name', 'father_phone', 'father_email', 'father_occupation',
                      'mother_name', 'mother_phone', 'mother_email', 'mother_occupation',
                      'guardian_name', 'guardian_relation', 'guardian_phone', 
                      'guardian_email', 'guardian_address')
        }),
        ('Medical & Emergency', {
            'fields': ('medical_conditions', 'allergies', 'medication',
                      'emergency_contact', 'emergency_contact_name')
        }),
        ('Academic History', {
            'fields': ('previous_school', 'previous_class', 'transfer_certificate_no'),
            'classes': ('collapse',)
        }),
        ('System', {
            'fields': ('created_by', 'updated_by', 'created_at', 'updated_at', 
                      'archived', 'archived_at'),
            'classes': ('collapse',)
        }),
    )
    
    def archive_students(self, request, queryset):
        updated = queryset.update(archived=True, archived_at=timezone.now())
        self.message_user(request, f'{updated} student(s) archived successfully.')
    
    def restore_students(self, request, queryset):
        updated = queryset.update(archived=False, archived_at=None)
        self.message_user(request, f'{updated} student(s) restored successfully.')
    
    archive_students.short_description = "Archive selected students"
    restore_students.short_description = "Restore selected students"

class StudentAcademicHistoryAdmin(admin.ModelAdmin):
    list_display = ('student', 'academic_year', 'class_id', 'section', 
                   'promoted', 'promotion_date')
    list_filter = ('academic_year', 'class_id', 'promoted')
    search_fields = ('student__admission_no', 'student__first_name', 'student__last_name')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'

# ==================== CBE ACADEMIC STRUCTURE ====================
class AcademicYearAdmin(admin.ModelAdmin):
    list_display = ('year_code', 'year_name', 'start_date', 'end_date', 
                   'is_current')
    list_filter = ('is_current',)
    search_fields = ('year_code', 'year_name')
    actions = ['set_as_current']
    
    def set_as_current(self, request, queryset):
        if queryset.count() > 1:
            self.message_user(request, "Please select only one academic year.", 
                            level=messages.ERROR)
            return
        
        academic_year = queryset.first()
        AcademicYear.objects.update(is_current=False)
        academic_year.is_current = True
        academic_year.save()
        self.message_user(request, f'"{academic_year.year_name}" set as current academic year.')
    
    set_as_current.short_description = "Set as current academic year"

class TermAdmin(admin.ModelAdmin):
    list_display = ('academic_year', 'term', 'start_date', 'end_date', 'is_current')
    list_filter = ('academic_year', 'term', 'is_current')
    search_fields = ('academic_year__year_code', 'term')
    actions = ['set_as_current']
    
    def set_as_current(self, request, queryset):
        if queryset.count() > 1:
            self.message_user(request, "Please select only one term.", 
                            level=messages.ERROR)
            return
        
        term = queryset.first()
        Term.objects.update(is_current=False)
        term.is_current = True
        term.save()
        self.message_user(request, f'"{term.term} - {term.academic_year.year_name}" set as current term.')
    
    set_as_current.short_description = "Set as current term"

class LearningAreaAdmin(admin.ModelAdmin):
    list_display = ('area_code', 'area_name', 'short_name', 'area_type', 'is_active')
    list_filter = ('area_type', 'is_active')
    search_fields = ('area_code', 'area_name', 'short_name')
    list_per_page = 20

class StrandAdmin(admin.ModelAdmin):
    list_display = ('learning_area', 'strand_code', 'strand_name', 'display_order')
    list_filter = ('learning_area',)
    search_fields = ('strand_code', 'strand_name', 'learning_area__area_name')
    list_per_page = 20

class SubStrandAdmin(admin.ModelAdmin):
    list_display = ('strand', 'substrand_code', 'substrand_name', 'display_order')
    list_filter = ('strand__learning_area', 'strand')
    search_fields = ('substrand_code', 'substrand_name', 'strand__strand_name')
    list_per_page = 20

class CompetencyAdmin(admin.ModelAdmin):
    list_display = ('substrand', 'competency_code', 'competency_statement_truncated', 
                   'is_core_competency', 'display_order')
    list_filter = ('substrand__strand__learning_area', 'substrand__strand', 'is_core_competency')
    search_fields = ('competency_code', 'competency_statement')
    list_per_page = 20
    
    def competency_statement_truncated(self, obj):
        return obj.competency_statement[:100] + '...' if len(obj.competency_statement) > 100 else obj.competency_statement
    competency_statement_truncated.short_description = 'Competency Statement'

# ==================== SUMMATIVE ASSESSMENT MODELS (CBE) ====================
class AssessmentWindowAdmin(admin.ModelAdmin):
    list_display = ('term', 'assessment_type', 'weight_percentage', 'open_date', 
                   'close_date', 'is_active')
    list_filter = ('term__academic_year', 'term', 'assessment_type', 'is_active')
    search_fields = ('assessment_type', 'term__academic_year__year_code')
    date_hierarchy = 'open_date'

class SummativeAssessmentAdmin(admin.ModelAdmin):
    list_display = ('assessment_code', 'assessment_window', 'class_id', 
                   'learning_area', 'teacher', 'status', 'created_at')
    list_filter = ('status', 'assessment_window__term', 'learning_area', 'class_id')
    search_fields = ('assessment_code', 'teacher__username', 'class_id__class_name')
    readonly_fields = ('assessment_code', 'created_at', 'updated_at')
    filter_horizontal = ('competencies',)
    date_hierarchy = 'created_at'

class SummativeRatingAdmin(admin.ModelAdmin):
    list_display = ('assessment', 'student', 'competency', 'rating', 'internal_value', 
                   'rated_by', 'rated_at')
    list_filter = ('rating', 'rated_at', 'assessment__assessment_window__term')
    search_fields = ('student__admission_no', 'student__full_name', 
                    'competency__competency_code')
    readonly_fields = ('internal_value', 'rated_at', 'modified_at')
    date_hierarchy = 'rated_at'

class TermlySummaryAdmin(admin.ModelAdmin):
    list_display = ('student', 'term', 'learning_area', 'final_internal_value', 
                   'final_rating', 'progression_status', 'promotion_status', 
                   'is_approved')
    list_filter = ('term', 'learning_area', 'final_rating', 'progression_status', 
                  'promotion_status', 'is_approved')
    search_fields = ('student__admission_no', 'student__full_name', 
                    'learning_area__area_name')
    readonly_fields = ('created_at', 'updated_at', 'approved_at')
    date_hierarchy = 'created_at'

# ==================== ACADEMICS MODULE ====================
class ClassAdmin(admin.ModelAdmin):
    list_display = ('class_code', 'class_name', 'numeric_level', 'stream', 
                   'capacity', 'class_teacher', 'is_active')
    list_filter = ('numeric_level', 'stream', 'is_active')
    search_fields = ('class_code', 'class_name', 'class_teacher__username')
    list_per_page = 20

class ClassSubjectAllocationAdmin(admin.ModelAdmin):
    list_display = ('academic_year', 'class_id', 'subject', 'teacher', 
                   'periods_per_week', 'is_compulsory')
    list_filter = ('academic_year', 'class_id', 'is_compulsory')
    search_fields = ('subject__area_name', 'teacher__username', 'class_id__class_name')
    list_per_page = 20

# ==================== E-LEARNING MODELS ====================
class CourseAdmin(admin.ModelAdmin):
    list_display = ('course_code', 'course_title', 'learning_area', 'class_id', 
                   'credit_hours', 'is_published', 'created_by', 'created_at')
    list_filter = ('is_published', 'learning_area', 'class_id')
    search_fields = ('course_code', 'course_title', 'description', 'created_by__username')
    readonly_fields = ('created_at', 'updated_at', 'published_date')
    date_hierarchy = 'created_at'

class CourseModuleAdmin(admin.ModelAdmin):
    list_display = ('course', 'module_title', 'module_order', 'estimated_hours')
    list_filter = ('course',)
    search_fields = ('module_title', 'description', 'course__course_title')
    filter_horizontal = ('competencies',)

class LearningContentAdmin(admin.ModelAdmin):
    list_display = ('module', 'content_title', 'content_type', 'content_order', 
                   'is_published', 'created_by')
    list_filter = ('content_type', 'is_published', 'module__course')
    search_fields = ('content_title', 'description', 'module__module_title')
    readonly_fields = ('publish_date', 'created_at', 'updated_at')

class StudentEnrollmentAdmin(admin.ModelAdmin):
    list_display = ('student', 'course', 'enrollment_date', 'enrollment_status', 
                   'progress_percentage', 'completed_at')
    list_filter = ('enrollment_status', 'course', 'enrollment_date')
    search_fields = ('student__admission_no', 'student__full_name', 'course__course_title')
    readonly_fields = ('enrollment_date', 'completed_at')
    date_hierarchy = 'enrollment_date'

class ContentProgressAdmin(admin.ModelAdmin):
    list_display = ('enrollment', 'content', 'is_completed', 'completed_at', 
                   'time_spent_minutes', 'score')
    list_filter = ('is_completed', 'content__content_type')
    search_fields = ('enrollment__student__admission_no', 'content__content_title')
    readonly_fields = ('created_at', 'last_accessed', 'completed_at')

# ==================== FINANCE MODULE ====================
class FeeCategoryAdmin(admin.ModelAdmin):
    list_display = ('category_code', 'category_name', 'frequency', 'is_mandatory', 
                   'is_active', 'created_by', 'created_at')
    list_filter = ('frequency', 'is_mandatory', 'is_active')
    search_fields = ('category_code', 'category_name', 'description')
    list_per_page = 20

class FeeStructureAdmin(admin.ModelAdmin):
    list_display = ('academic_year', 'term', 'class_id', 'category', 'amount', 
                   'due_date', 'is_active', 'created_by')
    list_filter = ('academic_year', 'term', 'class_id', 'is_active')
    search_fields = ('category__category_name', 'class_id__class_name')
    readonly_fields = ('created_at',)

class StudentFeeInvoiceAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ('invoice_no', 'student', 'academic_year', 'term', 'invoice_date', 
                   'due_date', 'total_amount', 'amount_paid', 'balance_amount', 
                   'status', 'payment_status')
    list_filter = ('status', 'payment_status', 'academic_year', 'term', 'invoice_date')
    search_fields = ('invoice_no', 'student__admission_no', 'student__full_name')
    readonly_fields = ('invoice_no', 'created_at', 'updated_at', 'cancelled_at')
    actions = ['export_as_csv', 'mark_as_paid', 'cancel_invoices']
    date_hierarchy = 'invoice_date'
    
    fieldsets = (
        ('Invoice Information', {
            'fields': ('invoice_no', 'student', 'academic_year', 'term', 
                      'invoice_date', 'due_date')
        }),
        ('Amount Details', {
            'fields': ('subtotal', 'discount_amount', 'late_fee_amount', 
                      'total_amount', 'amount_paid', 'balance_amount')
        }),
        ('Status', {
            'fields': ('status', 'payment_status')
        }),
        ('Cancellation', {
            'fields': ('cancelled_by', 'cancelled_at', 'cancellation_reason'),
            'classes': ('collapse',)
        }),
        ('Audit', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def mark_as_paid(self, request, queryset):
        for invoice in queryset:
            invoice.amount_paid = invoice.total_amount
            invoice.save()
        self.message_user(request, f'{queryset.count()} invoice(s) marked as paid.')
    
    def cancel_invoices(self, request, queryset):
        updated = queryset.update(status='Cancelled', cancelled_at=timezone.now(), 
                                 cancelled_by=request.user)
        self.message_user(request, f'{updated} invoice(s) cancelled.')
    
    mark_as_paid.short_description = "Mark selected invoices as paid"
    cancel_invoices.short_description = "Cancel selected invoices"

class InvoiceItemAdmin(admin.ModelAdmin):
    list_display = ('invoice', 'fee_structure', 'description', 'quantity', 
                   'unit_price', 'amount', 'net_amount')
    list_filter = ('fee_structure__category',)
    search_fields = ('invoice__invoice_no', 'description', 'fee_structure__category__category_name')
    readonly_fields = ('amount', 'discount_amount', 'net_amount', 'created_at')

class FeeTransactionAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ('transaction_no', 'student', 'invoice', 'payment_date', 
                   'payment_mode', 'amount_kes', 'currency', 'status', 
                   'collected_by', 'verified_by')
    list_filter = ('status', 'payment_mode', 'currency', 'payment_date')
    search_fields = ('transaction_no', 'student__admission_no', 'invoice__invoice_no', 
                    'payment_reference')
    readonly_fields = ('transaction_no', 'amount_kes', 'created_at')
    actions = ['export_as_csv', 'verify_transactions', 'reverse_transactions']
    date_hierarchy = 'payment_date'
    
    def verify_transactions(self, request, queryset):
        updated = queryset.update(status='Completed', verified_by=request.user, 
                                verified_at=timezone.now())
        self.message_user(request, f'{updated} transaction(s) verified.')
    
    def reverse_transactions(self, request, queryset):
        for transaction in queryset:
            transaction.status = 'Reversed'
            transaction.reversed_by = request.user
            transaction.reversed_at = timezone.now()
            transaction.save()
        self.message_user(request, f'{queryset.count()} transaction(s) reversed.')
    
    verify_transactions.short_description = "Verify selected transactions"
    reverse_transactions.short_description = "Reverse selected transactions"

class GeneralLedgerAdmin(admin.ModelAdmin):
    list_display = ('transaction_date', 'gl_date', 'account_code', 'account_name', 
                   'debit_amount', 'credit_amount', 'reference_no', 'created_by')
    list_filter = ('gl_date', 'account_code')
    search_fields = ('account_code', 'account_name', 'reference_no', 'description')
    readonly_fields = ('created_at',)
    date_hierarchy = 'gl_date'

# ==================== ATTENDANCE & DISCIPLINE ====================
class AttendanceSessionAdmin(admin.ModelAdmin):
    list_display = ('session_date', 'session_type', 'class_id', 'subject', 
                   'period_number', 'conducted_by', 'is_active')
    list_filter = ('session_type', 'class_id', 'subject', 'session_date', 'is_active')
    search_fields = ('class_id__class_name', 'subject__area_name', 'conducted_by__username')
    date_hierarchy = 'session_date'

class StudentAttendanceAdmin(admin.ModelAdmin):
    list_display = ('session', 'student', 'attendance_status', 'check_in_time', 
                   'check_out_time', 'late_minutes', 'recorded_by')
    list_filter = ('attendance_status', 'session__session_date', 'session__class_id')
    search_fields = ('student__admission_no', 'session__class_id__class_name')
    readonly_fields = ('recorded_at',)
    date_hierarchy = 'recorded_at'

class DisciplineCategoryAdmin(admin.ModelAdmin):
    list_display = ('category_code', 'category_name', 'severity_level', 
                   'default_points', 'is_active')
    list_filter = ('severity_level', 'is_active')
    search_fields = ('category_code', 'category_name')
    list_per_page = 20

class DisciplineIncidentAdmin(admin.ModelAdmin):
    list_display = ('incident_code', 'incident_date', 'student', 'category', 
                   'severity_display', 'status', 'assigned_to', 'parent_notified')
    list_filter = ('status', 'category', 'incident_date', 'parent_notified')
    search_fields = ('incident_code', 'student__admission_no', 'description', 
                    'reported_by__username')
    readonly_fields = ('incident_code', 'created_at', 'updated_at', 'closed_at')
    actions = ['mark_as_resolved', 'notify_parents']
    date_hierarchy = 'incident_date'
    
    def severity_display(self, obj):
        return obj.category.severity_level
    severity_display.short_description = 'Severity'
    
    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(status='Resolved', resolution_date=timezone.now())
        self.message_user(request, f'{updated} incident(s) marked as resolved.')
    
    def notify_parents(self, request, queryset):
        updated = queryset.update(parent_notified=True, 
                                 parent_notification_date=timezone.now())
        self.message_user(request, f'Parent notification sent for {updated} incident(s).')
    
    mark_as_resolved.short_description = "Mark selected incidents as resolved"
    notify_parents.short_description = "Notify parents of selected incidents"

class StudentDisciplinePointsAdmin(admin.ModelAdmin):
    list_display = ('student', 'academic_year', 'term', 'total_points', 
                   'warnings_count', 'suspensions_count', 'current_status')
    list_filter = ('academic_year', 'term', 'current_status')
    search_fields = ('student__admission_no', 'student__full_name')
    readonly_fields = ('updated_at',)

# ==================== HUMAN RESOURCES ====================
class StaffAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ('staff_id', 'full_name', 'department', 'designation', 
                   'employment_type', 'employment_date', 'status', 'is_active_display')
    list_filter = ('department', 'employment_type', 'status', 'archived')
    search_fields = ('staff_id', 'first_name', 'last_name', 'national_id', 
                    'personal_email', 'personal_phone')
    readonly_fields = ('created_at', 'updated_at', 'archived')
    actions = ['export_as_csv', 'archive_staff', 'restore_staff']
    
    fieldsets = (
        ('Personal Details', {
            'fields': ('staff_id', 'user', 'title', 'first_name', 'middle_name', 
                      'last_name', 'date_of_birth', 'gender', 'marital_status')
        }),
        ('Contact Information', {
            'fields': ('personal_email', 'personal_phone', 'emergency_contact', 
                      'emergency_contact_name', 'emergency_relation')
        }),
        ('Address', {
            'fields': ('permanent_address', 'temporary_address', 'city', 'country')
        }),
        ('Identification', {
            'fields': ('national_id', 'passport_no', 'kra_pin', 'nssf_no', 'nhif_no'),
            'classes': ('collapse',)
        }),
        ('Employment Details', {
            'fields': ('employment_type', 'employment_date', 'confirmation_date', 
                      'contract_end_date', 'department', 'designation', 'job_grade', 
                      'reporting_to')
        }),
        ('Qualifications', {
            'fields': ('highest_qualification', 'specialization', 'university', 
                      'year_of_graduation'),
            'classes': ('collapse',)
        }),
        ('Bank & Salary', {
            'fields': ('bank_name', 'bank_branch', 'account_name', 'account_number',
                      'basic_salary', 'salary_currency', 'payment_mode'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('status', 'status_date', 'status_reason', 'exit_interview_conducted', 
                      'exit_interview_notes')
        }),
        ('Documents', {
            'fields': ('photo_url', 'documents'),
            'classes': ('collapse',)
        }),
        ('Audit', {
            'fields': ('created_by', 'updated_by', 'created_at', 'updated_at', 'archived'),
            'classes': ('collapse',)
        }),
    )
    
    def is_active_display(self, obj):
        return obj.status == 'Active' and not obj.archived
    is_active_display.boolean = True
    is_active_display.short_description = 'Active'
    
    def archive_staff(self, request, queryset):
        updated = queryset.update(archived=True)
        self.message_user(request, f'{updated} staff member(s) archived successfully.')
    
    def restore_staff(self, request, queryset):
        updated = queryset.update(archived=False)
        self.message_user(request, f'{updated} staff member(s) restored successfully.')
    
    archive_staff.short_description = "Archive selected staff"
    restore_staff.short_description = "Restore selected staff"

class StaffLeaveAdmin(admin.ModelAdmin):
    list_display = ('staff', 'leave_type', 'start_date', 'end_date', 'total_days', 
                   'status', 'applied_date', 'approved_by')
    list_filter = ('leave_type', 'status', 'applied_date', 'start_date')
    search_fields = ('staff__staff_id', 'staff__full_name', 'reason')
    readonly_fields = ('total_days', 'applied_date', 'created_at', 'updated_at')
    actions = ['approve_leaves', 'reject_leaves']
    date_hierarchy = 'applied_date'
    
    def approve_leaves(self, request, queryset):
        updated = queryset.update(status='Approved', approved_by=request.user, 
                                 approved_date=timezone.now())
        self.message_user(request, f'{updated} leave request(s) approved.')
    
    def reject_leaves(self, request, queryset):
        updated = queryset.update(status='Rejected')
        self.message_user(request, f'{updated} leave request(s) rejected.')
    
    approve_leaves.short_description = "Approve selected leaves"
    reject_leaves.short_description = "Reject selected leaves"

class LeaveBalanceAdmin(admin.ModelAdmin):
    list_display = ('staff', 'leave_year', 'leave_type', 'total_entitled', 
                   'taken_so_far', 'balance', 'carried_over')
    list_filter = ('leave_year', 'leave_type')
    search_fields = ('staff__staff_id', 'staff__full_name')
    readonly_fields = ('balance', 'updated_at')

# ==================== PAYROLL MANAGEMENT ====================
class PayrollComponentAdmin(admin.ModelAdmin):
    list_display = ('component_code', 'component_name', 'component_type', 
                   'calculation_type', 'is_active', 'effective_date')
    list_filter = ('component_type', 'calculation_type', 'is_active', 'statutory_component')
    search_fields = ('component_code', 'component_name', 'description')
    list_per_page = 20

class StaffPayrollComponentAdmin(admin.ModelAdmin):
    list_display = ('staff', 'component', 'is_active', 'effective_from', 
                   'effective_to', 'approved_by')
    list_filter = ('is_active', 'component__component_type', 'approved_by')
    search_fields = ('staff__staff_id', 'staff__full_name', 'component__component_name')
    readonly_fields = ('created_at', 'updated_at', 'approved_date')

class PayrollPeriodAdmin(admin.ModelAdmin):
    list_display = ('period_code', 'period_name', 'start_date', 'end_date', 
                   'pay_date', 'status', 'total_staff', 'total_net')
    list_filter = ('status', 'start_date', 'end_date')
    search_fields = ('period_code', 'period_name')
    readonly_fields = ('processed_date', 'approved_date', 'closed_date', 
                      'locked_date', 'created_at', 'updated_at')
    actions = ['approve_period', 'close_period', 'lock_period']
    date_hierarchy = 'start_date'
    
    def approve_period(self, request, queryset):
        updated = queryset.update(status='Approved', approved_by=request.user, 
                                 approved_date=timezone.now())
        self.message_user(request, f'{updated} payroll period(s) approved.')
    
    def close_period(self, request, queryset):
        updated = queryset.update(status='Closed', closed_by=request.user, 
                                 closed_date=timezone.now())
        self.message_user(request, f'{updated} payroll period(s) closed.')
    
    def lock_period(self, request, queryset):
        updated = queryset.update(is_locked=True, locked_by=request.user, 
                                 locked_date=timezone.now())
        self.message_user(request, f'{updated} payroll period(s) locked.')
    
    approve_period.short_description = "Approve selected periods"
    close_period.short_description = "Close selected periods"
    lock_period.short_description = "Lock selected periods"

class PayrollRecordAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ('payroll_period', 'staff', 'basic_salary', 'gross_salary', 
                   'total_deductions', 'net_salary', 'payment_status')
    list_filter = ('payroll_period', 'payment_status', 'is_approved', 'is_paid')
    search_fields = ('staff__staff_id', 'staff__full_name', 'payroll_period__period_code')
    readonly_fields = ('created_at', 'updated_at', 'calculated_date', 
                      'approved_date', 'paid_date')
    actions = ['export_as_csv', 'approve_records', 'mark_as_paid']

class StaffLoanAdmin(admin.ModelAdmin):
    list_display = ('loan_id', 'staff', 'loan_type', 'loan_amount', 'interest_rate', 
                   'repayment_months', 'status', 'outstanding_balance')
    list_filter = ('loan_type', 'status', 'applied_date')
    search_fields = ('loan_id', 'staff__staff_id', 'staff__full_name')
    readonly_fields = ('loan_id', 'outstanding_balance', 'overdue_amount', 
                      'overdue_days', 'created_at', 'updated_at')
    actions = ['approve_loans', 'disburse_loans']
    date_hierarchy = 'applied_date'

class LoanRepaymentAdmin(admin.ModelAdmin):
    list_display = ('loan', 'repayment_date', 'amount_paid', 'principal_amount', 
                   'interest_amount', 'payment_method', 'is_overdue')
    list_filter = ('payment_method', 'is_overdue', 'repayment_date')
    search_fields = ('loan__loan_id', 'loan__staff__staff_id')
    readonly_fields = ('processed_date',)
    date_hierarchy = 'repayment_date'

# ==================== LIBRARY MODULE ====================
class BookResourceAdmin(admin.ModelAdmin):
    list_display = ('school_code', 'title', 'authors', 'book_category', 'subject', 
                   'total_copies', 'available_copies', 'condition_status', 'is_active')
    list_filter = ('book_category', 'subject', 'condition_status', 'is_active', 
                  'language', 'is_reference_only')
    search_fields = ('school_code', 'title', 'authors', 'isbn', 'keywords')
    readonly_fields = ('added_date', 'last_updated', 'available_copies')
    filter_horizontal = ('grade_levels',)
    list_per_page = 20

# ==================== SYSTEM & AUDIT ====================
class AuditLogAdmin(ReadOnlyAdminMixin, admin.ModelAdmin, ExportCsvMixin):
    list_display = ('event_time', 'event_type', 'user', 'username', 'table_name', 
                   'operation', 'ip_address')
    list_filter = ('event_type', 'operation', 'table_name', 'event_time')
    search_fields = ('username', 'user__username', 'table_name', 'ip_address', 
                    'endpoint')
    readonly_fields = ('event_time', 'request_id')
    date_hierarchy = 'event_time'
    actions = ['export_as_csv']

class BackupHistoryAdmin(admin.ModelAdmin):
    list_display = ('backup_name', 'backup_type', 'status', 'backup_start', 
                   'backup_end', 'file_size', 'initiated_by')
    list_filter = ('backup_type', 'status', 'verification_status', 'restore_point')
    search_fields = ('backup_name', 'file_path', 'database_version', 'error_message')
    readonly_fields = ('backup_start', 'backup_end', 'verification_time', 
                      'created_at')
    date_hierarchy = 'backup_start'

class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ('setting_key', 'setting_value_truncated', 'setting_type', 
                   'category', 'is_public', 'updated_at')
    list_filter = ('category', 'setting_type', 'is_public', 'requires_restart')
    search_fields = ('setting_key', 'setting_value', 'description')
    readonly_fields = ('updated_at',)
    list_editable = ('is_public',)
    
    def setting_value_truncated(self, obj):
        return obj.setting_value[:50] + '...' if len(obj.setting_value) > 50 else obj.setting_value
    setting_value_truncated.short_description = 'Setting Value'

# ==================== UTILITY TABLES ====================
class HolidayAdmin(admin.ModelAdmin):
    list_display = ('holiday_date', 'holiday_name', 'holiday_type', 'is_working_day', 
                   'academic_year', 'created_by')
    list_filter = ('holiday_type', 'is_working_day', 'academic_year')
    search_fields = ('holiday_name', 'description')
    date_hierarchy = 'holiday_date'

class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'notification_type', 'recipient_type', 'priority', 
                   'status', 'sent_by', 'sent_at', 'read_at')
    list_filter = ('notification_type', 'recipient_type', 'priority', 'status', 
                  'sent_at')
    search_fields = ('title', 'message', 'recipient_id')
    readonly_fields = ('sent_at', 'read_at')
    actions = ['mark_as_read', 'mark_as_unread']
    date_hierarchy = 'sent_at'
    
    def mark_as_read(self, request, queryset):
        updated = queryset.update(status='Read', read_at=timezone.now())
        self.message_user(request, f'{updated} notification(s) marked as read.')
    
    def mark_as_unread(self, request, queryset):
        updated = queryset.update(status='Unread', read_at=None)
        self.message_user(request, f'{updated} notification(s) marked as unread.')
    
    mark_as_read.short_description = "Mark selected as read"
    mark_as_unread.short_description = "Mark selected as unread"

class TimetableAdmin(admin.ModelAdmin):
    list_display = ('class_id', 'day_of_week', 'period', 'subject', 'teacher', 
                   'room', 'academic_year', 'term', 'is_active')
    list_filter = ('class_id', 'day_of_week', 'academic_year', 'term', 'is_active')
    search_fields = ('class_id__class_name', 'subject__area_name', 'teacher__username')
    list_per_page = 30

# ==================== CBE REPORT CARDS ====================
class CBEReportCardAdmin(admin.ModelAdmin):
    list_display = ('report_id', 'report_type', 'student', 'class_id', 'academic_year', 
                   'term', 'is_published', 'generated_by', 'generated_date')
    list_filter = ('report_type', 'academic_year', 'term', 'is_published', 'is_printed')
    search_fields = ('report_id', 'student__admission_no', 'class_id__class_name', 
                    'teacher__username')
    readonly_fields = ('report_id', 'generated_date', 'published_date', 'printed_date', 
                      'created_at')
    actions = ['publish_reports', 'mark_as_printed']
    date_hierarchy = 'generated_date'
    
    def publish_reports(self, request, queryset):
        updated = queryset.update(is_published=True, published_date=timezone.now())
        self.message_user(request, f'{updated} report(s) published.')
    
    def mark_as_printed(self, request, queryset):
        updated = queryset.update(is_printed=True, printed_date=timezone.now())
        self.message_user(request, f'{updated} report(s) marked as printed.')
    
    publish_reports.short_description = "Publish selected reports"
    mark_as_printed.short_description = "Mark selected reports as printed"

class StudentCreditAdmin(admin.ModelAdmin):
    list_display = ('student', 'credit_amount', 'credit_type', 'credit_date', 
                   'credit_expiry', 'is_utilized', 'is_expired_display', 'is_active_display')
    list_filter = ('credit_type', 'is_utilized', 'academic_year', 'term')
    search_fields = ('student__admission_no', 'notes')
    readonly_fields = ('created_at', 'updated_at', 'utilized_date')
    actions = ['mark_as_utilized']
    date_hierarchy = 'credit_date'
    
    def is_expired_display(self, obj):
        return obj.is_expired
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'
    
    def is_active_display(self, obj):
        return obj.is_active
    is_active_display.boolean = True
    is_active_display.short_description = 'Active'
    
    def mark_as_utilized(self, request, queryset):
        updated = queryset.update(is_utilized=True, utilized_date=timezone.now())
        self.message_user(request, f'{updated} credit(s) marked as utilized.')
    
    mark_as_utilized.short_description = "Mark selected credits as utilized"

# ==================== PARENT MODEL ====================
class ParentAdmin(admin.ModelAdmin):
    list_display = ('parent_id', 'full_name', 'phone', 'email', 'relation_to_student', 
                   'is_active', 'students_count')
    list_filter = ('is_active', 'relation_to_student', 'country')
    search_fields = ('parent_id', 'first_name', 'last_name', 'phone', 'email')
    filter_horizontal = ('students',)
    
    def students_count(self, obj):
        return obj.students.count()
    students_count.short_description = 'Number of Students'

# ==================== E-LEARNING ADDITIONAL MODELS ====================
class ELearningQuizAdmin(admin.ModelAdmin):
    list_display = ('quiz_title', 'content', 'time_limit_minutes', 'max_attempts', 
                   'passing_score', 'is_published', 'created_by')
    list_filter = ('is_published', 'randomize_questions', 'show_results')
    search_fields = ('quiz_title', 'content__content_title', 'created_by__username')
    readonly_fields = ('published_date', 'created_at', 'updated_at')

class QuizQuestionAdmin(admin.ModelAdmin):
    list_display = ('quiz', 'question_text_truncated', 'question_type', 'question_order', 
                   'points')
    list_filter = ('question_type', 'quiz')
    search_fields = ('question_text', 'quiz__quiz_title')
    
    def question_text_truncated(self, obj):
        return obj.question_text[:100] + '...' if len(obj.question_text) > 100 else obj.question_text
    question_text_truncated.short_description = 'Question'

class QuizAttemptAdmin(admin.ModelAdmin):
    list_display = ('enrollment', 'quiz', 'attempt_number', 'started_at', 'completed_at', 
                   'score', 'percentage', 'is_passed')
    list_filter = ('quiz', 'is_passed', 'started_at')
    search_fields = ('enrollment__student__admission_no', 'quiz__quiz_title')
    readonly_fields = ('started_at', 'completed_at', 'percentage', 'is_passed')

class DiscussionForumAdmin(admin.ModelAdmin):
    list_display = ('course', 'forum_title', 'is_active', 'is_moderated', 'created_by', 
                   'created_at')
    list_filter = ('is_active', 'is_moderated', 'course')
    search_fields = ('forum_title', 'description', 'course__course_title')
    readonly_fields = ('created_at',)

class ForumPostAdmin(admin.ModelAdmin):
    list_display = ('forum', 'author', 'post_title_truncated', 'parent_post', 
                   'is_pinned', 'is_locked', 'is_approved', 'upvotes', 'downvotes', 
                   'created_at')
    list_filter = ('is_pinned', 'is_locked', 'is_approved', 'forum')
    search_fields = ('post_title', 'content', 'author__username')
    
    def post_title_truncated(self, obj):
        title = obj.post_title or obj.content[:50]
        return title[:100] + '...' if len(title) > 100 else title
    post_title_truncated.short_description = 'Title/Content'

# ==================== REGISTER MODELS ====================
# User Management
admin.site.register(User, CustomUserAdmin)
admin.site.register(UserSession, UserSessionAdmin)
admin.site.register(PasswordHistory, PasswordHistoryAdmin)

# Security
admin.site.register(IPWhitelist, IPWhitelistAdmin)

# Student Management
admin.site.register(Student, StudentAdmin)
admin.site.register(StudentAcademicHistory, StudentAcademicHistoryAdmin)

# CBE Academic Structure
admin.site.register(AcademicYear, AcademicYearAdmin)
admin.site.register(Term, TermAdmin)
admin.site.register(LearningArea, LearningAreaAdmin)
admin.site.register(Strand, StrandAdmin)
admin.site.register(SubStrand, SubStrandAdmin)
admin.site.register(Competency, CompetencyAdmin)

# Summative Assessment (CBE)
admin.site.register(AssessmentWindow, AssessmentWindowAdmin)
admin.site.register(SummativeAssessment, SummativeAssessmentAdmin)
admin.site.register(SummativeRating, SummativeRatingAdmin)
admin.site.register(TermlySummary, TermlySummaryAdmin)

# Academics Module
admin.site.register(Class, ClassAdmin)
admin.site.register(ClassSubjectAllocation, ClassSubjectAllocationAdmin)

# E-Learning
admin.site.register(Course, CourseAdmin)
admin.site.register(CourseModule, CourseModuleAdmin)
admin.site.register(LearningContent, LearningContentAdmin)
admin.site.register(StudentEnrollment, StudentEnrollmentAdmin)
admin.site.register(ContentProgress, ContentProgressAdmin)
admin.site.register(ELearningQuiz, ELearningQuizAdmin)
admin.site.register(QuizQuestion, QuizQuestionAdmin)
admin.site.register(QuizAttempt, QuizAttemptAdmin)
admin.site.register(DiscussionForum, DiscussionForumAdmin)
admin.site.register(ForumPost, ForumPostAdmin)

# Finance Module
admin.site.register(FeeCategory, FeeCategoryAdmin)
admin.site.register(FeeStructure, FeeStructureAdmin)
admin.site.register(StudentFeeInvoice, StudentFeeInvoiceAdmin)
admin.site.register(InvoiceItem, InvoiceItemAdmin)
admin.site.register(FeeTransaction, FeeTransactionAdmin)
admin.site.register(GeneralLedger, GeneralLedgerAdmin)

# Attendance & Discipline
admin.site.register(AttendanceSession, AttendanceSessionAdmin)
admin.site.register(StudentAttendance, StudentAttendanceAdmin)
admin.site.register(DisciplineCategory, DisciplineCategoryAdmin)
admin.site.register(DisciplineIncident, DisciplineIncidentAdmin)
admin.site.register(StudentDisciplinePoints, StudentDisciplinePointsAdmin)

# Human Resources
admin.site.register(Staff, StaffAdmin)
admin.site.register(StaffLeave, StaffLeaveAdmin)
admin.site.register(LeaveBalance, LeaveBalanceAdmin)

# Payroll Management
admin.site.register(PayrollComponent, PayrollComponentAdmin)
admin.site.register(StaffPayrollComponent, StaffPayrollComponentAdmin)
admin.site.register(PayrollPeriod, PayrollPeriodAdmin)
admin.site.register(PayrollRecord, PayrollRecordAdmin)
admin.site.register(StaffLoan, StaffLoanAdmin)
admin.site.register(LoanRepayment, LoanRepaymentAdmin)

# Library Module
admin.site.register(BookResource, BookResourceAdmin)

# System & Audit
admin.site.register(AuditLog, AuditLogAdmin)
admin.site.register(BackupHistory, BackupHistoryAdmin)
admin.site.register(SystemSetting, SystemSettingAdmin)

# Utility Tables
admin.site.register(Holiday, HolidayAdmin)
admin.site.register(Notification, NotificationAdmin)
admin.site.register(Timetable, TimetableAdmin)

# CBE Report Cards
admin.site.register(CBEReportCard, CBEReportCardAdmin)
admin.site.register(StudentCredit, StudentCreditAdmin)

# Parent Model
admin.site.register(Parent, ParentAdmin)

# ==================== CUSTOM ADMIN SITE CONFIGURATION ====================
# admin.site.site_header = "School Management System Administration"
# admin.site.site_title = "SMS Admin Portal"
# admin.site.index_title = "Welcome to School Management System Administration"