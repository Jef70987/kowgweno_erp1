# models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.utils import timezone
from django.core.exceptions import ValidationError
import uuid

# ==================== UTILITY FUNCTIONS ====================
def generate_inv_id():
    return f"INV-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

def generate_txn_id():
    return f"TXN-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

def generate_inc_id():
    return f"INC-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"

def generate_assessment_code():
    return f"ASS-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

def generate_report_id():
    return f"REP-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

# ==================== USER MANAGEMENT ====================
class User(AbstractUser):
    ROLE_CHOICES = [
        ('system_admin', 'System Administrator'),
        ('principal', 'Principal'),
        ('deputy_principal', 'Deputy Principal'),
        ('director_studies', 'Director of Studies'),
        ('registrar', 'Registrar'),
        ('bursar', 'Bursar'),
        ('accountant', 'Accountant'),
        ('teacher', 'Teacher'),
        ('hr_manager', 'HR Manager'),
        ('student', 'Student'),
        ('parent', 'Parent'),
    ]
   
    role = models.CharField(max_length=30, choices=ROLE_CHOICES)
    department = models.CharField(max_length=50, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)
    last_password_change = models.DateTimeField(default=timezone.now)
    failed_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(blank=True, null=True)
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'  # Django will use email for authenticate()
    REQUIRED_FIELDS = ['username'] 
    class Meta:
        indexes = [
            models.Index(fields=['role']),
            models.Index(fields=['is_active'], name='idx_active_users'),
        ]

class UserSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    access_token = models.TextField()
    refresh_token = models.TextField()
    client_ip = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)
    device_fingerprint = models.CharField(max_length=64, blank=True, null=True)
    login_time = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    
    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['access_token']),
            models.Index(fields=['expires_at']),
        ]


# ==================== SECURITY & IP WHITELISTING ====================
class IPWhitelist(models.Model):
    """
    IP Whitelisting for enhanced security
    Controls which IPs can access the system
    """
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
        ('Blocked', 'Blocked'),
    ]
    
    ACCESS_LEVEL_CHOICES = [
        ('Full Access', 'Full Access'),
        ('Limited Access', 'Limited Access'),
        ('Read Only', 'Read Only'),
        ('API Only', 'API Only'),
    ]
    
    ip_address = models.GenericIPAddressField(unique=True, verbose_name="IP Address")
    description = models.CharField(max_length=200, verbose_name="Description/Purpose")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')
    access_level = models.CharField(max_length=20, choices=ACCESS_LEVEL_CHOICES, default='Full Access')
    
    # User/Role association
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                           verbose_name="Associated User", related_name='whitelisted_ips')
    allowed_roles = models.JSONField(default=list, blank=True, 
                                     verbose_name="Allowed Roles (leave empty for all)")
    
    # Time restrictions
    allowed_days = models.JSONField(default=list, blank=True, 
                                   verbose_name="Allowed Days (0=Monday, 1=Tuesday, etc.)")
    time_start = models.TimeField(null=True, blank=True, verbose_name="Access Start Time")
    time_end = models.TimeField(null=True, blank=True, verbose_name="Access End Time")
    
    # Geolocation info (optional)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    isp = models.CharField(max_length=200, blank=True, null=True, verbose_name="Internet Service Provider")
    
    # Usage tracking
    last_used = models.DateTimeField(null=True, blank=True, verbose_name="Last Access Time")
    total_access_count = models.IntegerField(default=0, verbose_name="Total Access Count")
    failed_attempts = models.IntegerField(default=0, verbose_name="Failed Login Attempts")
    
    # Security flags
    require_2fa = models.BooleanField(default=False, verbose_name="Require 2FA")
    notify_on_access = models.BooleanField(default=False, verbose_name="Notify on Access")
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, 
                                 related_name='created_ip_whitelists', verbose_name="Created By")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name="Expires At")
    
    class Meta:
        verbose_name = "IP Whitelist"
        verbose_name_plural = "IP Whitelist"
        ordering = ['ip_address']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['status']),
            models.Index(fields=['user']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.description}"
    
    def is_active_now(self):
        """Check if IP is currently allowed based on time restrictions"""
        if self.status == 'Active':
            return True
        
        
        now = timezone.now()
        
        # Check time restrictions
        if self.time_start and self.time_end:
            current_time = now.time()
            if not (self.time_start <= current_time <= self.time_end):
                return False
        
        # Check day restrictions
        if self.allowed_days:
            current_day = now.weekday()
            if current_day not in self.allowed_days:
                return False
        
        # Check expiration
        if self.expires_at and now > self.expires_at:
            return False
        
        return True
    
    def increment_access_count(self):
        """Increment access count and update last used"""
        self.total_access_count += 1
        self.last_used = timezone.now()
        self.save(update_fields=['total_access_count', 'last_used'])

class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_history')
    password_hash = models.CharField(max_length=255)
    changed_at = models.DateTimeField(auto_now_add=True)
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='changed_passwords')

# ==================== STUDENT MANAGEMENT ====================
class Student(models.Model):
    GENDER_CHOICES = [('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')]
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Graduated', 'Graduated'),
        ('Transferred', 'Transferred'),
        ('Withdrawn', 'Withdrawn'),
        ('Suspended', 'Suspended'),
    ]
    ADMISSION_TYPE_CHOICES = [
        ('Regular', 'Regular'),
        ('Transfer', 'Transfer'),
        ('Re-admission', 'Re-admission'),
    ]
    
    # Core Information
    admission_no = models.CharField(max_length=30, unique=True)
    student_uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    nationality = models.CharField(max_length=50, default='Kenya')
    religion = models.CharField(max_length=30, blank=True, null=True)
    blood_group = models.CharField(max_length=5, blank=True, null=True)
    
    # User account for portal access
    user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True, 
                                related_name='student_profile')
    
    # Contact Information
    address = models.TextField(validators=[RegexValidator(regex='.{10,}', message='Address must be at least 10 characters')])
    city = models.CharField(max_length=50)
    country = models.CharField(max_length=50, default='Kenya')
    phone = models.CharField(max_length=20, blank=True, null=True, 
                             validators=[RegexValidator(regex=r'^\+?[0-9\s\-\(\)]+$')])
    email = models.EmailField(blank=True, null=True)
    
    # Academic Information
    current_class = models.ForeignKey('Class', on_delete=models.SET_NULL, null=True, related_name='current_students')
    current_section = models.CharField(max_length=10, blank=True, null=True)
    stream = models.CharField(max_length=20, blank=True, null=True)
    roll_number = models.IntegerField(blank=True, null=True)
    admission_date = models.DateField(default=timezone.now)
    admission_type = models.CharField(max_length=20, choices=ADMISSION_TYPE_CHOICES, default='Regular')
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')
    status_reason = models.TextField(blank=True, null=True)
    status_changed_date = models.DateField(blank=True, null=True)
    expected_graduation_date = models.DateField(blank=True, null=True)
    
    # Guardian Information
    father_name = models.CharField(max_length=100, blank=True, null=True)
    father_phone = models.CharField(max_length=20, blank=True, null=True)
    father_email = models.EmailField(blank=True, null=True)
    father_occupation = models.CharField(max_length=50, blank=True, null=True)
    mother_name = models.CharField(max_length=100, blank=True, null=True)
    mother_phone = models.CharField(max_length=20, blank=True, null=True)
    mother_email = models.EmailField(blank=True, null=True)
    mother_occupation = models.CharField(max_length=50, blank=True, null=True)
    
    guardian_name = models.CharField(max_length=100)
    guardian_relation = models.CharField(max_length=30)
    guardian_phone = models.CharField(max_length=20)
    guardian_email = models.EmailField(blank=True, null=True)
    guardian_address = models.TextField(blank=True, null=True)
    
    # Medical & Emergency
    medical_conditions = models.TextField(blank=True, null=True)
    allergies = models.TextField(blank=True, null=True)
    medication = models.TextField(blank=True, null=True)
    emergency_contact = models.CharField(max_length=20)
    emergency_contact_name = models.CharField(max_length=100)
    
    # Academic History
    previous_school = models.CharField(max_length=100, blank=True, null=True)
    previous_class = models.CharField(max_length=20, blank=True, null=True)
    transfer_certificate_no = models.CharField(max_length=50, blank=True, null=True)
    
    # System
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='created_students')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_students')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived = models.BooleanField(default=False)
    archived_at = models.DateTimeField(blank=True, null=True)
    
    # Full name property
    @property
    def full_name(self):
        return f"{self.first_name} {self.middle_name + ' ' if self.middle_name else ''}{self.last_name}"
    
    class Meta:
        indexes = [
            models.Index(fields=['admission_no']),
            models.Index(fields=['current_class']),
            models.Index(fields=['status']),
            models.Index(fields=['guardian_phone']),
            models.Index(fields=['user']),
        ]
    
    def __str__(self):
        return f"{self.full_name} ({self.admission_no})"

class StudentAcademicHistory(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='academic_history')
    academic_year = models.CharField(max_length=9)  # Format: 2024-2025
    class_id = models.ForeignKey('Class', on_delete=models.CASCADE)
    section = models.CharField(max_length=10, blank=True, null=True)
    stream = models.CharField(max_length=20, blank=True, null=True)
    roll_number = models.IntegerField(blank=True, null=True)
    class_teacher = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    promoted = models.BooleanField(default=False)
    promotion_date = models.DateField(blank=True, null=True)
    remarks = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['student', 'academic_year']
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['academic_year']),
        ]

# ==================== CBE ACADEMIC STRUCTURE ====================
class AcademicYear(models.Model):
    """Academic Year e.g., 2024-2025"""
    year_code = models.CharField(max_length=9, unique=True)  # Format: 2024-2025
    year_name = models.CharField(max_length=50)
    start_date = models.DateField()
    end_date = models.DateField()
    is_current = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-start_date']
    
    def __str__(self):
        return self.year_name

class Term(models.Model):
    """School Terms (1, 2, 3)"""
    TERM_CHOICES = [
        ('Term 1', 'Term 1'),
        ('Term 2', 'Term 2'),
        ('Term 3', 'Term 3'),
    ]
    
    academic_year = models.ForeignKey(AcademicYear, on_delete=models.CASCADE, related_name='terms')
    term = models.CharField(max_length=10, choices=TERM_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField()
    is_current = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['academic_year', 'term']
        ordering = ['academic_year', 'term']
    
    def __str__(self):
        return f"{self.term} - {self.academic_year.year_name}"

class LearningArea(models.Model):
    """CBE Learning Areas (Core, Optional, Extracurricular)"""
    AREA_TYPE_CHOICES = [
        ('Core', 'Core'),
        ('Optional', 'Optional'),
        ('Extracurricular', 'Extracurricular'),
    ]
    
    area_code = models.CharField(max_length=10, unique=True)
    area_name = models.CharField(max_length=100)
    short_name = models.CharField(max_length=20, blank=True, null=True)
    area_type = models.CharField(max_length=20, choices=AREA_TYPE_CHOICES)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['area_code']
    
    def __str__(self):
        return f"{self.area_code} - {self.area_name}"

class Strand(models.Model):
    """Strands within Learning Areas"""
    learning_area = models.ForeignKey(LearningArea, on_delete=models.CASCADE, related_name='strands')
    strand_code = models.CharField(max_length=10)
    strand_name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    display_order = models.IntegerField(default=0)
    
    class Meta:
        unique_together = ['learning_area', 'strand_code']
        ordering = ['learning_area', 'display_order']
    
    def __str__(self):
        return f"{self.strand_code}: {self.strand_name}"

class SubStrand(models.Model):
    """Sub-Strands within Strands"""
    strand = models.ForeignKey(Strand, on_delete=models.CASCADE, related_name='substrands')
    substrand_code = models.CharField(max_length=15)
    substrand_name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    display_order = models.IntegerField(default=0)
    
    class Meta:
        unique_together = ['strand', 'substrand_code']
        ordering = ['strand', 'display_order']
    
    def __str__(self):
        return f"{self.substrand_code}: {self.substrand_name}"

class Competency(models.Model):
    """Specific Competencies within Sub-Strands"""
    substrand = models.ForeignKey(SubStrand, on_delete=models.CASCADE, related_name='competencies')
    competency_code = models.CharField(max_length=20)
    competency_statement = models.TextField()
    performance_indicator = models.TextField(blank=True, null=True)
    is_core_competency = models.BooleanField(default=True)
    display_order = models.IntegerField(default=0)
    
    class Meta:
        unique_together = ['substrand', 'competency_code']
        ordering = ['substrand', 'display_order']
    
    def __str__(self):
        return f"{self.competency_code}: {self.competency_statement[:100]}..."

# ==================== SUMMATIVE ASSESSMENT MODELS (CBE) ====================
class AssessmentWindow(models.Model):
    """Pre-defined assessment windows (Opener, Mid-Term, End-Term)"""
    ASSESSMENT_TYPE_CHOICES = [
        ('Opener', 'Opener'),
        ('Mid-Term', 'Mid-Term'),
        ('End-Term', 'End-Term'),
    ]
    
    term = models.ForeignKey(Term, on_delete=models.CASCADE, related_name='assessment_windows')
    assessment_type = models.CharField(max_length=20, choices=ASSESSMENT_TYPE_CHOICES)
    weight_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0,
                                           validators=[MinValueValidator(0), MaxValueValidator(100)])
    open_date = models.DateField()
    close_date = models.DateField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['term', 'assessment_type']
        ordering = ['term', 'open_date']
    
    def __str__(self):
        return f"{self.assessment_type} - {self.term}"

class SummativeAssessment(models.Model):
    """Summative Assessment Definition for CBE"""
    assessment_code = models.CharField(max_length=30, unique=True, default=generate_assessment_code)
    assessment_window = models.ForeignKey(AssessmentWindow, on_delete=models.CASCADE, related_name='assessments')
    class_id = models.ForeignKey('Class', on_delete=models.CASCADE, related_name='summative_assessments')
    learning_area = models.ForeignKey(LearningArea, on_delete=models.CASCADE, related_name='cbe_assessments')
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_summative_assessments')
    
    # Competencies being assessed
    competencies = models.ManyToManyField(Competency, related_name='summative_assessments', blank=True)
    
    # Status
    status = models.CharField(max_length=20, choices=[
        ('Draft', 'Draft'),
        ('Published', 'Published'),
        ('Locked', 'Locked'),
        ('Archived', 'Archived'),
    ], default='Draft')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['assessment_code']),
            models.Index(fields=['class_id']),
            models.Index(fields=['learning_area']),
        ]
    
    def __str__(self):
        return f"{self.assessment_window.assessment_type} - {self.class_id.class_name} - {self.learning_area.area_name}"

class SummativeRating(models.Model):
    """Individual competency ratings for summative assessments"""
    RATING_CHOICES = [
        ('BE', 'Below Expectation (0-39%)'),
        ('AE', 'Approaching Expectation (40-59%)'),
        ('ME', 'Meeting Expectation (60-79%)'),
        ('EE', 'Exceeding Expectation (80-100%)'),
    ]
    
    # Hidden internal values for calculation
    RATING_VALUES = {
        'BE': 1,
        'AE': 2,
        'ME': 3,
        'EE': 4,
    }
    
    assessment = models.ForeignKey(SummativeAssessment, on_delete=models.CASCADE, related_name='ratings')
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='summative_ratings')
    competency = models.ForeignKey(Competency, on_delete=models.CASCADE, related_name='student_ratings')
    
    rating = models.CharField(max_length=2, choices=RATING_CHOICES)
    teacher_comment = models.TextField(blank=True, null=True)
    
    # Auto-calculated internal value
    internal_value = models.IntegerField(default=0)
    
    # Audit
    rated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='given_ratings')
    rated_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['assessment', 'student', 'competency']
        indexes = [
            models.Index(fields=['assessment']),
            models.Index(fields=['student']),
            models.Index(fields=['competency']),
            models.Index(fields=['rating']),
        ]
    
    def save(self, *args, **kwargs):
        # Auto-calculate internal value
        self.internal_value = self.RATING_VALUES.get(self.rating, 1)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.student.admission_no} - {self.competency.competency_code}: {self.rating}"

class TermlySummary(models.Model):
    """Aggregated termly results for each student per learning area"""
    PROGRESSION_STATUS_CHOICES = [
        ('Ready', 'Ready'),
        ('Needs Support', 'Needs Support'),
        ('Intervention Required', 'Intervention Required'),
    ]
    PROMOTION_STATUS_CHOICES = [
        ('Promoted', 'Promoted'),
        ('Retained', 'Retained'),
        ('Under Review', 'Under Review'),
    ]
    
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='termly_summaries')
    term = models.ForeignKey(Term, on_delete=models.CASCADE, related_name='student_summaries')
    learning_area = models.ForeignKey(LearningArea, on_delete=models.CASCADE, related_name='student_summaries')
    
    # Weighted calculations
    opener_weighted = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    midterm_weighted = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    endterm_weighted = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    
    final_internal_value = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    final_rating = models.CharField(max_length=2, choices=SummativeRating.RATING_CHOICES, blank=True, null=True)
    
    # Competency summary
    total_competencies = models.IntegerField(default=0)
    be_count = models.IntegerField(default=0)
    ae_count = models.IntegerField(default=0)
    me_count = models.IntegerField(default=0)
    ee_count = models.IntegerField(default=0)
    
    # Flags
    flags = models.JSONField(default=list, blank=True)  # List of flagged competencies
    progression_status = models.CharField(max_length=30, choices=PROGRESSION_STATUS_CHOICES, default='Under Review')
    promotion_status = models.CharField(max_length=30, choices=PROMOTION_STATUS_CHOICES, default='Under Review')
    
    # Teacher feedback
    teacher_comment = models.TextField(blank=True, null=True)
    promotion_recommendation = models.TextField(blank=True, null=True)
    
    # Approval
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_summaries')
    approved_at = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['student', 'term', 'learning_area']
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['term']),
            models.Index(fields=['final_rating']),
        ]
    
    def calculate_final_rating(self):
        """Calculate final rating based on internal value"""
        if self.final_internal_value >= 3.5:
            return 'EE'
        elif self.final_internal_value >= 2.5:
            return 'ME'
        elif self.final_internal_value >= 1.5:
            return 'AE'
        else:
            return 'BE'
    
    def save(self, *args, **kwargs):
        # Auto-calculate final rating
        if self.final_internal_value > 0:
            self.final_rating = self.calculate_final_rating()
        super().save(*args, **kwargs)

# ==================== ACADEMICS MODULE ====================
class Class(models.Model):
    class_code = models.CharField(max_length=10, unique=True)
    class_name = models.CharField(max_length=50)
    numeric_level = models.IntegerField()
    stream = models.CharField(max_length=20, blank=True, null=True)
    capacity = models.IntegerField(default=40, validators=[MinValueValidator(1)])
    class_teacher = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='classes_taught')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['numeric_level']),
        ]
        ordering = ['numeric_level', 'stream']
    
    def __str__(self):
        return f"{self.class_name} ({self.class_code})"

class ClassSubjectAllocation(models.Model):
    academic_year = models.CharField(max_length=9)
    class_id = models.ForeignKey(Class, on_delete=models.CASCADE)
    subject = models.ForeignKey(LearningArea, on_delete=models.CASCADE)
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='allocated_subjects')
    periods_per_week = models.IntegerField(default=5, validators=[MinValueValidator(1), MaxValueValidator(10)])
    is_compulsory = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['academic_year', 'class_id', 'subject']
        indexes = [
            models.Index(fields=['teacher']),
        ]

# ==================== E-LEARNING MODELS ====================
class Course(models.Model):
    """E-Learning Courses"""
    course_code = models.CharField(max_length=20, unique=True)
    course_title = models.CharField(max_length=200)
    learning_area = models.ForeignKey(LearningArea, on_delete=models.SET_NULL, null=True, blank=True, 
                                     related_name='elearning_courses')
    class_id = models.ForeignKey(Class, on_delete=models.CASCADE, related_name='elearning_courses', null=True, blank=True)
    
    description = models.TextField(blank=True, null=True)
    course_image = models.CharField(max_length=255, blank=True, null=True)
    
    # Course details
    credit_hours = models.IntegerField(default=0)
    duration_weeks = models.IntegerField(default=12)
    
    # Status
    is_published = models.BooleanField(default=False)
    published_date = models.DateTimeField(blank=True, null=True)
    
    # Creator
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_courses')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['course_code']
    
    def __str__(self):
        return f"{self.course_code}: {self.course_title}"

class CourseModule(models.Model):
    """Modules within a Course"""
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='modules')
    module_title = models.CharField(max_length=200)
    module_order = models.IntegerField(default=0)
    description = models.TextField(blank=True, null=True)
    learning_objectives = models.TextField(blank=True, null=True)
    
    # Duration
    estimated_hours = models.IntegerField(default=2)
    
    # Competencies covered
    competencies = models.ManyToManyField(Competency, related_name='course_modules', blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['course', 'module_order']
        unique_together = ['course', 'module_order']
    
    def __str__(self):
        return f"Module {self.module_order}: {self.module_title}"

class LearningContent(models.Model):
    """Learning Content within Modules"""
    CONTENT_TYPE_CHOICES = [
        ('Video', 'Video'),
        ('Document', 'Document'),
        ('Presentation', 'Presentation'),
        ('Quiz', 'Quiz'),
        ('Assignment', 'Assignment'),
        ('Link', 'External Link'),
        ('Audio', 'Audio'),
        ('Image', 'Image'),
    ]
    
    module = models.ForeignKey(CourseModule, on_delete=models.CASCADE, related_name='contents')
    content_title = models.CharField(max_length=200)
    content_type = models.CharField(max_length=20, choices=CONTENT_TYPE_CHOICES)
    content_order = models.IntegerField(default=0)
    
    # Content details
    description = models.TextField(blank=True, null=True)
    content_url = models.CharField(max_length=500, blank=True, null=True)
    file_path = models.CharField(max_length=255, blank=True, null=True)
    file_size = models.BigIntegerField(blank=True, null=True)
    duration_minutes = models.IntegerField(blank=True, null=True)  # For videos/audio
    
    # Access control
    is_published = models.BooleanField(default=True)
    publish_date = models.DateTimeField(auto_now_add=True)
    requires_completion = models.BooleanField(default=True)
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['module', 'content_order']
    
    def __str__(self):
        return f"{self.content_type}: {self.content_title}"

class StudentEnrollment(models.Model):
    """Student enrollment in e-learning courses"""
    ENROLLMENT_STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Completed', 'Completed'),
        ('Dropped', 'Dropped'),
        ('Suspended', 'Suspended'),
    ]
    
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='elearning_enrollments')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='enrollments')
    
    enrollment_date = models.DateTimeField(auto_now_add=True)
    enrollment_status = models.CharField(max_length=20, choices=ENROLLMENT_STATUS_CHOICES, default='Active')
    
    # Progress tracking
    progress_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    last_accessed = models.DateTimeField(blank=True, null=True)
    
    # Completion
    completed_at = models.DateTimeField(blank=True, null=True)
    final_score = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    
    class Meta:
        unique_together = ['student', 'course']
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['course']),
            models.Index(fields=['enrollment_status']),
        ]
    
    def __str__(self):
        return f"{self.student.admission_no} - {self.course.course_code}"

class ContentProgress(models.Model):
    """Track student progress through learning content"""
    enrollment = models.ForeignKey(StudentEnrollment, on_delete=models.CASCADE, related_name='content_progress')
    content = models.ForeignKey(LearningContent, on_delete=models.CASCADE, related_name='student_progress')
    
    # Progress tracking
    is_completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(blank=True, null=True)
    time_spent_minutes = models.IntegerField(default=0)
    last_accessed = models.DateTimeField(auto_now=True)
    
    # For quizzes/assignments
    score = models.DecimalField(max_digits=6, decimal_places=2, blank=True, null=True)
    max_score = models.DecimalField(max_digits=6, decimal_places=2, blank=True, null=True)
    attempts = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['enrollment', 'content']
        indexes = [
            models.Index(fields=['enrollment']),
            models.Index(fields=['content']),
            models.Index(fields=['is_completed']),
        ]
    
    def __str__(self):
        return f"{self.enrollment.student.admission_no} - {self.content.content_title}"

class ELearningQuiz(models.Model):
    """E-Learning Quizzes"""
    content = models.OneToOneField(LearningContent, on_delete=models.CASCADE, related_name='quiz')
    quiz_title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    
    # Quiz settings
    time_limit_minutes = models.IntegerField(blank=True, null=True)
    max_attempts = models.IntegerField(default=1)
    passing_score = models.DecimalField(max_digits=5, decimal_places=2, default=50)
    randomize_questions = models.BooleanField(default=False)
    show_results = models.BooleanField(default=True)
    
    # Status
    is_published = models.BooleanField(default=True)
    published_date = models.DateTimeField(auto_now_add=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.quiz_title

class QuizQuestion(models.Model):
    """Questions for quizzes"""
    QUESTION_TYPE_CHOICES = [
        ('MCQ', 'Multiple Choice'),
        ('TrueFalse', 'True/False'),
        ('ShortAnswer', 'Short Answer'),
        ('Essay', 'Essay'),
        ('Matching', 'Matching'),
    ]
    
    quiz = models.ForeignKey(ELearningQuiz, on_delete=models.CASCADE, related_name='questions')
    question_text = models.TextField()
    question_type = models.CharField(max_length=20, choices=QUESTION_TYPE_CHOICES, default='MCQ')
    question_order = models.IntegerField(default=0)
    points = models.DecimalField(max_digits=5, decimal_places=2, default=1)
    
    # For MCQ
    options = models.JSONField(default=list, blank=True)  # [{'text': 'Option A', 'is_correct': true}, ...]
    
    # For all types
    correct_answer = models.TextField(blank=True, null=True)
    explanation = models.TextField(blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['quiz', 'question_order']
    
    def __str__(self):
        return f"Q{self.question_order}: {self.question_text[:100]}..."

class QuizAttempt(models.Model):
    """Student quiz attempts"""
    enrollment = models.ForeignKey(StudentEnrollment, on_delete=models.CASCADE, related_name='quiz_attempts')
    quiz = models.ForeignKey(ELearningQuiz, on_delete=models.CASCADE, related_name='attempts')
    
    attempt_number = models.IntegerField(default=1)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    
    # Results
    score = models.DecimalField(max_digits=6, decimal_places=2, blank=True, null=True)
    max_score = models.DecimalField(max_digits=6, decimal_places=2, blank=True, null=True)
    percentage = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    is_passed = models.BooleanField(default=False)
    
    # Detailed responses
    responses = models.JSONField(default=dict, blank=True)
    
    class Meta:
        unique_together = ['enrollment', 'quiz', 'attempt_number']
        indexes = [
            models.Index(fields=['enrollment']),
            models.Index(fields=['quiz']),
        ]
    
    def save(self, *args, **kwargs):
        if self.score is not None and self.max_score is not None and self.max_score > 0:
            self.percentage = (self.score / self.max_score) * 100
            if self.percentage >= self.quiz.passing_score:
                self.is_passed = True
        super().save(*args, **kwargs)

class DiscussionForum(models.Model):
    """Discussion forums for courses"""
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='forums')
    forum_title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    is_moderated = models.BooleanField(default=False)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.forum_title

class ForumPost(models.Model):
    """Posts in discussion forums"""
    forum = models.ForeignKey(DiscussionForum, on_delete=models.CASCADE, related_name='posts')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='forum_posts')
    parent_post = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    
    post_title = models.CharField(max_length=200, blank=True, null=True)
    content = models.TextField()
    
    # Moderation
    is_pinned = models.BooleanField(default=False)
    is_locked = models.BooleanField(default=False)
    is_approved = models.BooleanField(default=True)
    
    # Engagement
    upvotes = models.IntegerField(default=0)
    downvotes = models.IntegerField(default=0)
    view_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-is_pinned', '-created_at']
    
    def __str__(self):
        return f"Post by {self.author.username}: {self.content[:100]}..."

# ==================== FINANCE MODULE ====================
class FeeCategory(models.Model):
    FREQUENCY_CHOICES = [
        ('One-Time', 'One-Time'),
        ('Monthly', 'Monthly'),
        ('Termly', 'Termly'),
        ('Annual', 'Annual'),
    ]
    
    category_code = models.CharField(max_length=20, unique=True)
    category_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    is_mandatory = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    gl_account_code = models.CharField(max_length=30, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.category_code} - {self.category_name}"

class FeeStructure(models.Model):
    TERM_CHOICES = [('Term 1', 'Term 1'), ('Term 2', 'Term 2'), ('Term 3', 'Term 3')]
    
    academic_year = models.CharField(max_length=9)
    term = models.CharField(max_length=20, choices=TERM_CHOICES)
    class_id = models.ForeignKey(Class, on_delete=models.CASCADE)
    category = models.ForeignKey(FeeCategory, on_delete=models.PROTECT)
    amount = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(0)])
    due_date = models.DateField()
    late_fee_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0, 
                                               validators=[MinValueValidator(0)])
    late_fee_after_days = models.IntegerField(default=30)
    installment_allowed = models.BooleanField(default=False)
    max_installments = models.IntegerField(default=1)
    discount_allowed = models.BooleanField(default=False)
    max_discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['academic_year', 'term', 'class_id', 'category']
        indexes = [
            models.Index(fields=['academic_year']),
            models.Index(fields=['class_id']),
        ]
    
    def __str__(self):
        return f"{self.academic_year} {self.term} - {self.class_id.class_name} - {self.category.category_name}"

class StudentFeeInvoice(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Partial', 'Partial'),
        ('Paid', 'Paid'),
        ('Overdue', 'Overdue'),
        ('Cancelled', 'Cancelled'),
    ]
    PAYMENT_STATUS_CHOICES = [
        ('Unpaid', 'Unpaid'),
        ('Partially Paid', 'Partially Paid'),
        ('Fully Paid', 'Fully Paid'),
    ]
    
    invoice_no = models.CharField(max_length=30, unique=True, default=generate_inv_id)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='invoices')
    academic_year = models.CharField(max_length=9)
    term = models.CharField(max_length=20)
    invoice_date = models.DateField(default=timezone.now)
    due_date = models.DateField()
    
    # Amounts
    subtotal = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    discount_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    late_fee_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    amount_paid = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    balance_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='Unpaid')
    
    # Audit
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_invoices')
    cancelled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='cancelled_invoices')
    cancelled_at = models.DateTimeField(blank=True, null=True)
    cancellation_reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['status']),
            models.Index(fields=['invoice_date']),
        ]
    
    def save(self, *args, **kwargs):
        # Auto-calculate totals
        self.total_amount = self.subtotal - self.discount_amount + self.late_fee_amount
        self.balance_amount = self.total_amount - self.amount_paid
        
        # Auto-update status
        if self.balance_amount <= 0 and self.total_amount > 0:
            self.status = 'Paid'
            self.payment_status = 'Fully Paid'
        elif self.amount_paid > 0 and self.balance_amount > 0:
            self.status = 'Partial'
            self.payment_status = 'Partially Paid'
        elif self.due_date < timezone.now().date() and self.balance_amount > 0:
            self.status = 'Overdue'
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.invoice_no} - {self.student.admission_no}"

class InvoiceItem(models.Model):
    invoice = models.ForeignKey(StudentFeeInvoice, on_delete=models.CASCADE, related_name='items')
    fee_structure = models.ForeignKey(FeeStructure, on_delete=models.PROTECT)
    description = models.CharField(max_length=200)
    quantity = models.IntegerField(default=1, validators=[MinValueValidator(1)])
    unit_price = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(0)])
    amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    discount_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    net_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        self.amount = self.quantity * self.unit_price
        self.discount_amount = self.amount * (self.discount_percentage / 100)
        self.net_amount = self.amount - self.discount_amount
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.description} - {self.net_amount}"

class FeeTransaction(models.Model):
    PAYMENT_MODE_CHOICES = [
        ('Cash', 'Cash'),
        ('Cheque', 'Cheque'),
        ('Bank Transfer', 'Bank Transfer'),
        ('Mobile Money', 'Mobile Money'),
        ('Credit Card', 'Credit Card'),
    ]
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Completed', 'Completed'),
        ('Failed', 'Failed'),
        ('Reversed', 'Reversed'),
    ]
    CURRENCY_CHOICES = [('KES', 'KES'), ('USD', 'USD'), ('EUR', 'EUR')]
    
    transaction_no = models.CharField(max_length=30, unique=True, default=generate_txn_id)
    invoice = models.ForeignKey(StudentFeeInvoice, on_delete=models.SET_NULL, null=True, blank=True, related_name='transactions')
    student = models.ForeignKey(Student, on_delete=models.PROTECT, related_name='fee_transactions')
    
    # Payment details
    payment_date = models.DateTimeField(default=timezone.now)
    payment_mode = models.CharField(max_length=20, choices=PAYMENT_MODE_CHOICES)
    payment_reference = models.CharField(max_length=100, blank=True, null=True)
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    cheque_no = models.CharField(max_length=50, blank=True, null=True)
    mobile_money_no = models.CharField(max_length=20, blank=True, null=True)
    
    # Amounts
    amount = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(0.01)])
    currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='KES')
    exchange_rate = models.DecimalField(max_digits=10, decimal_places=4, default=1)
    amount_kes = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Status and audit
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Completed')
    collected_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='collected_transactions')
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_transactions')
    verified_at = models.DateTimeField(blank=True, null=True)
    reversal_reason = models.TextField(blank=True, null=True)
    reversed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reversed_transactions')
    reversed_at = models.DateTimeField(blank=True, null=True)
    
    # Receipt
    receipt_printed = models.BooleanField(default=False)
    receipt_printed_at = models.DateTimeField(blank=True, null=True)
    receipt_printed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='printed_receipts')
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['payment_date']),
            models.Index(fields=['payment_mode']),
        ]
    
    def save(self, *args, **kwargs):
        self.amount_kes = self.amount * self.exchange_rate
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.transaction_no} - {self.amount_kes}"

class GeneralLedger(models.Model):
    transaction_date = models.DateField(default=timezone.now)
    gl_date = models.DateField(default=timezone.now)
    account_code = models.CharField(max_length=30)
    account_name = models.CharField(max_length=100)
    debit_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    credit_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    description = models.TextField()
    reference_no = models.CharField(max_length=50, blank=True, null=True)
    reference_type = models.CharField(max_length=30, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['gl_date']),
            models.Index(fields=['account_code']),
        ]
    
    def __str__(self):
        return f"{self.gl_date} - {self.account_code}"

# ==================== ATTENDANCE & DISCIPLINE ====================
class AttendanceSession(models.Model):
    SESSION_TYPE_CHOICES = [
        ('Morning', 'Morning'),
        ('Afternoon', 'Afternoon'),
        ('Full Day', 'Full Day'),
        ('Evening', 'Evening'),
    ]
    
    session_date = models.DateField(default=timezone.now)
    session_type = models.CharField(max_length=20, choices=SESSION_TYPE_CHOICES)
    class_id = models.ForeignKey(Class, on_delete=models.SET_NULL, null=True, blank=True)
    subject = models.ForeignKey(LearningArea, on_delete=models.SET_NULL, null=True, blank=True)
    period_number = models.IntegerField(blank=True, null=True)
    start_time = models.TimeField()
    end_time = models.TimeField(blank=True, null=True)
    conducted_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='conducted_sessions')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['session_date', 'class_id', 'period_number', 'session_type']
        indexes = [
            models.Index(fields=['session_date']),
        ]
    
    def __str__(self):
        return f"{self.session_date} - {self.class_id.class_name if self.class_id else 'General'} - {self.session_type}"

class StudentAttendance(models.Model):
    ATTENDANCE_STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Absent', 'Absent'),
        ('Late', 'Late'),
        ('Excused', 'Excused'),
        ('Half-day', 'Half-day'),
    ]
    
    session = models.ForeignKey(AttendanceSession, on_delete=models.CASCADE, related_name='attendance_records')
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='attendance_records')
    attendance_status = models.CharField(max_length=15, choices=ATTENDANCE_STATUS_CHOICES)
    check_in_time = models.DateTimeField(blank=True, null=True)
    check_out_time = models.DateTimeField(blank=True, null=True)
    late_minutes = models.IntegerField(default=0)
    remarks = models.TextField(blank=True, null=True)
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    recorded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['session', 'student']
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['attendance_status']),
        ]
    
    def __str__(self):
        return f"{self.student.admission_no} - {self.session.session_date} - {self.attendance_status}"

class DisciplineCategory(models.Model):
    SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]
    
    category_code = models.CharField(max_length=20, unique=True)
    category_name = models.CharField(max_length=100)
    severity_level = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    default_points = models.IntegerField(default=1, validators=[MinValueValidator(0)])
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.category_name} ({self.severity_level})"

class DisciplineIncident(models.Model):
    STATUS_CHOICES = [
        ('Reported', 'Reported'),
        ('Under Investigation', 'Under Investigation'),
        ('Resolved', 'Resolved'),
        ('Escalated', 'Escalated'),
        ('Closed', 'Closed'),
    ]
    
    incident_code = models.CharField(max_length=30, unique=True, default=generate_inc_id)
    incident_date = models.DateField(default=timezone.now)
    incident_time = models.TimeField(default=timezone.now)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='discipline_incidents')
    category = models.ForeignKey(DisciplineCategory, on_delete=models.PROTECT)
    reported_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='reported_incidents')
    
    # Incident details
    description = models.TextField()
    location = models.CharField(max_length=100, blank=True, null=True)
    witnesses = models.TextField(blank=True, null=True)
    evidence_urls = models.JSONField(default=list, blank=True)
    
    # Resolution tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Reported')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_incidents')
    investigation_notes = models.TextField(blank=True, null=True)
    resolution = models.TextField(blank=True, null=True)
    resolution_date = models.DateField(blank=True, null=True)
    points_awarded = models.IntegerField(validators=[MinValueValidator(0)])
    
    # Parent communication
    parent_notified = models.BooleanField(default=False)
    parent_notification_date = models.DateField(blank=True, null=True)
    parent_response = models.TextField(blank=True, null=True)
    
    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='closed_incidents')
    closed_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['student']),
            models.Index(fields=['incident_date']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.incident_code} - {self.student.admission_no}"

class StudentDisciplinePoints(models.Model):
    STATUS_CHOICES = [
        ('Excellent', 'Excellent'),
        ('Good', 'Good'),
        ('Warning', 'Warning'),
        ('Probation', 'Probation'),
        ('Suspension', 'Suspension'),
    ]
    
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='discipline_points')
    academic_year = models.CharField(max_length=9)
    term = models.CharField(max_length=20)
    total_points = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    warnings_count = models.IntegerField(default=0)
    suspensions_count = models.IntegerField(default=0)
    last_incident_date = models.DateField(blank=True, null=True)
    current_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Good')
    remarks = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['student', 'academic_year', 'term']
        indexes = [
            models.Index(fields=['student']),
        ]
    
    def __str__(self):
        return f"{self.student.admission_no} - {self.academic_year} {self.term}"

# ==================== HUMAN RESOURCES ====================
class Staff(models.Model):
    EMPLOYMENT_TYPE_CHOICES = [
        ('Permanent', 'Permanent'),
        ('Contract', 'Contract'),
        ('Probation', 'Probation'),
        ('Part-time', 'Part-time'),
        ('Intern', 'Intern'),
    ]
    GENDER_CHOICES = [('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')]
    MARITAL_STATUS_CHOICES = [
        ('Single', 'Single'),
        ('Married', 'Married'),
        ('Divorced', 'Divorced'),
        ('Widowed', 'Widowed'),
    ]
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('On Leave', 'On Leave'),
        ('Suspended', 'Suspended'),
        ('Resigned', 'Resigned'),
        ('Terminated', 'Terminated'),
        ('Retired', 'Retired'),
        ('Deceased', 'Deceased'),
    ]
    PAYMENT_MODE_CHOICES = [
        ('Bank Transfer', 'Bank Transfer'),
        ('Cheque', 'Cheque'),
        ('Cash', 'Cash'),
    ]
    
    staff_id = models.CharField(max_length=30, unique=True)
    user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='staff_profile')
    
    # Personal details
    title = models.CharField(max_length=10, blank=True, null=True)
    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    marital_status = models.CharField(max_length=20, choices=MARITAL_STATUS_CHOICES, blank=True, null=True)
    
    # Contact
    personal_email = models.EmailField(blank=True, null=True)
    personal_phone = models.CharField(max_length=20, blank=True, null=True)
    emergency_contact = models.CharField(max_length=20)
    emergency_contact_name = models.CharField(max_length=100)
    emergency_relation = models.CharField(max_length=30, blank=True, null=True)
    
    # Address
    permanent_address = models.TextField(blank=True, null=True)
    temporary_address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=50, blank=True, null=True)
    country = models.CharField(max_length=50, default='Kenya')
    
    # Identification
    national_id = models.CharField(max_length=20, unique=True, blank=True, null=True)
    passport_no = models.CharField(max_length=20, unique=True, blank=True, null=True)
    kra_pin = models.CharField(max_length=20, blank=True, null=True)
    nssf_no = models.CharField(max_length=20, blank=True, null=True)
    nhif_no = models.CharField(max_length=20, blank=True, null=True)
    
    # Employment
    employment_type = models.CharField(max_length=20, choices=EMPLOYMENT_TYPE_CHOICES)
    employment_date = models.DateField()
    confirmation_date = models.DateField(blank=True, null=True)
    contract_end_date = models.DateField(blank=True, null=True)
    department = models.CharField(max_length=50)
    designation = models.CharField(max_length=50)
    job_grade = models.CharField(max_length=10, blank=True, null=True)
    reporting_to = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='subordinates')
    
    # Qualifications
    highest_qualification = models.CharField(max_length=100, blank=True, null=True)
    specialization = models.TextField(blank=True, null=True)
    university = models.CharField(max_length=100, blank=True, null=True)
    year_of_graduation = models.IntegerField(blank=True, null=True)
    
    # Bank details
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    bank_branch = models.CharField(max_length=100, blank=True, null=True)
    account_name = models.CharField(max_length=100, blank=True, null=True)
    account_number = models.CharField(max_length=30, blank=True, null=True)
    
    # Salary
    basic_salary = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True, validators=[MinValueValidator(0)])
    salary_currency = models.CharField(max_length=3, default='KES')
    payment_mode = models.CharField(max_length=20, choices=PAYMENT_MODE_CHOICES, blank=True, null=True)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')
    status_date = models.DateField(blank=True, null=True)
    status_reason = models.TextField(blank=True, null=True)
    exit_interview_conducted = models.BooleanField(default=False)
    exit_interview_notes = models.TextField(blank=True, null=True)
    
    # Documents
    photo_url = models.CharField(max_length=255, blank=True, null=True)
    documents = models.JSONField(default=dict, blank=True)
    
    # Audit
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_staff')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_staff')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived = models.BooleanField(default=False)
    
    class Meta:
        indexes = [
            models.Index(fields=['department']),
            models.Index(fields=['status']),
            models.Index(fields=['employment_type']),
        ]
    
    @property
    def full_name(self):
        return f"{self.title + ' ' if self.title else ''}{self.first_name} {self.middle_name + ' ' if self.middle_name else ''}{self.last_name}"
    
    def __str__(self):
        return f"{self.full_name} ({self.staff_id})"

class StaffLeave(models.Model):
    LEAVE_TYPE_CHOICES = [
        ('Annual', 'Annual'),
        ('Sick', 'Sick'),
        ('Maternity', 'Maternity'),
        ('Paternity', 'Paternity'),
        ('Study', 'Study'),
        ('Compassionate', 'Compassionate'),
        ('Unpaid', 'Unpaid'),
    ]
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
        ('Cancelled', 'Cancelled'),
    ]
    
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='leaves')
    leave_type = models.CharField(max_length=30, choices=LEAVE_TYPE_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField()
    total_days = models.IntegerField(default=0)
    reason = models.TextField()
    contact_during_leave = models.CharField(max_length=20, blank=True, null=True)
    
    # Approval workflow
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    applied_date = models.DateField(default=timezone.now)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_leaves')
    approved_date = models.DateField(blank=True, null=True)
    rejection_reason = models.TextField(blank=True, null=True)
    
    # Handover
    handover_notes = models.TextField(blank=True, null=True)
    handover_to = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name='handover_leaves')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['staff']),
            models.Index(fields=['status']),
        ]
    
    def save(self, *args, **kwargs):
        # Calculate total days excluding weekends and holidays
        from datetime import timedelta
        total = 0
        current = self.start_date
        while current <= self.end_date:
            if current.weekday() < 5:  # Monday=0, Friday=4
                total += 1
            current += timedelta(days=1)
        self.total_days = total
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.staff.staff_id} - {self.leave_type} - {self.start_date} to {self.end_date}"

class LeaveBalance(models.Model):
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='leave_balances')
    leave_year = models.IntegerField()
    leave_type = models.CharField(max_length=30)
    total_entitled = models.IntegerField(default=0)
    taken_so_far = models.IntegerField(default=0)
    balance = models.IntegerField(default=0)
    carried_over = models.IntegerField(default=0)
    expires_on = models.DateField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['staff', 'leave_year', 'leave_type']
        indexes = [
            models.Index(fields=['staff']),
        ]
    
    def save(self, *args, **kwargs):
        self.balance = self.total_entitled - self.taken_so_far + self.carried_over
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.staff.staff_id} - {self.leave_year} - {self.leave_type}: {self.balance}"

# ==================== PAYROLL MANAGEMENT ====================
class PayrollComponent(models.Model):
    COMPONENT_TYPE_CHOICES = [
        ('Earning', 'Earning'),
        ('Deduction', 'Deduction'),
        ('Benefit', 'Benefit'),
        ('Allowance', 'Allowance'),
    ]
    
    CALCULATION_TYPE_CHOICES = [
        ('Fixed Amount', 'Fixed Amount'),
        ('Percentage of Basic', 'Percentage of Basic'),
        ('Per Unit', 'Per Unit'),
        ('Formula', 'Formula'),
    ]
    
    FREQUENCY_CHOICES = [
        ('Monthly', 'Monthly'),
        ('One-Time', 'One-Time'),
        ('Annual', 'Annual'),
        ('Quarterly', 'Quarterly'),
    ]
    
    component_code = models.CharField(max_length=20, unique=True)
    component_name = models.CharField(max_length=100)
    component_type = models.CharField(max_length=20, choices=COMPONENT_TYPE_CHOICES)
    calculation_type = models.CharField(max_length=30, choices=CALCULATION_TYPE_CHOICES)
    
    # Calculation Details
    fixed_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    percentage_rate = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    formula = models.TextField(blank=True, null=True)
    
    # Taxation
    is_taxable = models.BooleanField(default=True)
    is_pensionable = models.BooleanField(default=True)
    statutory_component = models.BooleanField(default=False)
    
    # Application
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES, default='Monthly')
    applies_to_all = models.BooleanField(default=False)
    applies_to_staff_type = models.JSONField(default=list, blank=True)
    
    # Limits
    min_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    max_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    max_percentage = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    
    # Accounting
    gl_account_code = models.CharField(max_length=30, blank=True, null=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    effective_date = models.DateField(default=timezone.now)
    expiry_date = models.DateField(blank=True, null=True)
    
    description = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_payroll_components')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.component_code} - {self.component_name}"

class StaffPayrollComponent(models.Model):
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='payroll_components')
    component = models.ForeignKey(PayrollComponent, on_delete=models.CASCADE, related_name='staff_components')
    
    # Customized Values (overrides default)
    custom_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    custom_percentage = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    custom_formula = models.TextField(blank=True, null=True)
    
    # Effective Dates
    effective_from = models.DateField(default=timezone.now)
    effective_to = models.DateField(blank=True, null=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Approval
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_staff_components')
    approved_date = models.DateField(blank=True, null=True)
    
    # Audit
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_staff_payroll_components')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['staff', 'component']
        indexes = [
            models.Index(fields=['staff']),
            models.Index(fields=['component']),
        ]
    
    def __str__(self):
        return f"{self.staff.staff_id} - {self.component.component_name}"

class PayrollPeriod(models.Model):
    STATUS_CHOICES = [
        ('Draft', 'Draft'),
        ('Processing', 'Processing'),
        ('Calculated', 'Calculated'),
        ('Approved', 'Approved'),
        ('Paid', 'Paid'),
        ('Closed', 'Closed'),
    ]
    
    period_code = models.CharField(max_length=30, unique=True)
    period_name = models.CharField(max_length=100)
    
    # Dates
    start_date = models.DateField()
    end_date = models.DateField()
    pay_date = models.DateField()
    
    # Processing Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Draft')
    
    # Staff Coverage
    total_staff = models.IntegerField(default=0)
    processed_staff = models.IntegerField(default=0)
    
    # Financial Summary
    total_gross = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_deductions = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_net = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    
    # Tax Summary
    total_paye = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_nssf = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_nhif = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    
    # Processing Details
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_payroll_periods')
    processed_date = models.DateTimeField(blank=True, null=True)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_payroll_periods')
    approved_date = models.DateTimeField(blank=True, null=True)
    closed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='closed_payroll_periods')
    closed_date = models.DateTimeField(blank=True, null=True)
    
    # Locking
    is_locked = models.BooleanField(default=False)
    locked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='locked_payroll_periods')
    locked_date = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-start_date']
        indexes = [
            models.Index(fields=['period_code']),
            models.Index(fields=['status']),
            models.Index(fields=['pay_date']),
        ]
    
    def __str__(self):
        return f"{self.period_name} ({self.start_date} to {self.end_date})"

class PayrollRecord(models.Model):
    PAYMENT_STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Paid', 'Paid'),
        ('Partially Paid', 'Partially Paid'),
        ('On Hold', 'On Hold'),
    ]
    
    PAYMENT_METHOD_CHOICES = [
        ('Bank Transfer', 'Bank Transfer'),
        ('Cheque', 'Cheque'),
        ('Cash', 'Cash'),
        ('Mobile Money', 'Mobile Money'),
    ]
    
    payroll_period = models.ForeignKey(PayrollPeriod, on_delete=models.CASCADE, related_name='records')
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='payroll_records')
    
    # Earnings
    basic_salary = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    allowances_total = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    overtime_total = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    bonus_total = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    other_earnings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    gross_salary = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Deductions
    paye_tax = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    nssf_deduction = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    nhif_deduction = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    pension_deduction = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    loan_deductions = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    other_deductions = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_deductions = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Net Amount
    net_salary = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Payment Details
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='Pending')
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES, blank=True, null=True)
    payment_reference = models.CharField(max_length=100, blank=True, null=True)
    payment_date = models.DateField(blank=True, null=True)
    bank_account = models.CharField(max_length=50, blank=True, null=True)
    
    # Breakdown (JSON for flexibility)
    allowances_breakdown = models.JSONField(default=list, blank=True)
    deductions_breakdown = models.JSONField(default=list, blank=True)
    
    # Attendance & Leaves
    days_worked = models.IntegerField(default=0)
    days_absent = models.IntegerField(default=0)
    leave_days = models.IntegerField(default=0)
    overtime_hours = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    
    # Statutory Information
    taxable_income = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    pensionable_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Status
    is_calculated = models.BooleanField(default=False)
    is_approved = models.BooleanField(default=False)
    is_paid = models.BooleanField(default=False)
    
    # Approval
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_payroll_records')
    approved_date = models.DateTimeField(blank=True, null=True)
    
    # Audit
    calculated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='calculated_payroll_records')
    calculated_date = models.DateTimeField(blank=True, null=True)
    paid_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='paid_payroll_records')
    paid_date = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['payroll_period', 'staff']
        indexes = [
            models.Index(fields=['payroll_period']),
            models.Index(fields=['staff']),
            models.Index(fields=['payment_status']),
        ]
    
    def save(self, *args, **kwargs):
        self.gross_salary = self.basic_salary + self.allowances_total + self.overtime_total + self.bonus_total + self.other_earnings
        self.total_deductions = self.paye_tax + self.nssf_deduction + self.nhif_deduction + self.pension_deduction + self.loan_deductions + self.other_deductions
        self.net_salary = self.gross_salary - self.total_deductions
        
        if self.is_paid:
            self.payment_status = 'Paid'
        elif self.net_salary > 0:
            self.payment_status = 'Pending'
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.staff.staff_id} - {self.payroll_period.period_name} - {self.net_salary}"

class StaffLoan(models.Model):
    LOAN_TYPE_CHOICES = [
        ('Emergency', 'Emergency'),
        ('Salary Advance', 'Salary Advance'),
        ('Housing', 'Housing'),
        ('Vehicle', 'Vehicle'),
        ('Education', 'Education'),
        ('Other', 'Other'),
    ]
    
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Disbursed', 'Disbursed'),
        ('Active', 'Active'),
        ('Settled', 'Settled'),
        ('Defaulted', 'Defaulted'),
        ('Written Off', 'Written Off'),
    ]
    
    loan_id = models.CharField(max_length=30, unique=True, default=generate_inc_id)
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='loans')
    
    # Loan Details
    loan_type = models.CharField(max_length=30, choices=LOAN_TYPE_CHOICES)
    loan_amount = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(1)])
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    interest_type = models.CharField(max_length=20, choices=[('Flat', 'Flat'), ('Reducing', 'Reducing')], default='Flat')
    
    # Repayment Terms
    repayment_months = models.IntegerField(default=12)
    monthly_installment = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    start_date = models.DateField()
    end_date = models.DateField()
    
    # Disbursement
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approved_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    disbursed_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    disbursement_date = models.DateField(blank=True, null=True)
    disbursement_method = models.CharField(max_length=30, blank=True, null=True)
    
    # Repayment Tracking
    total_paid = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_interest_paid = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_principal_paid = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    outstanding_balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    overdue_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    overdue_days = models.IntegerField(default=0)
    
    # Approval Workflow
    applied_date = models.DateField(default=timezone.now)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_staff_loans')
    approved_date = models.DateField(blank=True, null=True)
    rejection_reason = models.TextField(blank=True, null=True)
    
    # Guarantor/Security
    guarantor_name = models.CharField(max_length=100, blank=True, null=True)
    guarantor_contact = models.CharField(max_length=20, blank=True, null=True)
    security_details = models.TextField(blank=True, null=True)
    
    # Audit
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_staff_loans')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['loan_id']),
            models.Index(fields=['staff']),
            models.Index(fields=['status']),
        ]
    
    def save(self, *args, **kwargs):
        if self.loan_amount > 0 and self.repayment_months > 0:
            if self.interest_type == 'Flat' and self.interest_rate > 0:
                total_interest = self.loan_amount * (self.interest_rate / 100) * (self.repayment_months / 12)
                total_repayment = self.loan_amount + total_interest
                self.monthly_installment = total_repayment / self.repayment_months
            else:
                self.monthly_installment = self.loan_amount / self.repayment_months
        
        self.outstanding_balance = self.loan_amount - self.total_principal_paid
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.loan_id} - {self.staff.staff_id} - {self.loan_amount}"

class LoanRepayment(models.Model):
    loan = models.ForeignKey(StaffLoan, on_delete=models.CASCADE, related_name='repayments')
    
    # Payment Details
    repayment_date = models.DateField(default=timezone.now)
    amount_paid = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(0.01)])
    principal_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    interest_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Payment Method
    payment_method = models.CharField(max_length=20, choices=[
        ('Salary Deduction', 'Salary Deduction'),
        ('Bank Transfer', 'Bank Transfer'),
        ('Cash', 'Cash'),
        ('Cheque', 'Cheque'),
        ('Mobile Money', 'Mobile Money'),
    ])
    payment_reference = models.CharField(max_length=100, blank=True, null=True)
    
    # Status
    is_overdue = models.BooleanField(default=False)
    overdue_days = models.IntegerField(default=0)
    
    # Processing
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='processed_loan_repayments')
    processed_date = models.DateTimeField(default=timezone.now)
    
    # Remarks
    remarks = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['loan']),
            models.Index(fields=['repayment_date']),
        ]
    
    def __str__(self):
        return f"{self.loan.loan_id} - {self.repayment_date} - {self.amount_paid}"

# ==================== LIBRARY MODULE ====================
class BookResource(models.Model):
    CONDITION_STATUS_CHOICES = [
        ('New', 'New'),
        ('Good', 'Good'),
        ('Worn', 'Worn'),
        ('Damaged', 'Damaged'),
        ('Lost', 'Lost'),
    ]
    
    BOOK_CATEGORY_CHOICES = [
        ('Textbook', 'Textbook'),
        ('Storybook', 'Storybook'),
        ('Reference', 'Reference'),
        ('Teacher Guide', 'Teacher Guide'),
        ('Digital Resource', 'Digital Resource'),
        ('Journal', 'Journal'),
        ('Magazine', 'Magazine'),
        ('Newspaper', 'Newspaper'),
        ('Audio Book', 'Audio Book'),
        ('Video', 'Video'),
    ]
    
    LANGUAGE_CHOICES = [
        ('English', 'English'),
        ('Kiswahili', 'Kiswahili'),
        ('French', 'French'),
        ('German', 'German'),
        ('Arabic', 'Arabic'),
        ('Other', 'Other'),
    ]
    
    # Identification
    isbn = models.CharField(max_length=20, blank=True, null=True, verbose_name="ISBN")
    school_code = models.CharField(max_length=30, unique=True)
    accession_number = models.CharField(max_length=30, unique=True)
    
    # Basic Information
    title = models.CharField(max_length=200)
    authors = models.CharField(max_length=300)
    publisher = models.CharField(max_length=100, blank=True, null=True)
    edition = models.CharField(max_length=20, blank=True, null=True)
    year_of_publication = models.IntegerField(blank=True, null=True)
    language = models.CharField(max_length=20, choices=LANGUAGE_CHOICES, default='English')
    
    # Classification
    subject = models.ForeignKey(LearningArea, on_delete=models.SET_NULL, null=True, blank=True, 
                               verbose_name="Kenya CBE Learning Area")
    grade_levels = models.ManyToManyField(Class, blank=True, related_name='books')
    book_category = models.CharField(max_length=30, choices=BOOK_CATEGORY_CHOICES)
    
    # Physical Details
    shelf_location = models.CharField(max_length=50)
    call_number = models.CharField(max_length=30, blank=True, null=True)
    pages = models.IntegerField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    
    # Inventory
    total_copies = models.IntegerField(default=1, validators=[MinValueValidator(1)])
    available_copies = models.IntegerField(default=1)
    reserved_copies = models.IntegerField(default=0)
    condition_status = models.CharField(max_length=20, choices=CONDITION_STATUS_CHOICES, default='Good')
    
    # Digital Resources
    digital_file_url = models.CharField(max_length=255, blank=True, null=True)
    thumbnail_url = models.CharField(max_length=255, blank=True, null=True)
    has_digital_version = models.BooleanField(default=False)
    
    # Metadata
    keywords = models.TextField(blank=True, null=True)
    summary = models.TextField(blank=True, null=True)
    table_of_contents = models.TextField(blank=True, null=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    is_reference_only = models.BooleanField(default=False)
    
    # Audit
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='added_books')
    added_date = models.DateField(default=timezone.now)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['school_code']),
            models.Index(fields=['title']),
            models.Index(fields=['authors']),
            models.Index(fields=['subject']),
            models.Index(fields=['book_category']),
            models.Index(fields=['is_active']),
        ]
        ordering = ['title']
    
    def __str__(self):
        return f"{self.title} - {self.school_code}"
    
    def save(self, *args, **kwargs):
        if not self.available_copies:
            self.available_copies = self.total_copies
        super().save(*args, **kwargs)

# ==================== SYSTEM & AUDIT ====================
class AuditLog(models.Model):
    EVENT_TYPE_CHOICES = [
        ('USER_LOGIN', 'User Login'),
        ('USER_LOGOUT', 'User Logout'),
        ('USER_CREATE', 'User Create'),
        ('USER_UPDATE', 'User Update'),
        ('USER_DELETE', 'User Delete'),
        ('STUDENT_CREATE', 'Student Create'),
        ('STUDENT_UPDATE', 'Student Update'),
        ('STUDENT_DELETE', 'Student Delete'),
        ('FEE_CREATE', 'Fee Create'),
        ('FEE_UPDATE', 'Fee Update'),
        ('FEE_DELETE', 'Fee Delete'),
        ('PAYMENT_RECEIVED', 'Payment Received'),
        ('EXAM_CREATE', 'Exam Create'),
        ('EXAM_UPDATE', 'Exam Update'),
        ('MARKS_ENTERED', 'Marks Entered'),
        ('MARKS_MODIFIED', 'Marks Modified'),
        ('ATTENDANCE_MARKED', 'Attendance Marked'),
        ('DISCIPLINE_INCIDENT', 'Discipline Incident'),
        ('SYSTEM_BACKUP', 'System Backup'),
        ('SYSTEM_RESTORE', 'System Restore'),
        ('CONFIG_CHANGE', 'Config Change'),
        ('CBE_RATING_ENTERED', 'CBE Rating Entered'),
        ('CBE_REPORT_GENERATED', 'CBE Report Generated'),
    ]
    OPERATION_CHOICES = [
        ('INSERT', 'Insert'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('SELECT', 'Select'),
    ]
    
    event_time = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES)
    
    # Who
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=50, blank=True, null=True)
    user_role = models.CharField(max_length=30, blank=True, null=True)
    
    # What
    table_name = models.CharField(max_length=50)
    record_id = models.IntegerField(blank=True, null=True)
    operation = models.CharField(max_length=20, choices=OPERATION_CHOICES, blank=True, null=True)
    
    # Changes
    old_values = models.JSONField(blank=True, null=True)
    new_values = models.JSONField(blank=True, null=True)
    changed_fields = models.JSONField(default=list, blank=True)
    
    # Context
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    endpoint = models.CharField(max_length=255, blank=True, null=True)
    http_method = models.CharField(max_length=10, blank=True, null=True)
    request_id = models.UUIDField(blank=True, null=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['event_time']),
            models.Index(fields=['user']),
            models.Index(fields=['table_name']),
            models.Index(fields=['event_type']),
        ]
    
    def __str__(self):
        return f"{self.event_time} - {self.event_type} - {self.username or 'Unknown'}"


class BackupHistory(models.Model):
    BACKUP_TYPE_CHOICES = [
        ('Full', 'Full'),
        ('Incremental', 'Incremental'),
        ('Differential', 'Differential'),
        ('Manual', 'Manual'),
        ('Scheduled', 'Scheduled'),
    ]
    STATUS_CHOICES = [
        ('Started', 'Started'),
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
        ('Failed', 'Failed'),
        ('Verified', 'Verified'),
    ]
    
    backup_type = models.CharField(max_length=20, choices=BACKUP_TYPE_CHOICES)
    backup_name = models.CharField(max_length=100)
    file_path = models.TextField()
    file_size = models.BigIntegerField(blank=True, null=True)
    database_version = models.CharField(max_length=20, blank=True, null=True)
    backup_start = models.DateTimeField()
    backup_end = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    verification_status = models.BooleanField(blank=True, null=True)
    verification_time = models.DateTimeField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    initiated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    restore_point = models.BooleanField(default=False)
    retention_days = models.IntegerField(default=30)
    expires_on = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['backup_start']),
            models.Index(fields=['status']),
            models.Index(fields=['expires_on']),
        ]
    
    def __str__(self):
        return f"{self.backup_name} - {self.backup_start.date()} - {self.status}"

class SystemSetting(models.Model):
    SETTING_TYPE_CHOICES = [
        ('String', 'String'),
        ('Number', 'Number'),
        ('Boolean', 'Boolean'),
        ('JSON', 'JSON'),
        ('Encrypted', 'Encrypted'),
    ]
    
    setting_key = models.CharField(max_length=100, unique=True)
    setting_value = models.TextField()
    setting_type = models.CharField(max_length=20, choices=SETTING_TYPE_CHOICES)
    category = models.CharField(max_length=50, default='General')
    description = models.TextField(blank=True, null=True)
    is_public = models.BooleanField(default=False)
    is_encrypted = models.BooleanField(default=False)
    encrypted_value = models.BinaryField(blank=True, null=True)
    min_value = models.TextField(blank=True, null=True)
    max_value = models.TextField(blank=True, null=True)
    validation_regex = models.TextField(blank=True, null=True)
    options = models.JSONField(blank=True, null=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    requires_restart = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.setting_key}: {self.setting_value[:50]}..."

# ==================== UTILITY TABLES ====================
class Holiday(models.Model):
    HOLIDAY_TYPE_CHOICES = [
        ('Public Holiday', 'Public Holiday'),
        ('School Holiday', 'School Holiday'),
        ('Exam Holiday', 'Exam Holiday'),
        ('Other', 'Other'),
    ]
    
    holiday_date = models.DateField(unique=True)
    holiday_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    holiday_type = models.CharField(max_length=30, choices=HOLIDAY_TYPE_CHOICES)
    is_working_day = models.BooleanField(default=False)
    academic_year = models.CharField(max_length=9, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.holiday_name} ({self.holiday_date})"

class Notification(models.Model):
    RECIPIENT_TYPE_CHOICES = [
        ('User', 'User'),
        ('Role', 'Role'),
        ('Class', 'Class'),
        ('All', 'All'),
    ]
    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Normal', 'Normal'),
        ('High', 'High'),
        ('Urgent', 'Urgent'),
    ]
    STATUS_CHOICES = [
        ('Unread', 'Unread'),
        ('Read', 'Read'),
        ('Archived', 'Archived'),
    ]
    
    notification_type = models.CharField(max_length=50)
    title = models.CharField(max_length=200)
    message = models.TextField()
    recipient_type = models.CharField(max_length=20, choices=RECIPIENT_TYPE_CHOICES)
    recipient_id = models.IntegerField(blank=True, null=True)  # user_id, role, or class_id
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='Normal')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Unread')
    action_url = models.CharField(max_length=255, blank=True, null=True)
    related_table = models.CharField(max_length=50, blank=True, null=True)
    related_id = models.IntegerField(blank=True, null=True)
    sent_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['recipient_type', 'recipient_id']),
            models.Index(fields=['status']),
            models.Index(fields=['sent_at']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.recipient_type}"

class Timetable(models.Model):
    DAY_CHOICES = [(1, 'Monday'), (2, 'Tuesday'), (3, 'Wednesday'), 
                   (4, 'Thursday'), (5, 'Friday'), (6, 'Saturday'), (7, 'Sunday')]
    
    class_id = models.ForeignKey(Class, on_delete=models.CASCADE)
    day_of_week = models.IntegerField(choices=DAY_CHOICES)
    period = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(10)])
    subject = models.ForeignKey(LearningArea, on_delete=models.CASCADE)
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name='timetable_slots')
    room = models.CharField(max_length=20, blank=True, null=True)
    academic_year = models.CharField(max_length=9)
    term = models.CharField(max_length=20)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['class_id', 'day_of_week', 'period', 'academic_year', 'term']
        ordering = ['day_of_week', 'period']
    
    def __str__(self):
        return f"{self.class_id.class_name} - Day {self.day_of_week} - Period {self.period}"

# ==================== CBE REPORT CARDS ====================
class CBEReportCard(models.Model):
    """CBE Report Card Structure"""
    REPORT_TYPE_CHOICES = [
        ('Learner Progress Report', 'Learner Progress Report'),
        ('Parent Summary Report', 'Parent Summary Report'),
        ('Teacher Class Performance Report', 'Teacher Class Performance Report'),
        ('School-Wide CBE Report', 'School-Wide CBE Report'),
    ]
    
    report_id = models.CharField(max_length=30, unique=True, default=generate_report_id)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPE_CHOICES)
    
    # Scope
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True, blank=True, related_name='cbe_report_cards')
    class_id = models.ForeignKey(Class, on_delete=models.CASCADE, null=True, blank=True, related_name='cbe_report_cards')
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='cbe_report_cards')
    
    # Period
    academic_year = models.CharField(max_length=9)
    term = models.CharField(max_length=20)
    reporting_date = models.DateField(default=timezone.now)
    
    # Learner Details Section
    learner_photo_url = models.CharField(max_length=255, blank=True, null=True)
    learner_attendance_summary = models.TextField(blank=True, null=True)
    
    # Learning Area Performance Section (JSON for flexibility)
    learning_area_performance = models.JSONField(default=list)
    
    # Competency Levels Summary
    competency_summary = models.JSONField(default=dict)
    
    # Core Competencies Progress
    core_competencies = models.JSONField(default=list)
    
    # Values Development
    values_assessment = models.JSONField(default=list)
    
    # Remarks Section
    teacher_remarks = models.TextField(blank=True, null=True)
    head_teacher_remarks = models.TextField(blank=True, null=True)
    head_teacher_signature = models.CharField(max_length=100, blank=True, null=True)
    
    # Parent Feedback Section
    parent_feedback_section = models.TextField(blank=True, null=True)
    parent_signature = models.CharField(max_length=100, blank=True, null=True)
    parent_date = models.DateField(blank=True, null=True)
    
    # Report Generation
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='generated_cbe_reports')
    generated_date = models.DateTimeField(default=timezone.now)
    
    # Status
    is_published = models.BooleanField(default=False)
    published_date = models.DateTimeField(blank=True, null=True)
    is_printed = models.BooleanField(default=False)
    printed_date = models.DateTimeField(blank=True, null=True)
    
    # Storage
    report_file_url = models.CharField(max_length=255, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['report_id']),
            models.Index(fields=['student']),
            models.Index(fields=['class_id']),
            models.Index(fields=['academic_year', 'term']),
            models.Index(fields=['is_published']),
        ]
    
    def __str__(self):
        return f"{self.report_type} - {self.student.full_name if self.student else self.class_id.class_name}"

class StudentCredit(models.Model):
    CREDIT_TYPE_CHOICES = [
        ('EXCESS_PAYMENT', 'Excess Payment'),
        ('REFUND', 'Refund'),
        ('ADJUSTMENT', 'Adjustment'),
        ('DISCOUNT', 'Discount'),
    ]
    
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='credits')
    credit_amount = models.DecimalField(max_digits=12, decimal_places=2)
    credit_type = models.CharField(max_length=20, choices=CREDIT_TYPE_CHOICES)
    original_transaction = models.ForeignKey(FeeTransaction, on_delete=models.SET_NULL, 
                                           null=True, blank=True, related_name='original_credits')
    credit_date = models.DateField(default=timezone.now)
    credit_expiry = models.DateField()
    is_utilized = models.BooleanField(default=False)
    utilized_date = models.DateField(null=True, blank=True)
    utilized_for_transaction = models.ForeignKey(FeeTransaction, on_delete=models.SET_NULL,
                                               null=True, blank=True, related_name='utilized_credits')
    academic_year = models.CharField(max_length=9, null=True, blank=True)
    term = models.CharField(max_length=20, null=True, blank=True)
    notes = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['student', 'is_utilized']),
            models.Index(fields=['credit_expiry']),
            models.Index(fields=['student', 'credit_expiry', 'is_utilized']),
        ]
        ordering = ['-credit_date']
    
    def __str__(self):
        return f"Credit {self.id}: {self.student.admission_no} - KSh {self.credit_amount}"
    
    @property
    def is_expired(self):
        return self.credit_expiry < timezone.now().date()
    
    @property
    def is_active(self):
        return not self.is_utilized and not self.is_expired

# ==================== PARENT MODEL ====================
class Parent(models.Model):
    """Parent/Guardian model for portal access"""
    parent_id = models.CharField(max_length=30, unique=True)
    user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True, 
                               related_name='parent_profile')
    
    # Personal Information
    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50)
    relation_to_student = models.CharField(max_length=30)
    phone = models.CharField(max_length=20)
    email = models.EmailField(blank=True, null=True)
    occupation = models.CharField(max_length=50, blank=True, null=True)
    
    # Address
    address = models.TextField()
    city = models.CharField(max_length=50)
    country = models.CharField(max_length=50, default='Kenya')
    
    # Students associated with this parent
    students = models.ManyToManyField(Student, related_name='parents')
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['parent_id']),
            models.Index(fields=['phone']),
            models.Index(fields=['email']),
        ]
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.middle_name + ' ' if self.middle_name else ''}{self.last_name}"
    
    def __str__(self):
        return f"{self.full_name} ({self.parent_id})"