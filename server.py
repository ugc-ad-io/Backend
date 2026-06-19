from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, UploadFile, File, Query
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import random
import string
from enum import Enum
import pyotp
import qrcode
import io
import base64
import re
import razorpay
import hmac
import hashlib
import boto3
from botocore.exceptions import ClientError as BotoClientError
from twilio.rest import Client as TwilioClient
from twilio.base.exceptions import TwilioRestException

# Import extended campaign models and helpers
from campaign_models import CampaignCreateExtended, CampaignDraftCreate, CampaignUpdate
from campaign_helpers import (
    validate_campaign_for_submission,
    normalize_campaign_response,
    prepare_campaign_for_storage,
    can_edit_campaign,
    get_campaign_completion_percentage,
    map_legacy_to_new_fields
)

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Import routers (after load_dotenv)
from applications import applications_router
from categories import categories_router, seed_categories
from gigs import gigs_router
import creator_features as cf

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="UGCad Backend API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

# Anti-Cheat Content Filtering
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_PATTERN = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\d{10}\b')
URL_PATTERN = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|(?:www\.)[a-zA-Z0-9-]+\.[a-zA-Z]{2,}')
SOCIAL_HANDLES_PATTERN = re.compile(r'@[\w.-]+|whatsapp|telegram|discord|skype', re.IGNORECASE)

# Safe domains whitelist
SAFE_DOMAINS = [
    'google.com', 'youtube.com', 'instagram.com', 'tiktok.com', 'twitter.com', 
    'facebook.com', 'linkedin.com', 'behance.net', 'dribbble.com', 'github.com',
    'vimeo.com', 'imgur.com', 'pinterest.com'
]

def check_content_safety(message: str) -> dict:
    """Check message for prohibited content"""
    violations = []
    
    # Check for emails
    emails = EMAIL_PATTERN.findall(message)
    if emails:
        violations.append({
            "type": "email",
            "content": emails,
            "severity": "high"
        })
    
    # Check for phone numbers
    phones = PHONE_PATTERN.findall(message)
    if phones:
        violations.append({
            "type": "phone",
            "content": [str(p) for p in phones],
            "severity": "high"
        })
    
    # Check for URLs
    urls = URL_PATTERN.findall(message)
    unsafe_urls = []
    for url in urls:
        # Check if URL is from safe domain
        is_safe = any(domain in url.lower() for domain in SAFE_DOMAINS)
        if not is_safe:
            unsafe_urls.append(url)
    
    if unsafe_urls:
        violations.append({
            "type": "unsafe_url",
            "content": unsafe_urls,
            "severity": "medium"
        })
    
    # Check for social media handles
    social_handles = SOCIAL_HANDLES_PATTERN.findall(message)
    if social_handles:
        violations.append({
            "type": "social_handle",
            "content": social_handles,
            "severity": "medium"
        })
    
    return {
        "safe": len(violations) == 0,
        "violations": violations
    }

def sanitize_message(message: str) -> str:
    """Remove prohibited content from message"""
    # Replace emails
    message = EMAIL_PATTERN.sub('[EMAIL REMOVED]', message)
    
    # Replace phone numbers
    message = PHONE_PATTERN.sub('[PHONE REMOVED]', message)
    
    # Replace unsafe URLs
    urls = URL_PATTERN.findall(message)
    for url in urls:
        is_safe = any(domain in url.lower() for domain in SAFE_DOMAINS)
        if not is_safe:
            message = message.replace(url, '[LINK REMOVED]')
    
    # Replace social handles
    message = SOCIAL_HANDLES_PATTERN.sub('[CONTACT INFO REMOVED]', message)
    
    return message

class UserRole(str, Enum):
    CREATOR = "creator"
    BUSINESS = "business"
    ADMIN = "admin"
    CAMPAIGN_MANAGER = "campaign_manager"
    SUPPORT_STAFF = "support_staff"

class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class CampaignStatus(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"

class WorkStatus(str, Enum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    REVISION_REQUESTED = "revision_requested"
    APPROVED = "approved"

class WithdrawalStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    REJECTED = "rejected"

# Models
class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    role: UserRole

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class CreatorProfileUpdate(BaseModel):
    username: Optional[str] = None
    profile_picture: Optional[str] = None
    banner: Optional[str] = None
    intro_video: Optional[str] = None
    # All optional so a partial onboarding submit doesn't 422; extra="allow" (below) keeps every
    # additional detail the form sends (name, age, contact, equipment, languages, ...) instead of
    # silently dropping it — those get stored via data.dict() in the route.
    bio: Optional[str] = ""
    tags: List[str] = []
    social_links: Dict[str, Any] = {}
    portfolio: List[Any] = []
    rate_card: Dict[str, Any] = {}
    availability_calendar: Optional[Dict[str, Any]] = None
    payment_methods: Dict[str, Any] = {}
    receive_briefs: bool = True
    terms_agreed: bool = False

    class Config:
        extra = "allow"

class BusinessProfileUpdate(BaseModel):
    business_name: Optional[str] = None
    logo: Optional[str] = None
    banner: Optional[str] = None
    # All optional so the onboarding form doesn't 422; extra="allow" stores the extra fields the
    # form sends (country, phone, gstin, ...) that aren't declared here, via data.dict().
    business_description: Optional[str] = ""
    website: Optional[str] = None
    social_links: Dict[str, Any] = {}
    product_type: Optional[str] = ""
    industry_category: Optional[str] = ""

    class Config:
        extra = "allow"

class PayoutRangeCreate(BaseModel):
    key: str
    label: str
    min_amount: float
    max_amount: float
    sort_order: Optional[int] = None

class PayoutRangeUpdate(BaseModel):
    key: Optional[str] = None
    label: Optional[str] = None
    min_amount: Optional[float] = None
    max_amount: Optional[float] = None
    is_active: Optional[bool] = None
    sort_order: Optional[int] = None

# Legacy CampaignCreate kept for backward compatibility
class CampaignCreate(BaseModel):
    title: str
    objectives: List[str]
    budget_min: float
    budget_max: float
    brief_text: str
    deadline: Optional[str] = None
    due_date: Optional[str] = None
    content_requirements: Optional[Dict[str, bool]] = None
    revision_limit: Optional[int] = 2
    campaign_basics: Optional[str] = None
    deliverables: Optional[str] = None
    creative_requirements: Optional[str] = None
    creative_restrictions: Optional[str] = None
    style_guidance: Optional[str] = None
    usage_rights: Optional[str] = None
    timeline_budget: Optional[str] = None
    review_summary: Optional[str] = None
    brief_attachments: List[str] = []
    requires_shipment: bool = False
    shipment_option: Optional[str] = 'no'  # 'yes', 'no', 'not_sure'
    shipment_checklist: Optional[Dict[str, Any]] = None

class BidCreate(BaseModel):
    campaign_id: str
    amount: float
    proposal: str
    estimated_delivery_days: int

class ChatMessage(BaseModel):
    recipient_id: str
    message: str
    attachment_urls: List[str] = []

class WorkSubmission(BaseModel):
    campaign_id: str
    work_files: List[str]
    description: str

class ReviewSubmit(BaseModel):
    campaign_id: str
    creator_id: Optional[str] = None
    business_id: Optional[str] = None  # set when a creator rates a brand (PRD 8.9)
    rating: int
    review: str

class ShipmentUpdate(BaseModel):
    campaign_id: str
    tracking_number: str
    courier_name: Optional[str] = None
    courier_tracking_url: Optional[str] = None
    courier_status: Optional[str] = "shipped"
    courier_slip: str
    expected_delivery: str
    shipment_checklist: Dict[str, bool]

class ShipmentReceive(BaseModel):
    campaign_id: str
    unboxing_video: str
    items_damaged: bool = False
    dispute_reason: Optional[str] = None

class WithdrawalRequest(BaseModel):
    amount: float
    payment_method: str
    account_details: Dict[str, str]

class RoleUpdate(BaseModel):
    user_id: str
    role: UserRole
    permissions: List[str]

class UserUpdateRequest(BaseModel):
    user_id: str
    nickname: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    balance: Optional[float] = None

class UserBanRequest(BaseModel):
    user_id: str
    banned: bool
    ban_reason: Optional[str] = None

class ApprovalAction(BaseModel):
    item_id: str
    action: str  # approve or reject
    reason: Optional[str] = None

class PaymentGatewayConfig(BaseModel):
    gateway_name: str  # razorpay or cashfree
    key_id: str
    key_secret: str
    enabled: bool = True
    is_default: bool = False

class PaymentOrderCreate(BaseModel):
    amount: float
    currency: str = "INR"
    customer_id: str
    customer_email: str
    customer_phone: str
    customer_name: str
    campaign_id: Optional[str] = None
    notes: Optional[Dict[str, str]] = None

class PaymentGatewayUpdate(BaseModel):
    enabled: Optional[bool] = None
    is_default: Optional[bool] = None

class NotificationGatewayConfig(BaseModel):
    gateway_type: str  # 'email' or 'sms'
    provider: str  # 'aws_ses' or 'twilio'
    config: Dict[str, str]  # Provider-specific configuration
    enabled: bool = True
    is_default: bool = False

class SendNotificationRequest(BaseModel):
    notification_type: str  # 'email' or 'sms'
    recipient: str  # email or phone number
    subject: Optional[str] = None  # For emails
    message: str
    template: Optional[str] = None

class InAppNotification(BaseModel):
    title: str
    message: str
    type: str = "info"  # info, success, warning, error
    link: Optional[str] = None

class BroadcastNotification(BaseModel):
    title: str
    message: str
    type: str = "info"
    target_roles: Optional[List[str]] = None  # If None, send to all users
    target_user_ids: Optional[List[str]] = None  # Specific user IDs
    link: Optional[str] = None

class BusinessSettingsProfileUpdate(BaseModel):
    brand_name: str
    contact_person: str
    work_email: EmailStr
    phone_number: Optional[str] = ""
    website_url: Optional[str] = ""
    logo_url: Optional[str] = ""

class BusinessSettingsCompanyUpdate(BaseModel):
    business_type: str
    gst_number: Optional[str] = ""
    business_category: str
    country: str
    billing_address: str
    city: str
    state: str
    kyb_status: Optional[str] = None

class BusinessTeamInvite(BaseModel):
    email: EmailStr
    role: str
    name: Optional[str] = None

class BusinessTeamMemberUpdate(BaseModel):
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    role: Optional[str] = None
    status: Optional[str] = None

class BusinessNotificationPreferences(BaseModel):
    new_creator_applications: bool
    deal_status_updates: bool
    payment_escrow_alerts: bool
    direct_messages: bool
    weekly_workspace_reports: bool

class BusinessBillingUpgrade(BaseModel):
    plan_name: str

class BusinessPaymentMethodCreate(BaseModel):
    type: str
    label: str
    last4: Optional[str] = None
    is_default: bool = False

class BusinessWalletRechargeCreate(BaseModel):
    amount: float
    gateway: str = "razorpay"

class DealReceiptSubmit(BaseModel):
    received_at: Optional[str] = None
    unboxing_video_url: str
    items_damaged: bool = False
    damage_report: Optional[str] = None

class DealContentSubmit(BaseModel):
    video_url: str
    caption_url: Optional[str] = None
    thumbnail_url: Optional[str] = None
    raw_footage_url: Optional[str] = None
    creator_note: Optional[str] = None
    self_assessment: Optional[List[str]] = None  # PRD 8.3: confirmed must-include items

class DealRevisionResponseSubmit(BaseModel):
    response: str
    note: Optional[str] = None

class DealChatSubmit(BaseModel):
    message: str
    attachment_urls: List[str] = []

class DealActionCardSubmit(BaseModel):
    type: str
    message: str
    attachment_urls: List[str] = []

class ChatFalsePositiveRequest(BaseModel):
    reason: Optional[str] = None

class ChatFalsePositiveReview(BaseModel):
    status: str
    note: Optional[str] = None

class ChatActionCardCreate(BaseModel):
    recipient_id: str
    type: str
    fields: Dict[str, Any]
    deal_id: Optional[str] = None

class ChatActionCardRespond(BaseModel):
    action: str
    note: Optional[str] = None
    decline_reason: Optional[str] = None

class CreatorDirectoryInviteCreate(BaseModel):
    campaign_id: Optional[str] = None
    campaign_name: str
    deliverable_summary: str
    budget: str
    timeline: str
    usage_rights: str
    message: Optional[str] = ""

class ShortlistCandidate(BaseModel):
    creator_id: str
    ops_note: str

class ShortlistCreate(BaseModel):
    candidates: List[ShortlistCandidate]

class ShortlistInviteCreate(BaseModel):
    deliverable_summary: Optional[str] = None
    budget: Optional[str] = None
    timeline: Optional[str] = None
    usage_rights: Optional[str] = None
    message: Optional[str] = ""

class DealIssueSubmit(BaseModel):
    message: Optional[str] = None
    attachment_urls: List[str] = []

class DisputeCreate(BaseModel):
    dispute_type: str          # PRD 9.3 dropdown
    description: str           # 100-1000 chars
    desired_outcome: str       # full_refund / partial_refund / extension / redo / reassignment / other
    evidence_urls: List[str] = []   # min 1 required

class DisputeRuling(BaseModel):
    ruling: str                # favor_brand / favor_creator / split / no_fault
    refund_amount: Optional[float] = 0     # to brand wallet
    creator_amount: Optional[float] = 0    # released to creator
    reasoning: str
    extension_days: Optional[int] = 0

class DisputeInfoRequest(BaseModel):
    party: str                 # brand / creator
    message: str

class DisputeAppeal(BaseModel):
    new_evidence_urls: List[str] = []
    grounds: str               # new evidence / points not previously considered

class StaffCreate(BaseModel):
    email: EmailStr
    nickname: str
    role: UserRole
    password: Optional[str] = None  # If None, will send invite email
    permissions: List[str] = []

class PermissionUpdate(BaseModel):
    user_id: str
    permissions: List[str]

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def generate_nickname() -> str:
    """Generate a unique nickname by checking database for existing nicknames"""
    adjectives = ['Lucky', 'Happy', 'Bright', 'Swift', 'Bold', 'Cool', 'Smart', 'Quick', 'Brave', 'Wise', 
                  'Noble', 'Fierce', 'Mighty', 'Grand', 'Royal', 'Elite', 'Prime', 'Alpha', 'Stellar', 'Epic']
    nouns = ['Tiger', 'Eagle', 'Lion', 'Wolf', 'Bear', 'Fox', 'Hawk', 'Panther', 'Falcon', 'Dragon',
             'Phoenix', 'Raven', 'Cobra', 'Shark', 'Viper', 'Leopard', 'Cheetah', 'Lynx', 'Puma', 'Jaguar']
    
    max_attempts = 50
    for _ in range(max_attempts):
        nickname = f"@{random.choice(adjectives)}{random.choice(nouns)}{random.randint(100, 999)}"
        # Check if nickname already exists
        existing = await db.users.find_one({"nickname": nickname})
        if not existing:
            return nickname
    
    # Fallback: use UUID if all attempts fail
    return f"@User{str(uuid.uuid4())[:8]}"

async def generate_creator_code() -> str:
    """Generate a permanent, unique public creator code (e.g. CR-7F3A2B).
    Distinct from the handle; never changes once assigned."""
    for _ in range(50):
        code = cf.generate_creator_code()
        existing = await db.users.find_one({"creator_code": code}, {"_id": 1})
        if not existing:
            return code
    return cf.generate_creator_code()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload['user_id']}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_business_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access these settings")
    return current_user

async def get_approved_business_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    if current_user.get("approval_status") != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Business profile must be approved")
    return current_user

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None

def hours_until(value: Optional[str]) -> Optional[int]:
    target = parse_iso(value)
    if not target:
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=timezone.utc)
    return int((target - datetime.now(timezone.utc)).total_seconds() // 3600)

CONTACT_INFO_BLOCK_DETAIL = "Your message appears to contain contact information. This cannot be shared on UGCAD.IO to protect both parties."
MIN_BRAND_CHAT_BALANCE = 2500
WALLET_MIN_RECHARGE = 2500
WALLET_BONUS_TIERS = [
    {"amount": 10000, "bonus_percent": 3, "label": "₹10K"},
    {"amount": 25000, "bonus_percent": 7, "label": "₹25K"},
    {"amount": 50000, "bonus_percent": 10, "label": "₹50K"},
]
CHAT_PAUSE_SECONDS = 60 * 60
ACTION_CARDS_ONLY_DAYS = 14
ROLLING_STRIKE_DAYS = 30
IMAGE_MAX_BYTES = 10 * 1024 * 1024
PDF_MAX_BYTES = 25 * 1024 * 1024
VIDEO_MAX_BYTES = 50 * 1024 * 1024
MAX_IMAGES_PER_CHAT_MESSAGE = 5
MAX_VIDEO_SECONDS = 30

IMAGE_CONTENT_TYPES = {"image/jpeg", "image/jpg", "image/png", "image/gif"}
PDF_CONTENT_TYPES = {"application/pdf"}
VIDEO_CONTENT_TYPES = {"video/mp4", "video/quicktime", "video/webm", "video/x-msvideo", "video/mpeg", "video/3gpp", "video/x-matroska"}
CONTACT_URL_DOMAINS = ["wa.me", "t.me", "telegram.me", "linktr.ee", "linktree", "about.me", "beacons.ai", "carrd.co"]
SOCIAL_PLATFORM_PATTERN = re.compile(r"\b(instagram|insta|whatsapp|telegram|linkedin|twitter|youtube|yt|x\.com)\b", re.IGNORECASE)
OBFUSCATED_EMAIL_PATTERN = re.compile(r"\b[\w.-]+\s+(?:at|\[at\]|\(at\))\s+[\w.-]+\s+(?:dot|\[dot\]|\(dot\))\s+[a-z]{2,}\b", re.IGNORECASE)
PHONE_SEQUENCE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\s().-]*){10,15}(?!\w)")

ACTION_CARD_TYPES = {
    "custom_offer",
    "private_invitation",
    "counter_offer",
    "revision_request",
    "milestone_update",
    "damage_report",
    "escalate_to_admin",
    "raise_dispute"
}

ACTIVE_DEAL_STATUSES = {CampaignStatus.IN_PROGRESS, "work_submitted"}
ARCHIVED_DEAL_STATUSES = {CampaignStatus.COMPLETED, CampaignStatus.REJECTED}

def thread_key_for(user_id: str, other_user_id: str) -> str:
    return ":".join(sorted([user_id, other_user_id]))

def get_attachment_kind(content_type: Optional[str], filename: str = "") -> str:
    lower_name = (filename or "").lower()
    if content_type in IMAGE_CONTENT_TYPES or lower_name.endswith((".jpg", ".jpeg", ".png", ".gif")):
        return "image"
    if content_type in PDF_CONTENT_TYPES or lower_name.endswith(".pdf"):
        return "pdf"
    if content_type in VIDEO_CONTENT_TYPES or lower_name.endswith((".mp4", ".mov", ".webm", ".avi", ".mpeg", ".mpg", ".3gp", ".mkv")):
        return "video"
    return "other"

def validate_upload_payload(content_type: Optional[str], filename: str, size: int, duration_seconds: Optional[float] = None) -> str:
    kind = get_attachment_kind(content_type, filename)
    if kind == "image" and size <= IMAGE_MAX_BYTES:
        return kind
    if kind == "pdf" and size <= PDF_MAX_BYTES:
        return kind
    if kind == "video" and size <= VIDEO_MAX_BYTES and (duration_seconds is None or duration_seconds <= MAX_VIDEO_SECONDS):
        return kind
    if kind == "other":
        raise HTTPException(status_code=400, detail="Unsupported file type. Upload jpg, png, gif, pdf, or supported video files.")
    if kind == "image":
        raise HTTPException(status_code=400, detail="Images must be 10 MB or smaller.")
    if kind == "pdf":
        raise HTTPException(status_code=400, detail="PDFs must be 25 MB or smaller.")
    raise HTTPException(status_code=400, detail="Videos must be 50 MB or smaller and 30 seconds or shorter.")

def get_video_duration_seconds(_content: bytes, _filename: str, _content_type: Optional[str]) -> Optional[float]:
    """Placeholder for ffprobe/moviepy integration. None means duration could not be determined."""
    return None

def scan_image_for_contact_info(_content: bytes, _filename: str = "") -> dict:
    """Placeholder OCR hook. Return safe until pytesseract or another OCR provider is configured."""
    return {"safe": True, "violations": []}

def extract_domain(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    cleaned = url.lower().strip()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = re.sub(r"^www\.", "", cleaned)
    return cleaned.split("/")[0] or None

def brand_allowed_domains(*users: dict) -> List[str]:
    domains = []
    for user in users:
        if not user or user.get("role") != UserRole.BUSINESS:
            continue
        profile = user.get("profile") or {}
        for url in [profile.get("website"), user.get("website"), user.get("business_website")]:
            domain = extract_domain(url)
            if domain:
                domains.append(domain)
    return domains

def check_contact_info_policy(message: str, allowed_domains: Optional[List[str]] = None) -> dict:
    text = message or ""
    violations = []
    allowed_domains = allowed_domains or []

    emails = EMAIL_PATTERN.findall(text)
    if emails:
        violations.append({"type": "email", "content": emails, "severity": "high"})

    phones = PHONE_PATTERN.findall(text)
    if phones:
        violations.append({"type": "phone", "content": [str(phone) for phone in phones], "severity": "high"})

    social_handles = SOCIAL_HANDLES_PATTERN.findall(text)
    if social_handles:
        violations.append({"type": "social_handle", "content": social_handles, "severity": "medium"})

    obfuscated_emails = OBFUSCATED_EMAIL_PATTERN.findall(text)
    if obfuscated_emails:
        violations.append({"type": "obfuscated_email", "content": obfuscated_emails, "severity": "high"})

    phone_matches = []
    for match in PHONE_SEQUENCE_PATTERN.findall(text):
        digits = re.sub(r"\D", "", match)
        if 10 <= len(digits) <= 15:
            phone_matches.append(match.strip())
    if phone_matches:
        violations.append({"type": "phone", "content": phone_matches, "severity": "high"})

    platforms = SOCIAL_PLATFORM_PATTERN.findall(text)
    if platforms:
        violations.append({"type": "social_platform", "content": sorted(set(platforms)), "severity": "medium"})

    urls = URL_PATTERN.findall(text)
    blocked_urls = []
    for url in urls:
        lower_url = url.lower()
        domain = extract_domain(url)
        is_allowed_public_brand_site = domain and any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowed_domains)
        is_safe_public_site = any(domain_name in lower_url for domain_name in SAFE_DOMAINS)
        if any(domain_name in lower_url for domain_name in CONTACT_URL_DOMAINS):
            blocked_urls.append(url)
        elif not is_allowed_public_brand_site and not is_safe_public_site:
            blocked_urls.append(url)
    if blocked_urls:
        violations.append({"type": "contact_link", "content": blocked_urls, "severity": "high"})

    deduped = []
    seen = set()
    for violation in violations:
        key = (violation.get("type"), str(violation.get("content")))
        if key not in seen:
            deduped.append(violation)
            seen.add(key)
    return {"safe": len(deduped) == 0, "violations": deduped}

async def notify_admins(title: str, message: str, link: Optional[str] = None):
    notification = {
        "id": str(uuid.uuid4()),
        "title": title,
        "message": message,
        "type": "warning",
        "link": link,
        "target_roles": [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF],
        "read_by": [],
        "created_at": now_iso(),
        "created_by": "system"
    }
    await db.in_app_notifications.insert_one(notification)
    await db.admin_notifications.insert_one(notification.copy())

async def notify_user(user_id: str, title: str, message: str, link: Optional[str] = None, ntype: str = "info"):
    """Send an in-app notification to a single user."""
    await db.in_app_notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "title": title,
        "message": message,
        "type": ntype,
        "link": link,
        "read": False,
        "created_at": now_iso(),
        "created_by": "system",
    })

async def record_match_event(event_type: str, brand_id: Optional[str], creator_id: Optional[str], card_id: Optional[str] = None, campaign_id: Optional[str] = None, extra: Optional[dict] = None):
    """PRD 5.8: capture match-interaction events for later analysis (not shown
    publicly in V0.5)."""
    doc = {
        "id": str(uuid.uuid4()),
        "event_type": event_type,
        "brand_id": brand_id,
        "creator_id": creator_id,
        "card_id": card_id,
        "campaign_id": campaign_id,
        "created_at": now_iso(),
    }
    if extra:
        doc.update(extra)
    await db.match_events.insert_one(doc)

REPEATED_DECLINE_THRESHOLD = 3

async def notify_if_repeated_declines(brand_id: str, creator_id: str):
    """PRD 5.9: if a creator has declined 3+ invitations from the same brand in
    the past 90 days, alert admin when a new invitation is sent (possible
    harassment, or legitimate retargeting)."""
    since = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    declines = await db.chat_action_cards.count_documents({
        "sender_id": brand_id,
        "recipient_id": creator_id,
        "type": "private_invitation",
        "status": "reject",
        "created_at": {"$gte": since},
    })
    if declines >= REPEATED_DECLINE_THRESHOLD:
        await notify_admins(
            "Repeated invitations to a creator who declined",
            f"Brand {brand_id} is inviting creator {creator_id} again after {declines} declines in 90 days.",
        )

async def find_chat_deal(user_id: str, other_user_id: str) -> Optional[dict]:
    return await db.campaigns.find_one({
        "$or": [
            {"business_id": user_id, "selected_creator": other_user_id},
            {"business_id": other_user_id, "selected_creator": user_id},
        ]
    }, {"_id": 0})

async def creator_has_chat_relationship(creator_id: str, brand_id: str) -> bool:
    if await find_chat_deal(creator_id, brand_id):
        return True
    invite_query = {
        "creator_id": creator_id,
        "business_id": brand_id,
        "status": {"$nin": ["rejected", "expired"]}
    }
    for collection_name in ["campaign_invites", "creator_invitations", "private_invitations"]:
        if await db[collection_name].find_one(invite_query, {"_id": 0}):
            return True
    invite = await db.chat_action_cards.find_one({
        "sender_id": brand_id,
        "recipient_id": creator_id,
        "type": "private_invitation"
    }, {"_id": 0})
    return bool(invite)

async def validate_chat_access(current_user: dict, recipient_id: str, allow_action_cards_only: bool = False):
    recipient = await db.users.find_one({"id": recipient_id}, {"_id": 0, "password": 0})
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    if current_user["id"] == recipient_id:
        raise HTTPException(status_code=400, detail="You cannot send chat messages to yourself")

    pause = await db.chat_pauses.find_one({
        "user_id": current_user["id"],
        "paused_until": {"$gt": now_iso()}
    }, {"_id": 0})
    if pause:
        raise HTTPException(status_code=403, detail="Chat is temporarily paused due to contact-info policy violations.")

    action_cards_until = parse_iso(current_user.get("action_cards_only_until"))
    if action_cards_until and action_cards_until > datetime.now(timezone.utc) and not allow_action_cards_only:
        raise HTTPException(status_code=403, detail="Free-form chat is temporarily unavailable. Please use Action Cards for this thread.")

    role = current_user.get("role")
    recipient_role = recipient.get("role")
    if role == UserRole.BUSINESS:
        fresh_user = await db.users.find_one({"id": current_user["id"]}, {"_id": 0})
        if fresh_user.get("approval_status") != ApprovalStatus.APPROVED:
            raise HTTPException(status_code=403, detail="Brand profile must be approved before starting chat.")
        if float(fresh_user.get("balance") or 0) < MIN_BRAND_CHAT_BALANCE:
            raise HTTPException(status_code=403, detail="Brand wallet balance must be at least INR 2,500 to start chat.")
    elif role == UserRole.CREATOR and recipient_role == UserRole.BUSINESS:
        if not await creator_has_chat_relationship(current_user["id"], recipient_id):
            raise HTTPException(status_code=403, detail="Creators can chat only with brands who invited them or with whom they have a deal.")
    elif role not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Chat is only available to creators, brands, and staff.")
    return recipient

async def log_chat_violation(current_user: dict, recipient_id: Optional[str], original_content: str, violations: List[dict], source: str = "message", deal_id: Optional[str] = None) -> dict:
    created_at = now_iso()
    thread_key = thread_key_for(current_user["id"], recipient_id) if recipient_id else None
    if not deal_id and recipient_id:
        deal = await find_chat_deal(current_user["id"], recipient_id)
        deal_id = make_deal_id(deal) if deal else None

    violation_doc = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "user_nickname": current_user.get("nickname"),
        "recipient_id": recipient_id,
        "thread_key": thread_key,
        "deal_id": deal_id,
        "source": source,
        "original_message": original_content,
        "violations": violations,
        "status": "blocked",
        "false_positive_status": None,
        "timestamp": created_at
    }
    await db.violations.insert_one(violation_doc)

    since = (datetime.now(timezone.utc) - timedelta(days=ROLLING_STRIKE_DAYS)).isoformat()
    per_deal_count = await db.chat_strikes.count_documents({
        "user_id": current_user["id"],
        "deal_id": deal_id,
        "invalidated": {"$ne": True}
    }) if deal_id else 0
    rolling_count = await db.chat_strikes.count_documents({
        "user_id": current_user["id"],
        "created_at": {"$gte": since},
        "invalidated": {"$ne": True}
    })
    strike_number = max(per_deal_count, rolling_count) + 1
    severity = "warning"
    if strike_number == 2:
        severity = "paused"
    elif strike_number == 3:
        severity = "action_cards_only"
    elif strike_number >= 4 or any(v.get("severity") == "flagrant" for v in violations):
        severity = "suspended"

    strike_doc = {
        "id": str(uuid.uuid4()),
        "violation_id": violation_doc["id"],
        "user_id": current_user["id"],
        "recipient_id": recipient_id,
        "thread_key": thread_key,
        "deal_id": deal_id,
        "strike_number": strike_number,
        "severity": severity,
        "violations": violations,
        "created_at": created_at,
        "invalidated": False
    }
    await db.chat_strikes.insert_one(strike_doc)

    user_updates = {"warning_count": strike_number, "last_warning_at": created_at}
    if severity == "paused":
        paused_until = (datetime.now(timezone.utc) + timedelta(seconds=CHAT_PAUSE_SECONDS)).isoformat()
        await db.chat_pauses.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": current_user["id"],
            "recipient_id": recipient_id,
            "thread_key": thread_key,
            "deal_id": deal_id,
            "paused_until": paused_until,
            "created_at": created_at,
            "reason": "contact_info_attempt"
        })
        await notify_admins("Chat policy strike", f"{current_user.get('nickname', current_user['id'])} received a second chat contact-info strike.")
    elif severity == "action_cards_only":
        user_updates["action_cards_only_until"] = (datetime.now(timezone.utc) + timedelta(days=ACTION_CARDS_ONLY_DAYS)).isoformat()
        await notify_admins("Action Cards only mode enabled", f"{current_user.get('nickname', current_user['id'])} reached a third chat contact-info strike.")
    elif severity == "suspended":
        user_updates.update({"banned": True, "banned_reason": "Chat contact-info policy violations pending admin review"})
        await notify_admins("Account suspended for review", f"{current_user.get('nickname', current_user['id'])} reached repeated or flagrant chat contact-info violations.")

    await db.users.update_one({"id": current_user["id"]}, {"$set": user_updates})
    return {"violation": violation_doc, "strike": strike_doc}

async def validate_message_attachments(attachment_urls: List[str]):
    if len(attachment_urls) > MAX_IMAGES_PER_CHAT_MESSAGE:
        # A message can include up to five image attachments; this also caps mixed simple file-only payloads.
        raise HTTPException(status_code=400, detail="A chat message can include at most 5 attachments.")
    if not attachment_urls:
        return
    uploads = await db.uploaded_files.find({"file_url": {"$in": attachment_urls}}, {"_id": 0}).to_list(100)
    upload_by_url = {item["file_url"]: item for item in uploads}
    image_count = 0
    for url in attachment_urls:
        meta = upload_by_url.get(url, {})
        kind = meta.get("kind") or get_attachment_kind(meta.get("content_type"), meta.get("filename") or url)
        if kind == "other":
            raise HTTPException(status_code=400, detail=f"Unsupported attachment: {url}")
        if kind == "image":
            image_count += 1
            if image_count > MAX_IMAGES_PER_CHAT_MESSAGE:
                raise HTTPException(status_code=400, detail="A chat message can include at most 5 images.")
        if meta.get("size"):
            validate_upload_payload(meta.get("content_type"), meta.get("filename") or url, int(meta["size"]), meta.get("duration_seconds"))

def strip_private_fields(user_doc: dict, requester_role: Optional[str]) -> dict:
    """Remove fields that should not leak to other roles.

    Username is a creator's private internal handle — only visible to the creator
    themselves and admin/staff. Brands continue to see the auto-generated nickname.
    """
    if not isinstance(user_doc, dict):
        return user_doc
    if requester_role == UserRole.BUSINESS:
        user_doc.pop("username", None)
        user_doc.pop("email", None)
    return user_doc

def message_to_chat_item(msg: dict) -> dict:
    created_at = msg.get("created_at") or msg.get("timestamp")
    read_by = msg.get("read_by") or ([msg.get("recipient_id")] if msg.get("read") else [])
    return {
        **msg,
        "item_type": "message",
        "created_at": created_at,
        "timestamp": created_at,
        "attachment_urls": msg.get("attachment_urls", []),
        "read": bool(msg.get("read")),
        "read_by": read_by,
        "read_at": msg.get("read_at"),
        "status": msg.get("status") or ("read" if read_by else "delivered")
    }

def action_card_to_chat_item(card: dict) -> dict:
    expired = is_action_card_expired(card)
    return {
        **card,
        "item_type": "action_card",
        "message": card.get("message") or card.get("title") or card.get("type"),
        "attachment_urls": card.get("attachment_urls", []),
        "read": bool(card.get("read")),
        "read_by": card.get("read_by", []),
        "is_expired": expired,
        "display_status": "expired" if expired else card.get("status"),
        "timestamp": card.get("created_at")
    }

OFFER_CARD_TYPES = ["custom_offer", "private_invitation", "counter_offer"]
DECLINE_REASONS = ["not_my_niche", "budget", "timeline", "unavailable", "other"]


def action_card_deadline(card: dict) -> Optional[datetime]:
    """The response deadline for an offer-type card (72h invites, 48h offers)."""
    fields = card.get("fields") or {}
    return parse_iso(fields.get("response_deadline") or fields.get("expires_at"))


def is_action_card_expired(card: dict) -> bool:
    if card.get("type") not in OFFER_CARD_TYPES:
        return False
    if card.get("status") not in ["open", "pending"]:
        return False
    deadline = action_card_deadline(card)
    return bool(deadline and deadline < datetime.now(timezone.utc))


def get_action_card_available_actions(card_type: str) -> List[str]:
    if card_type in ["custom_offer", "private_invitation", "counter_offer"]:
        return ["accept", "reject", "counter"]
    if card_type in ["revision_request", "damage_report", "escalate_to_admin", "raise_dispute"]:
        return ["acknowledge", "resolve"]
    return ["acknowledge"]

def require_fields(fields: Dict[str, Any], required: List[str], card_type: str):
    missing = [field for field in required if fields.get(field) in [None, "", []]]
    if missing:
        raise HTTPException(status_code=400, detail=f"{card_type} requires: {', '.join(missing)}")

async def enforce_offer_price_floor(sender: dict, recipient_id: str, price: Any, field_name: str):
    """Reject offers/counter-offers priced below the creator's level floor (PRD:
    level-based price floors). The floor is keyed off the creator in the thread,
    whether the offer is sent by the creator or by the brand."""
    if sender.get("role") == UserRole.CREATOR:
        creator = sender
    else:
        creator = await db.users.find_one(
            {"id": recipient_id},
            {"_id": 0, "level": 1, "role": 1, "quality_tier": 1, "content_quality_tier": 1, "profile": 1},
        )
        if not creator or creator.get("role") != UserRole.CREATOR:
            return  # not a creator thread; no floor to enforce
    quality_tier = (
        creator.get("quality_tier")
        or creator.get("content_quality_tier")
        or (creator.get("profile") or {}).get("quality_tier")
    )
    floor = cf.price_floor_for_level(creator.get("level"), quality_tier)
    try:
        value = float(price)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{field_name} must be a number.")
    if value < floor:
        level_label = cf.CREATOR_LEVELS[cf.normalize_level(creator.get("level"))]["label"]
        tier_note = f" (tier {cf.normalize_quality_tier(quality_tier).upper()})" if quality_tier else ""
        raise HTTPException(
            status_code=400,
            detail=f"Offer is below the minimum for a {level_label} creator{tier_note}. The price floor is ₹{floor}.",
        )


CUSTOM_OFFER_DAILY_LIMIT = 5
CUSTOM_OFFER_ANOMALY_MULTIPLE = 5  # price >= this * floor → admin spot-check


async def enforce_custom_offer_abuse_rules(sender: dict, recipient_id: str, fields: Dict[str, Any]) -> None:
    """PRD 5.7 anti-abuse: max 5 custom offers/day, 24h resend block on a declined
    offer, and an admin spot-check flag for anomalous pricing."""
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(hours=24)).isoformat()

    # 1. Max 5 custom offers per creator per day
    sent_today = await db.chat_action_cards.count_documents({
        "sender_id": sender["id"],
        "type": "custom_offer",
        "created_at": {"$gte": day_ago},
    })
    if sent_today >= CUSTOM_OFFER_DAILY_LIMIT:
        raise HTTPException(status_code=429, detail=f"You can send at most {CUSTOM_OFFER_DAILY_LIMIT} custom offers per day.")

    # 2. If declined, the same offer cannot be resent for 24 hours
    recent_declined = await db.chat_action_cards.find_one({
        "sender_id": sender["id"],
        "recipient_id": recipient_id,
        "type": "custom_offer",
        "status": "reject",
        "fields.deliverable_type": fields.get("deliverable_type"),
        "fields.price": fields.get("price"),
        "response.responded_at": {"$gte": day_ago},
    })
    if recent_declined:
        raise HTTPException(status_code=429, detail="This offer was declined in the last 24 hours. Please wait before resending the same offer.")

    # 3. Flag anomalous pricing for admin spot-check (does not block)
    quality_tier = sender.get("quality_tier") or sender.get("content_quality_tier") or (sender.get("profile") or {}).get("quality_tier")
    floor = cf.price_floor_for_level(sender.get("level"), quality_tier)
    try:
        value = float(fields.get("price"))
    except (TypeError, ValueError):
        value = 0.0
    if floor and value >= floor * CUSTOM_OFFER_ANOMALY_MULTIPLE:
        fields["flagged_for_review"] = True
        await notify_admins(
            "Custom offer flagged for spot-check",
            f"{sender.get('nickname', sender['id'])} sent a custom offer of ₹{int(value)} (≥{CUSTOM_OFFER_ANOMALY_MULTIPLE}× their ₹{floor} floor).",
        )


async def validate_action_card_payload(data: ChatActionCardCreate, current_user: dict):
    if data.type not in ACTION_CARD_TYPES:
        raise HTTPException(status_code=400, detail="Invalid action card type")
    fields = data.fields or {}
    if data.type == "custom_offer":
        require_fields(fields, ["deliverable_type", "quantity", "duration", "price", "timeline", "usage_rights"], "custom_offer")
        await enforce_offer_price_floor(current_user, data.recipient_id, fields.get("price"), "price")
        await enforce_custom_offer_abuse_rules(current_user, data.recipient_id, fields)
        fields.setdefault("expires_at", (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat())
    elif data.type == "private_invitation":
        require_fields(fields, ["campaign_name", "deliverable_summary", "budget", "timeline", "usage_rights", "full_brief_link"], "private_invitation")
        fields.setdefault("response_deadline", (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat())
    elif data.type == "counter_offer":
        require_fields(fields, ["modified_price", "revisions", "timeline", "usage_rights", "diff_vs_original"], "counter_offer")
        await enforce_offer_price_floor(current_user, data.recipient_id, fields.get("modified_price"), "modified_price")
        existing_rounds = await db.chat_action_cards.count_documents({
            "thread_key": thread_key_for(current_user["id"], data.recipient_id),
            "type": "counter_offer"
        })
        if existing_rounds >= 3:
            raise HTTPException(status_code=400, detail="Counter offers are limited to 3 rounds.")
        fields["round"] = existing_rounds + 1
        fields.setdefault("expires_at", (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat())
    elif data.type == "revision_request":
        items = fields.get("revision_items") or fields.get("items") or []
        if not isinstance(items, list) or not 1 <= len(items) <= 5:
            raise HTTPException(status_code=400, detail="Revision request requires 1 to 5 revision items.")
        if data.deal_id:
            campaign = await get_campaign_by_deal_id(data.deal_id)
            if campaign and campaign.get("status") != "work_submitted":
                raise HTTPException(status_code=400, detail="Revision requests are allowed only during Content Submitted - Awaiting Review.")
    elif data.type == "milestone_update":
        require_fields(fields, ["status"], "milestone_update")
    elif data.type == "damage_report":
        require_fields(fields, ["reason", "description", "severity"], "damage_report")
    elif data.type == "escalate_to_admin":
        require_fields(fields, ["summary", "category"], "escalate_to_admin")
        summary_length = len(str(fields.get("summary", "")))
        if summary_length < 100 or summary_length > 500:
            raise HTTPException(status_code=400, detail="Escalation summary must be 100 to 500 characters.")
    elif data.type == "raise_dispute":
        require_fields(fields, ["summary", "category"], "raise_dispute")
    return fields

def to_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0

def require_non_empty(data: Dict[str, Any], fields: List[str]):
    missing = [field for field in fields if data.get(field) in [None, ""]]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required fields: {', '.join(missing)}")

def validate_choice(value: Optional[str], allowed: List[str], field_name: str):
    if value is not None and value not in allowed:
        raise HTTPException(status_code=400, detail=f"{field_name} must be one of: {', '.join(allowed)}")

def business_profile_defaults(user: dict, settings: Optional[dict] = None) -> dict:
    settings = settings or {}
    profile = user.get("profile") or {}
    return {
        "brand_name": settings.get("brand_name") or profile.get("business_name") or user.get("business_name") or user.get("nickname") or "",
        "contact_person": settings.get("contact_person") or user.get("contact_person") or user.get("nickname") or "",
        "work_email": settings.get("work_email") or user.get("email") or "",
        "phone_number": settings.get("phone_number") or user.get("phone_number") or "",
        "website_url": settings.get("website_url") or profile.get("website") or user.get("website") or user.get("business_website") or "",
        "logo_url": settings.get("logo_url") or profile.get("logo") or user.get("logo_url") or ""
    }

def business_company_defaults(user: dict, settings: Optional[dict] = None) -> dict:
    settings = settings or {}
    profile = user.get("profile") or {}
    approval_status = user.get("approval_status")
    kyb_status = "pending"
    if approval_status == ApprovalStatus.APPROVED:
        kyb_status = "verified"
    elif approval_status == ApprovalStatus.REJECTED:
        kyb_status = "rejected"
    return {
        "business_type": settings.get("business_type") or profile.get("product_type") or "",
        "gst_number": settings.get("gst_number") or user.get("gst_number") or "",
        "business_category": settings.get("business_category") or profile.get("industry_category") or "",
        "country": settings.get("country") or "India",
        "billing_address": settings.get("billing_address") or "",
        "city": settings.get("city") or "",
        "state": settings.get("state") or "",
        "kyb_status": settings.get("kyb_status") or kyb_status
    }

def business_notification_defaults(settings: Optional[dict] = None) -> dict:
    defaults = {
        "new_creator_applications": True,
        "deal_status_updates": True,
        "payment_escrow_alerts": True,
        "direct_messages": True,
        "weekly_workspace_reports": True
    }
    if settings:
        defaults.update({key: settings[key] for key in defaults.keys() if key in settings})
    return defaults

def month_start(dt: datetime) -> datetime:
    return datetime(dt.year, dt.month, 1, tzinfo=timezone.utc)

def add_months(dt: datetime, months: int) -> datetime:
    month = dt.month - 1 + months
    year = dt.year + month // 12
    month = month % 12 + 1
    return datetime(year, month, 1, tzinfo=timezone.utc)

def is_between_iso(value: Optional[str], start: datetime, end: datetime) -> bool:
    parsed = parse_iso(value)
    if not parsed:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return start <= parsed < end

def campaign_budget_total(campaign: dict) -> float:
    if campaign.get("budget"):
        return to_float(campaign.get("budget"))
    budget_min = to_float(campaign.get("budget_min"))
    budget_max = to_float(campaign.get("budget_max"))
    if budget_min and budget_max:
        return budget_max
    return budget_min or budget_max

def campaign_category(campaign: dict) -> str:
    return (
        campaign.get("industry_category") or
        campaign.get("category") or
        campaign.get("product_type") or
        ((campaign.get("objectives") or ["Other"])[0] if isinstance(campaign.get("objectives"), list) else campaign.get("objectives")) or
        "Other"
    )

def selected_bid_amount(campaign: dict) -> float:
    selected_creator = campaign.get("selected_creator")
    for bid in campaign.get("bids", []):
        if bid.get("creator_id") == selected_creator:
            return to_float(bid.get("amount"))
    return 0.0

def dashboard_stage(campaign: dict, work: Optional[dict], shipment: Optional[dict]) -> dict:
    status_value = campaign.get("status")
    work_status = (work or {}).get("status")
    shipment_status = (shipment or {}).get("status") or (shipment or {}).get("courier_status")
    if work_status == WorkStatus.SUBMITTED or status_value == "work_submitted":
        return {"stage": "awaiting_review", "stage_label": "Awaiting Review", "next_action": "review", "next_action_label": "Review"}
    if work_status == WorkStatus.REVISION_REQUESTED:
        return {"stage": "revision_requested", "stage_label": "Revision Requested", "next_action": "await_revision", "next_action_label": "Await Revision"}
    if work_status == WorkStatus.APPROVED or status_value == CampaignStatus.COMPLETED:
        return {"stage": "completed", "stage_label": "Completed", "next_action": "none", "next_action_label": "None"}
    if shipment_status in ["shipped", "in_transit", "delivered"]:
        return {"stage": "in_transit", "stage_label": "In Transit", "next_action": "track", "next_action_label": "Track"}
    if campaign.get("requires_shipment"):
        return {"stage": "awaiting_shipment", "stage_label": "Awaiting Shipment", "next_action": "upload_shipment", "next_action_label": "Upload Shipment"}
    return {"stage": "in_progress", "stage_label": "In Progress", "next_action": "monitor", "next_action_label": "Monitor"}

def percent_change(current: int, previous: int) -> float:
    if previous == 0:
        return 100.0 if current > 0 else 0.0
    return round(((current - previous) / previous) * 100, 2)

def wallet_bonus_percent(amount: float) -> int:
    percent = 0
    for tier in WALLET_BONUS_TIERS:
        if amount >= tier["amount"]:
            percent = tier["bonus_percent"]
    return percent

def wallet_bonus_amount(amount: float) -> float:
    return round(amount * wallet_bonus_percent(amount) / 100, 2)

def wallet_bonus_progress(amount: float) -> dict:
    current_tier = None
    next_tier = None
    for tier in WALLET_BONUS_TIERS:
        if amount >= tier["amount"]:
            current_tier = tier
        elif next_tier is None:
            next_tier = tier

    if current_tier is None:
        base_amount = 0
        current_tier = {"amount": 0, "bonus_percent": 0}
    else:
        base_amount = current_tier["amount"]

    if next_tier:
        span = next_tier["amount"] - base_amount
        amount_to_next = max(next_tier["amount"] - amount, 0)
        progress = round(((amount - base_amount) / span) * 100, 2) if span else 100
    else:
        amount_to_next = 0
        progress = 100

    return {
        "current_tier_percent": current_tier["bonus_percent"],
        "next_tier_percent": next_tier["bonus_percent"] if next_tier else current_tier["bonus_percent"],
        "current_tier_amount": current_tier["amount"],
        "next_tier_amount": next_tier["amount"] if next_tier else current_tier["amount"],
        "amount_to_next_tier": amount_to_next,
        "progress_percent": min(max(progress, 0), 100),
    }

def normalize_wallet_transaction(source: dict, default_type: str = "Wallet Recharge", default_direction: str = "credit") -> dict:
    tx_type = source.get("type") or source.get("purpose") or default_type
    status = source.get("status") or "success"
    amount = to_float(source.get("amount") or source.get("held_amount") or source.get("fee_amount"))
    direction = source.get("direction") or default_direction

    if tx_type in ["wallet_recharge", "payment", "recharge"]:
        tx_type = "Wallet Recharge"
        direction = "credit"
    elif tx_type in ["bonus_credit", "bonus"]:
        tx_type = "Bonus Credit"
        direction = "credit"
    elif tx_type in ["escrow", "escrow_lock", "held", "hold"]:
        tx_type = "Escrow Lock"
        direction = "debit"
    elif tx_type in ["platform_fee", "listing_fee", "fee"]:
        tx_type = "Platform Fee"
        direction = "debit"
    elif tx_type in ["refund", "wallet_refund"]:
        tx_type = "Refund"
        direction = "credit"

    return {
        "id": source.get("id") or source.get("gateway_order_id") or str(uuid.uuid4()),
        "date": source.get("created_at") or source.get("completed_at") or source.get("updated_at") or now_iso(),
        "type": tx_type,
        "reference": source.get("reference") or source.get("gateway_payment_id") or source.get("gateway_order_id") or source.get("campaign_id"),
        "amount": amount,
        "direction": direction,
        "status": status,
    }

async def credit_wallet_for_successful_transaction(transaction: dict, gateway_payment_id: Optional[str] = None) -> dict:
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")

    now = now_iso()
    set_fields = {
        "status": "success",
        "completed_at": now,
    }
    if gateway_payment_id:
        set_fields["gateway_payment_id"] = gateway_payment_id

    if transaction.get("purpose") != "wallet_recharge":
        await db.payment_transactions.update_one(
            {"id": transaction["id"]},
            {"$set": set_fields}
        )
        updated = await db.payment_transactions.find_one({"id": transaction["id"]}, {"_id": 0})
        wallet_user = await db.users.find_one({"id": transaction.get("user_id")}, {"_id": 0, "balance": 1})
        return {"transaction": updated, "wallet_balance": to_float((wallet_user or {}).get("balance"))}

    update_result = await db.payment_transactions.update_one(
        {"id": transaction["id"], "wallet_credited": {"$ne": True}},
        {"$set": {
            **set_fields,
            "wallet_credited": True,
            "credited_at": now,
        }}
    )

    if update_result.modified_count:
        amount = to_float(transaction.get("amount"))
        bonus_amount = to_float(transaction.get("bonus_amount"))
        credited_amount = to_float(transaction.get("credited_amount")) or amount + bonus_amount
        await db.users.update_one(
            {"id": transaction["user_id"]},
            {"$inc": {"balance": credited_amount}}
        )
        reference = gateway_payment_id or transaction.get("gateway_payment_id") or transaction.get("gateway_order_id")
        ledger_rows = [{
            "id": str(uuid.uuid4()),
            "user_id": transaction["user_id"],
            "transaction_id": transaction["id"],
            "type": "Wallet Recharge",
            "amount": amount,
            "direction": "credit",
            "status": "success",
            "reference": reference,
            "created_at": now,
        }]
        if bonus_amount > 0:
            ledger_rows.append({
                "id": str(uuid.uuid4()),
                "user_id": transaction["user_id"],
                "transaction_id": transaction["id"],
                "type": "Bonus Credit",
                "amount": bonus_amount,
                "direction": "credit",
                "status": "success",
                "reference": reference,
                "created_at": now,
            })
        await db.wallet_ledger.insert_many(ledger_rows)
    elif gateway_payment_id:
        await db.payment_transactions.update_one(
            {"id": transaction["id"]},
            {"$set": {"gateway_payment_id": gateway_payment_id}}
        )

    updated = await db.payment_transactions.find_one({"id": transaction["id"]}, {"_id": 0})
    wallet_user = await db.users.find_one({"id": transaction.get("user_id")}, {"_id": 0, "balance": 1})
    return {"transaction": updated, "wallet_balance": to_float((wallet_user or {}).get("balance"))}

def make_deal_id(campaign: dict) -> str:
    if campaign.get('deal_id'):
        return campaign['deal_id']
    campaign_id = str(campaign.get('id', ''))
    try:
        number = uuid.UUID(campaign_id).int % 9000 + 1000
    except (TypeError, ValueError):
        number = sum(ord(ch) for ch in campaign_id) % 9000 + 1000
    return f"DEAL-{number}"

def get_required_assets(campaign: dict) -> dict:
    checklist = campaign.get('content_requirements') or campaign.get('shipment_checklist') or {}
    return {
        "final_video": True,
        "caption_script": bool(
            checklist.get('caption_script') or
            checklist.get('caption') or
            campaign.get('caption_required')
        ),
        "thumbnail": bool(checklist.get('thumbnail') or campaign.get('thumbnail_required')),
        "raw_footage": bool(
            checklist.get('raw_footage') or
            checklist.get('raw_files') or
            campaign.get('raw_footage_required')
        )
    }

def get_brief_sections(campaign: dict) -> List[dict]:
    brief_text = campaign.get('brief_text') or ''
    budget_text = f"Budget: {campaign.get('budget_min', 0)} - {campaign.get('budget_max', 0)} INR"
    objectives = campaign.get('objectives') or []
    objective_text = ', '.join(objectives) if objectives else brief_text
    fields = [
        ("Campaign Basics", campaign.get('campaign_basics') or brief_text),
        ("Deliverables", campaign.get('deliverables') or objective_text),
        ("Creative Requirements", campaign.get('creative_requirements') or brief_text),
        ("Creative Restrictions", campaign.get('creative_restrictions') or campaign.get('restrictions') or ''),
        ("Style Guidance", campaign.get('style_guidance') or campaign.get('tone') or ''),
        ("Usage Rights", campaign.get('usage_rights') or campaign.get('usage') or ''),
        ("Timeline & Budget", campaign.get('timeline_budget') or budget_text),
        ("Review Summary", campaign.get('review_summary') or brief_text)
    ]
    return [{"title": title, "content": content or "Not specified"} for title, content in fields]

def normalize_shipment(campaign: dict, shipment: Optional[dict]) -> dict:
    shipment = shipment or {}
    raw_status = shipment.get('courier_status') or shipment.get('status')
    status_map = {
        "shipped": "shipped",
        "in_transit": "in_transit",
        "delivered": "delivered",
        "received": "delivered"
    }
    return {
        "required": bool(campaign.get('requires_shipment')),
        "tracking_id": shipment.get('tracking_id') or shipment.get('tracking_number'),
        "courier_name": shipment.get('courier_name') or shipment.get('courier'),
        "courier_tracking_url": shipment.get('courier_tracking_url') or shipment.get('tracking_url'),
        "courier_status": status_map.get(raw_status, raw_status),
        "expected_delivery_at": shipment.get('expected_delivery_at') or shipment.get('expected_delivery'),
        "delivered_at": shipment.get('delivered_at')
    }

def normalize_receipt(shipment: Optional[dict], receipt: Optional[dict]) -> dict:
    shipment = shipment or {}
    receipt = receipt or {}
    damage = receipt.get('damage_report') or shipment.get('dispute', {}).get('reason')
    return {
        "received_at": receipt.get('received_at') or shipment.get('received_at'),
        "unboxing_video_url": (
            receipt.get('unboxing_video_url') or
            receipt.get('unboxing_video') or
            shipment.get('unboxing_video_url') or
            shipment.get('unboxing_video')
        ),
        "items_damaged": bool(receipt.get('items_damaged') or shipment.get('dispute', {}).get('reported')),
        "damage_report": damage
    }

def normalize_escrow(escrow: Optional[dict], my_bid: Optional[dict], state: Optional[str] = None) -> dict:
    escrow = escrow or {}
    amount = float(escrow.get('amount') or escrow.get('held_amount') or (my_bid or {}).get('amount') or 0)
    status_value = escrow.get('status') or ("released" if state == "Paid — Complete" else "held")
    status_map = {
        "held": "held",
        "released": "released",
        "on_hold": "on_hold",
        "disputed": "on_hold"
    }
    deductions = escrow.get('deductions') or [
        {"label": "TDS", "amount": 0},
        {"label": "Penalty", "amount": 0}
    ]
    net_payable = escrow.get('net_payable')
    if net_payable is None:
        net_payable = amount - sum(float(item.get('amount') or 0) for item in deductions)
    return {
        "status": status_map.get(status_value, "held"),
        "held_amount": amount,
        "currency": escrow.get('currency') or "INR",
        "net_payable": net_payable,
        "deductions": deductions,
        "estimated_payout_at": escrow.get('estimated_payout_at') or escrow.get('released_at')
    }

def normalize_content_submission(campaign: dict, content_versions: List[dict], work: Optional[dict]) -> dict:
    versions = []
    for version in content_versions:
        versions.append({
            "version": version.get('version'),
            "video_url": version.get('video_url'),
            "caption_url": version.get('caption_url'),
            "thumbnail_url": version.get('thumbnail_url'),
            "raw_footage_url": version.get('raw_footage_url'),
            "original_url": version.get('original_url') or version.get('video_url'),
            "watermark": version.get('watermark') or cf.build_watermark_record(version.get('video_url'), "video"),
            "submitted_at": version.get('submitted_at'),
            "status": version.get('status', 'submitted')
        })
    if work and not versions:
        work_files = work.get('work_files') or []
        versions.append({
            "version": 1,
            "video_url": work_files[0] if work_files else None,
            "caption_url": None,
            "thumbnail_url": None,
            "raw_footage_url": None,
            "submitted_at": work.get('submitted_at'),
            "status": work.get('status', 'submitted')
        })
    return {
        "required_assets": get_required_assets(campaign),
        "versions": versions,
        "watermark_required_until_approval": True
    }

def normalize_revision_tracker(work: Optional[dict], response: Optional[dict]) -> dict:
    revisions = (work or {}).get('revisions') or []
    latest = revisions[-1] if revisions else {}
    requested_changes = latest.get('requested_changes')
    if not requested_changes and latest.get('feedback'):
        requested_changes = [line.strip() for line in latest['feedback'].splitlines() if line.strip()]
    used = len(revisions)
    return {
        "revision_count_used": used,
        "revision_limit": (work or {}).get('revision_limit', cf.FREE_REVISION_LIMIT),
        "free_revision_limit": cf.FREE_REVISION_LIMIT,
        "free_revisions_remaining": max(0, cf.FREE_REVISION_LIMIT - used),
        "next_revision_fee": cf.revision_fee_for(used),
        "latest_feedback": latest.get('feedback'),
        "requested_changes": requested_changes or [],
        "new_deadline_at": latest.get('new_deadline_at'),
        "creator_response": (response or {}).get('response')
    }

def compute_deal_state(campaign: dict, shipment: Optional[dict], receipt: dict, work: Optional[dict], escrow: Optional[dict], action_cards: List[dict]) -> dict:
    damaged = receipt.get('items_damaged') or any(card.get('type') == 'damage_report' and card.get('status') == 'open' for card in action_cards)
    disputed = any(card.get('type') in ['raise_dispute', 'escalate_to_admin'] and card.get('status') == 'open' for card in action_cards)
    shipment_status = (shipment or {}).get('status') or (shipment or {}).get('courier_status')
    work_status = (work or {}).get('status')
    escrow_status = (escrow or {}).get('status')

    if damaged:
        state, party, action = "Damaged/Wrong Product Reported", "brand", "Resolve damage report"
        started = receipt.get('received_at') or now_iso()
    elif disputed:
        state, party, action = "Disputed", "admin", "Await admin resolution"
        started = now_iso()
    elif escrow_status == "released" and campaign.get('status') == CampaignStatus.COMPLETED:
        state, party, action = "Paid — Complete", "system", "Deal complete"
        started = (escrow or {}).get('released_at') or (work or {}).get('approved_at')
    elif work_status == WorkStatus.APPROVED or campaign.get('status') == CampaignStatus.COMPLETED:
        state, party, action = "Approved — Payment Processing", "system", "Process payout"
        started = (work or {}).get('approved_at') or campaign.get('updated_at')
    elif work_status == WorkStatus.REVISION_REQUESTED:
        state, party, action = "Revision Requested", "creator", "Submit revised content"
        revisions = (work or {}).get('revisions') or []
        started = (revisions[-1] if revisions else {}).get('requested_at') or (work or {}).get('submitted_at')
    elif work_status == WorkStatus.SUBMITTED or campaign.get('status') == "work_submitted":
        state, party, action = "Content Submitted — Awaiting Review", "brand", "Review submitted content"
        started = (work or {}).get('submitted_at')
    elif receipt.get('received_at') or shipment_status == "received":
        state, party, action = "Received — Content in Progress", "creator", "Submit content"
        started = receipt.get('received_at') or (shipment or {}).get('received_at')
    elif shipment_status == "delivered":
        state, party, action = "Delivered — Awaiting Receipt Confirmation", "creator", "Confirm receipt"
        started = (shipment or {}).get('delivered_at') or (shipment or {}).get('updated_at')
    elif shipment_status in ["shipped", "in_transit"]:
        state, party, action = "Shipped — In Transit", "creator", "Track shipment"
        started = (shipment or {}).get('updated_at')
    elif campaign.get('requires_shipment'):
        state, party, action = "Accepted — Awaiting Shipment", "brand", "Upload shipment tracking"
        started = campaign.get('work_started_at') or campaign.get('created_at')
    else:
        state, party, action = "Received — Content in Progress", "creator", "Submit content"
        started = campaign.get('work_started_at') or campaign.get('created_at')

    next_deadline = (
        (work or {}).get('due_at') or
        (shipment or {}).get('expected_delivery_at') or
        (shipment or {}).get('expected_delivery') or
        campaign.get('deadline') or
        campaign.get('due_date')
    )
    return {
        "current_state": state,
        "active_party": party,
        "primary_next_action": action,
        "state_started_at": started,
        "next_deadline_at": next_deadline,
        "deadline_countdown_hours": hours_until(next_deadline)
    }

def map_sender_type(sender_id: str, campaign: dict, creator_id: str, sender_role: Optional[str] = None) -> str:
    if sender_id == "system":
        return "system"
    if sender_role in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        return "admin"
    if sender_id == creator_id:
        return "creator"
    if sender_id == campaign.get('business_id'):
        return "brand"
    return sender_role or "system"

async def insert_deal_activity(campaign: dict, actor_type: str, actor_name: str, event_type: str, message: str) -> dict:
    event = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "timestamp": now_iso(),
        "actor_type": actor_type,
        "actor_name": actor_name,
        "event_type": event_type,
        "message": message
    }
    await db.deal_activity.insert_one(event)
    return event

async def insert_deal_system_message(campaign: dict, message: str) -> dict:
    msg = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "sender_id": "system",
        "sender_name": "System",
        "sender_type": "system",
        "message": message,
        "attachment_urls": [],
        "created_at": now_iso(),
        "read_by": []
    }
    await db.deal_messages.insert_one(msg)
    return msg

async def get_campaign_by_deal_id(deal_id: str) -> Optional[dict]:
    campaign = await db.campaigns.find_one({"$or": [{"deal_id": deal_id}, {"id": deal_id}]}, {"_id": 0})
    if campaign:
        return campaign
    campaigns = await db.campaigns.find({}, {"_id": 0}).to_list(10000)
    return next((item for item in campaigns if make_deal_id(item) == deal_id), None)

def ensure_deal_access(campaign: dict, current_user: dict):
    role = current_user.get('role')
    if role == UserRole.CREATOR and campaign.get('selected_creator') == current_user['id']:
        return
    if role == UserRole.BUSINESS and campaign.get('business_id') == current_user['id']:
        return
    if role in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        return
    raise HTTPException(status_code=403, detail="Not authorized for this deal")

async def settle_deal_lazily(campaign: dict) -> None:
    """Per-deal lazy settlement so payouts/auto-approval work without a cron.
    Auto-approves a stale submission and releases a due scheduled payout."""
    now = datetime.now(timezone.utc)
    cid = campaign.get('id')
    # Auto-approve a stale, undisputed submission (PRD 8.4).
    work = await db.work_submissions.find_one({"campaign_id": cid, "status": WorkStatus.SUBMITTED})
    if work:
        submitted = parse_iso(work.get('submitted_at') or work.get('created_at'))
        if submitted and (now - submitted).days >= AUTO_APPROVE_DAYS:
            cards = await db.deal_action_cards.find({"campaign_id": cid}, {"_id": 0}).to_list(100)
            disputed = any(c.get('type') in ['raise_dispute', 'escalate_to_admin'] and c.get('status') == 'open' for c in cards)
            if not disputed:
                await db.work_submissions.update_one({"id": work['id']}, {"$set": {"status": WorkStatus.APPROVED, "approved_at": now_iso(), "auto_approved": True}})
                await schedule_payout_for_deal(campaign, work, source="auto_approval")
                await db.campaigns.update_one({"id": cid}, {"$set": {"payout_status": "scheduled", "updated_at": now_iso()}})
                await notify_user(work['creator_id'], "Your content was auto-approved", "The brand didn't review in time, so your content was auto-approved.", link="/my-deals")
    # Release a due scheduled payout (PRD 8.7).
    escrow = await db.escrow.find_one({"campaign_id": cid, "payout_status": "scheduled"})
    if escrow:
        scheduled = parse_iso(escrow.get('payout_scheduled_at'))
        if scheduled and scheduled <= now:
            await release_scheduled_payout(escrow)


async def get_deal_context(deal_id: str, current_user: dict) -> dict:
    campaign = await get_campaign_by_deal_id(deal_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    ensure_deal_access(campaign, current_user)
    # Lazy settlement (no cron needed): release a due payout / auto-approve a stale
    # submission for this specific deal when it is viewed (PRD 8.4 / 8.7).
    await settle_deal_lazily(campaign)
    campaign = await get_campaign_by_deal_id(deal_id) or campaign
    creator = await db.users.find_one({"id": campaign.get('selected_creator')}, {"_id": 0, "password": 0})
    if not creator:
        raise HTTPException(status_code=404, detail="Creator not found for deal")
    brand = await db.users.find_one({"id": campaign.get('business_id')}, {"_id": 0, "password": 0})
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found for deal")
    my_bid = next((bid for bid in campaign.get('bids', []) if bid.get('creator_id') == creator['id']), None)
    shipment = await db.shipments.find_one({"campaign_id": campaign['id']}, {"_id": 0})
    receipt = await db.deal_receipts.find_one({"campaign_id": campaign['id']}, {"_id": 0})
    work = await db.work_submissions.find_one(
        {"campaign_id": campaign['id'], "creator_id": creator['id']},
        {"_id": 0},
        sort=[("submitted_at", -1)]
    )
    escrow = await db.escrow.find_one({"campaign_id": campaign['id']}, {"_id": 0})
    content_versions = await db.deal_content_submissions.find(
        {"campaign_id": campaign['id'], "creator_id": creator['id']},
        {"_id": 0}
    ).sort("version", 1).to_list(100)
    revision_response = await db.deal_revision_responses.find_one(
        {"campaign_id": campaign['id'], "creator_id": creator['id']},
        {"_id": 0},
        sort=[("created_at", -1)]
    )
    action_cards = await db.deal_action_cards.find({"campaign_id": campaign['id']}, {"_id": 0}).sort("created_at", 1).to_list(100)
    activity = await db.deal_activity.find({"campaign_id": campaign['id']}, {"_id": 0}).sort("timestamp", 1).to_list(200)
    return {
        "campaign": campaign,
        "creator": creator,
        "brand": brand,
        "my_bid": my_bid,
        "shipment": shipment,
        "receipt": receipt,
        "work": work,
        "escrow": escrow,
        "content_versions": content_versions,
        "revision_response": revision_response,
        "action_cards": action_cards,
        "activity": activity
    }

async def build_deal_response(context: dict, viewer: dict) -> dict:
    campaign = context['campaign']
    creator = context['creator']
    brand = context['brand']
    normalized_shipment = normalize_shipment(campaign, context['shipment'])
    normalized_receipt = normalize_receipt(context['shipment'], context['receipt'])
    state = compute_deal_state(campaign, context['shipment'], normalized_receipt, context['work'], context['escrow'], context['action_cards'])
    escrow = normalize_escrow(context['escrow'], context['my_bid'], state['current_state'])
    content_submission = normalize_content_submission(campaign, context['content_versions'], context['work'])
    # Watermark gating: a brand viewer only sees raw originals once the work is
    # approved; before that, versions are stripped to watermark-protected
    # previews (PRD Section 8). Creators and admins always see their own assets.
    work_approved = (context['work'] or {}).get('status') == WorkStatus.APPROVED or campaign.get('status') == CampaignStatus.COMPLETED
    if viewer.get('id') == brand.get('id') and viewer.get('role') == UserRole.BUSINESS:
        content_submission["versions"] = [
            cf.to_brand_facing_asset(version, approved=work_approved)
            for version in content_submission["versions"]
        ]
    revision_tracker = normalize_revision_tracker(context['work'], context['revision_response'])

    legacy_messages = await db.messages.find({
        "$or": [
            {"sender_id": creator['id'], "recipient_id": brand['id']},
            {"sender_id": brand['id'], "recipient_id": creator['id']},
            {"sender_id": "system", "recipient_id": {"$in": [creator['id'], brand['id']]}}
        ]
    }, {"_id": 0}).sort("timestamp", 1).to_list(100)
    deal_messages = await db.deal_messages.find({"campaign_id": campaign['id']}, {"_id": 0}).sort("created_at", 1).to_list(100)
    messages = []
    for msg in legacy_messages:
        messages.append({
            "id": msg.get('id'),
            "sender_type": map_sender_type(msg.get('sender_id'), campaign, creator['id']),
            "sender_name": msg.get('sender_nickname') or msg.get('sender_name') or 'User',
            "message": msg.get('message'),
            "attachment_urls": msg.get('attachment_urls', []),
            "created_at": msg.get('timestamp')
        })
    for msg in deal_messages:
        messages.append({
            "id": msg.get('id'),
            "sender_type": msg.get('sender_type') or map_sender_type(msg.get('sender_id'), campaign, creator['id']),
            "sender_name": msg.get('sender_name') or msg.get('sender_nickname') or 'User',
            "message": msg.get('message'),
            "attachment_urls": msg.get('attachment_urls', []),
            "created_at": msg.get('created_at') or msg.get('timestamp')
        })
    messages.sort(key=lambda item: item.get('created_at') or '')
    unread_count = await db.messages.count_documents({"sender_id": brand['id'], "recipient_id": viewer['id'], "read": False})
    unread_count += await db.deal_messages.count_documents({
        "campaign_id": campaign['id'],
        "sender_id": {"$ne": viewer['id']},
        "read_by": {"$ne": viewer['id']}
    })

    activity_feed = context['activity'] or []
    if not activity_feed:
        activity_feed = []
        if context['shipment']:
            activity_feed.append({
                "id": f"{campaign['id']}-shipment",
                "timestamp": context['shipment'].get('updated_at') or campaign.get('work_started_at'),
                "actor_type": "brand",
                "actor_name": brand.get('nickname') or brand.get('email') or 'Brand',
                "event_type": "tracking_uploaded",
                "message": "Shipment tracking was uploaded."
            })
        if normalized_receipt.get('received_at'):
            activity_feed.append({
                "id": f"{campaign['id']}-receipt",
                "timestamp": normalized_receipt['received_at'],
                "actor_type": "creator",
                "actor_name": creator.get('nickname') or creator.get('email') or 'Creator',
                "event_type": "receipt_confirmed",
                "message": "Product receipt was confirmed."
            })
        if context['work']:
            activity_feed.append({
                "id": f"{campaign['id']}-work",
                "timestamp": context['work'].get('submitted_at'),
                "actor_type": "creator",
                "actor_name": creator.get('nickname') or creator.get('email') or 'Creator',
                "event_type": "content_submitted",
                "message": "Content was submitted for brand review."
            })
        if context['escrow'] and context['escrow'].get('released_at'):
            activity_feed.append({
                "id": f"{campaign['id']}-payment",
                "timestamp": context['escrow'].get('released_at'),
                "actor_type": "system",
                "actor_name": "System",
                "event_type": "payment_released",
                "message": "Payment was released."
            })

    campaign_details = {key: value for key, value in campaign.items() if key != 'bids'}
    can_mark_received = bool(campaign.get('requires_shipment')) and normalized_shipment.get('courier_status') in ['delivered', 'shipped', 'in_transit'] and not normalized_receipt.get('received_at')
    can_submit_content = viewer.get('role') == UserRole.CREATOR and creator['id'] == viewer['id'] and state['active_party'] == 'creator' and state['current_state'] in [
        "Received — Content in Progress",
        "Revision Requested"
    ]

    return {
        "deal_id": make_deal_id(campaign),
        "campaign": campaign_details,
        "brand": {
            "id": brand.get('id'),
            "name": brand.get('profile', {}).get('business_name') or brand.get('business_name') or brand.get('nickname') or brand.get('email'),
            "handle": brand.get('nickname') if str(brand.get('nickname', '')).startswith('@') else f"@{brand.get('nickname', brand.get('id', 'brand'))}",
            "logo_url": brand.get('profile', {}).get('logo') or brand.get('logo') or brand.get('profile_photo')
        },
        "creator": {
            "id": creator.get('id'),
            "name": creator.get('full_name') or creator.get('nickname') or creator.get('email'),
            "handle": creator.get('nickname') if str(creator.get('nickname', '')).startswith('@') else f"@{creator.get('nickname', creator.get('id', 'creator'))}",
            "profile_photo": creator.get('profile_photo') or creator.get('profile_picture')
        },
        **state,
        "deadline": state.get('next_deadline_at'),
        "escrow": escrow,
        "my_bid": context['my_bid'],
        "shipment": normalized_shipment,
        "receipt": normalized_receipt,
        "brief_sections": get_brief_sections(campaign),
        "activity_feed": activity_feed,
        "content_submission": content_submission,
        "revision_tracker": revision_tracker,
        "chat_summary": {
            "thread_id": make_deal_id(campaign),
            "messages": messages,
            "unread_count": unread_count
        },
        "action_cards": context['action_cards'],
        "unread_count": unread_count,
        "can_submit_content": can_submit_content,
        "can_mark_received": can_mark_received,
        "can_raise_dispute": viewer.get('role') in [UserRole.CREATOR, UserRole.BUSINESS],
        "can_report_damage": viewer.get('role') == UserRole.CREATOR and bool(campaign.get('requires_shipment')) and not normalized_receipt.get('items_damaged')
    }

# Auth Routes
@api_router.post("/auth/signup")
async def signup(data: SignupRequest):
    existing = await db.users.find_one({"email": data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    nickname = await generate_nickname()

    user_doc = {
        "id": user_id,
        "email": data.email,
        "password": hash_password(data.password),
        "role": data.role,
        "nickname": nickname,
        "profile_completed": False,
        "curated_brand_visible": False,
        "creator_directory_visible": False,
        "approval_status": ApprovalStatus.PENDING if data.role in [UserRole.CREATOR, UserRole.BUSINESS] else ApprovalStatus.APPROVED,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "balance": 0.0
    }

    # Creators get a permanent, unique public code + a default level used for
    # offer price-floor enforcement.
    if data.role == UserRole.CREATOR:
        user_doc["creator_code"] = await generate_creator_code()
        user_doc["level"] = cf.DEFAULT_CREATOR_LEVEL
        user_doc["handle_locked"] = False

    await db.users.insert_one(user_doc)
    token = create_token(user_id, data.email, data.role)

    return {
        "token": token,
        "user_id": user_id,
        "nickname": nickname,
        "creator_code": user_doc.get("creator_code"),
        "role": data.role,
    }

@api_router.post("/auth/login")
async def login(data: LoginRequest, totp_token: Optional[str] = None):
    user = await db.users.find_one({"email": data.email}, {"_id": 0})
    if not user or not verify_password(data.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if user is banned
    if user.get('banned', False):
        ban_reason = user.get('ban_reason', 'Account suspended')
        raise HTTPException(status_code=403, detail=f"Account banned: {ban_reason}")
    
    # Check if 2FA is enabled
    if user.get('two_factor_enabled'):
        if not totp_token:
            # Return a special response indicating 2FA is required
            return {
                "requires_2fa": True,
                "temp_token": create_token(user['id'], user['email'], user['role']),
                "message": "2FA verification required"
            }
        
        # Verify 2FA token
        secret = user.get('two_factor_secret')
        if not secret:
            raise HTTPException(status_code=500, detail="2FA misconfigured")
        
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_token, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid 2FA code")
    
    token = create_token(user['id'], user['email'], user['role'])
    return {
        "token": token,
        "user_id": user['id'],
        "nickname": user['nickname'],
        "username": user.get('username'),
        "creator_code": user.get('creator_code'),
        "level": user.get('level'),
        "role": user['role'],
        "profile_completed": user.get('profile_completed', False),
        "approval_status": user.get('approval_status', ApprovalStatus.PENDING),
        "profile_photo": user.get('profile_photo')
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {k: v for k, v in current_user.items() if k != 'password'}

def normalize_handle(value: Optional[str]) -> str:
    handle = (value or "").strip()
    if not handle:
        return ""
    return handle if handle.startswith("@") else f"@{handle}"

def compact_list(*values: Any) -> List[str]:
    items = []
    for value in values:
        if isinstance(value, list):
            items.extend(value)
        elif isinstance(value, str) and value:
            items.extend([part.strip() for part in value.split(",")])
    return [item for item in items if item]

def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in [None, "", []]:
            return value
    return None

def matches_text_filter(needle: Optional[str], *haystacks: Any) -> bool:
    if not needle:
        return True
    lowered = needle.lower().strip()
    for haystack in haystacks:
        values = haystack if isinstance(haystack, list) else [haystack]
        for value in values:
            if not isinstance(value, str) or not value:
                continue
            normalized = value.lower().strip()
            if lowered == normalized or lowered in normalized:
                return True
            for part in [item.strip().lower() for item in value.split(",") if item.strip()]:
                if lowered == part or lowered in part:
                    return True
    return False

def creator_is_directory_visible(creator: dict) -> bool:
    return (
        creator.get("role") == UserRole.CREATOR and
        creator.get("approval_status") == ApprovalStatus.APPROVED and
        creator.get("profile_completed") is True and
        (creator.get("curated_brand_visible") is True or creator.get("creator_directory_visible") is True)
    )

async def get_visible_directory_creator(creator_id: str) -> Optional[dict]:
    return await db.users.find_one({
        "id": creator_id,
        "role": UserRole.CREATOR,
        "approval_status": ApprovalStatus.APPROVED,
        "profile_completed": True,
        "$or": [
            {"curated_brand_visible": True},
            {"creator_directory_visible": True},
        ],
    }, {"_id": 0})

async def creator_deliverables_completed(creator: dict) -> int:
    stored = creator.get("deliverables_completed")
    if stored is not None:
        try:
            return int(stored)
        except (TypeError, ValueError):
            pass
    return await db.campaigns.count_documents({
        "selected_creator": creator.get("id"),
        "status": CampaignStatus.COMPLETED,
    })

def creator_directory_public_view(creator: dict, deliverables_completed: int) -> dict:
    profile = creator.get("profile") or {}
    portfolio = first_non_empty(creator.get("portfolio"), profile.get("portfolio")) or []
    portfolio_preview = portfolio[0] if isinstance(portfolio, list) and portfolio else portfolio
    # Brands only ever see the watermark-protected preview of a sample (PRD 2.7).
    if isinstance(portfolio_preview, dict):
        portfolio_preview = cf.to_brand_facing_asset(portfolio_preview, approved=False)
    primary_category = first_non_empty(
        creator.get("primary_category"),
        creator.get("category"),
        profile.get("primary_category"),
        profile.get("category"),
        (creator.get("tags") or [None])[0] if isinstance(creator.get("tags"), list) else None,
        (profile.get("tags") or [None])[0] if isinstance(profile.get("tags"), list) else None,
    )
    return {
        "id": creator.get("id"),
        "public_creator_id": creator.get("public_creator_id") or "",
        "profile_photo": first_non_empty(creator.get("profile_photo"), creator.get("profile_picture"), profile.get("profile_photo"), profile.get("profile_picture")),
        "primary_category": primary_category or "",
        "languages": compact_list(creator.get("languages"), profile.get("languages"), creator.get("content_languages"), profile.get("content_languages")),
        "city_tier": first_non_empty(creator.get("city_tier"), creator.get("location_region"), profile.get("city_tier"), profile.get("location_region")) or "",
        "deliverables_completed": deliverables_completed,
        "portfolio_preview": portfolio_preview or "",
        "content_style": first_non_empty(creator.get("content_style"), profile.get("content_style")) or "",
        "budget_range": first_non_empty(creator.get("budget_range"), profile.get("budget_range")) or "",
    }

def creator_matches_directory_filters(creator: dict, category: Optional[str], language: Optional[str], region: Optional[str], style: Optional[str], budget: Optional[str]) -> bool:
    profile = creator.get("profile") or {}
    return (
        matches_text_filter(category, creator.get("primary_category"), creator.get("category"), creator.get("tags"), profile.get("primary_category"), profile.get("category"), profile.get("tags")) and
        matches_text_filter(language, creator.get("languages"), profile.get("languages"), creator.get("content_languages"), profile.get("content_languages")) and
        matches_text_filter(region, creator.get("city_tier"), creator.get("location_region"), profile.get("city_tier"), profile.get("location_region")) and
        matches_text_filter(style, creator.get("content_style"), profile.get("content_style")) and
        matches_text_filter(budget, creator.get("budget_range"), profile.get("budget_range"))
    )

def brand_match_terms(brand: dict) -> List[str]:
    profile = brand.get("profile") or {}
    return compact_list(
        brand.get("industry_category"),
        brand.get("business_category"),
        brand.get("product_type"),
        profile.get("industry_category"),
        profile.get("business_category"),
        profile.get("product_type"),
    )

def creator_best_match_score(creator: dict, brand: dict) -> int:
    terms = [term.lower() for term in brand_match_terms(brand)]
    if not terms:
        return 0
    profile = creator.get("profile") or {}
    creator_terms = [term.lower() for term in compact_list(
        creator.get("primary_category"),
        creator.get("category"),
        creator.get("tags"),
        profile.get("primary_category"),
        profile.get("category"),
        profile.get("tags"),
    )]
    return 1 if any(term in creator_terms for term in terms) else 0

async def ensure_public_creator_id(creator: dict) -> str:
    """Lazily backfill public_creator_id for approved creators that were approved
    before the public_creator_id system was introduced. Returns the id."""
    existing = creator.get("public_creator_id")
    if existing:
        return existing
    charset = string.ascii_letters + string.digits  # a-z + A-Z + 0-9
    for _ in range(10):
        candidate = "UGC-" + ''.join(random.choices(charset, k=8))
        collision = await db.users.find_one({"public_creator_id": candidate}, {"_id": 1})
        if not collision:
            await db.users.update_one(
                {"id": creator.get("id")},
                {"$set": {"public_creator_id": candidate}}
            )
            creator["public_creator_id"] = candidate
            return candidate
    return ""

@api_router.get("/business/creator-directory")
async def get_creator_directory(
    category: Optional[str] = None,
    language: Optional[str] = None,
    region: Optional[str] = None,
    style: Optional[str] = None,
    budget: Optional[str] = None,
    sort: Optional[str] = "best_match",
    current_user: dict = Depends(get_approved_business_user),
):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    if current_user.get("approval_status") != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Business profile must be approved")
    if sort not in ["recent", "active", "best_match", None]:
        raise HTTPException(status_code=400, detail="Invalid sort option")

    creators = await db.users.find({
        "role": UserRole.CREATOR,
        "approval_status": ApprovalStatus.APPROVED,
        "profile_completed": True,
        "$or": [
            {"curated_brand_visible": True},
            {"creator_directory_visible": True},
        ],
    }, {"_id": 0}).to_list(10000)

    rows = []
    for creator in creators:
        if not creator_matches_directory_filters(creator, category, language, region, style, budget):
            continue
        await ensure_public_creator_id(creator)
        deliverables = await creator_deliverables_completed(creator)
        rows.append({
            "creator": creator,
            "public": creator_directory_public_view(creator, deliverables),
            "deliverables": deliverables,
            "activity": first_non_empty(creator.get("recent_activity_score"), creator.get("activity_score"), (creator.get("profile") or {}).get("recent_activity_score")),
            "best_match": creator_best_match_score(creator, current_user),
        })

    if sort == "recent":
        rows.sort(key=lambda row: row["creator"].get("created_at") or "", reverse=True)
    elif sort == "active":
        rows.sort(key=lambda row: (to_float(row.get("activity")) or row["deliverables"], row["deliverables"]), reverse=True)
    else:
        rows.sort(key=lambda row: (row["best_match"], row["deliverables"]), reverse=True)

    return {"creators": [row["public"] for row in rows]}

@api_router.post("/business/creator-directory/{creator_id}/invite")
async def invite_creator_from_directory(
    creator_id: str,
    data: CreatorDirectoryInviteCreate,
    current_user: dict = Depends(get_approved_business_user),
):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    if current_user.get("approval_status") != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Business profile must be approved")
    creator = await get_visible_directory_creator(creator_id)
    if not creator:
        raise HTTPException(status_code=404, detail="Creator is not available in the brand directory")

    if data.campaign_id:
        campaign = await db.campaigns.find_one({"id": data.campaign_id, "business_id": current_user["id"]}, {"_id": 0})
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

    duplicate_query = {
        "business_id": current_user["id"],
        "creator_id": creator_id,
        "status": {"$in": ["open", "pending", "sent"]},
    }
    if data.campaign_id:
        duplicate_query["campaign_id"] = data.campaign_id
    else:
        duplicate_query["campaign_name"] = data.campaign_name
    if await db.private_invitations.find_one(duplicate_query, {"_id": 0}):
        raise HTTPException(status_code=409, detail="An open invitation already exists for this creator and campaign")

    created_at = now_iso()
    invitation = {
        "id": str(uuid.uuid4()),
        "business_id": current_user["id"],
        "business_nickname": current_user.get("nickname"),
        "creator_id": creator_id,
        "creator_nickname": creator.get("nickname"),
        "campaign_id": data.campaign_id,
        "campaign_name": data.campaign_name,
        "deliverable_summary": data.deliverable_summary,
        "budget": data.budget,
        "timeline": data.timeline,
        "usage_rights": data.usage_rights,
        "message": data.message or "",
        "status": "open",
        "source": "creator_directory",
        "created_at": created_at,
        "updated_at": created_at,
    }
    await db.private_invitations.insert_one(invitation)

    action_card = {
        "id": str(uuid.uuid4()),
        "thread_key": thread_key_for(current_user["id"], creator_id),
        "participants": sorted([current_user["id"], creator_id]),
        "sender_id": current_user["id"],
        "sender_nickname": current_user.get("nickname"),
        "recipient_id": creator_id,
        "deal_id": data.campaign_id,
        "type": "private_invitation",
        "fields": {
            "invitation_id": invitation["id"],
            "campaign_id": data.campaign_id,
            "campaign_name": data.campaign_name,
            "deliverable_summary": data.deliverable_summary,
            "budget": data.budget,
            "timeline": data.timeline,
            "usage_rights": data.usage_rights,
            "message": data.message or "",
            "response_deadline": (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat(),
        },
        "status": "open",
        "created_at": created_at,
        "available_actions": get_action_card_available_actions("private_invitation"),
        "read_by": [current_user["id"]],
        "immutable": True,
    }
    await db.chat_action_cards.insert_one(action_card)

    await notify_if_repeated_declines(current_user["id"], creator_id)
    await record_match_event("invitation_sent", current_user["id"], creator_id, card_id=action_card["id"], campaign_id=data.campaign_id, extra={"source": "directory"})

    return {
        "message": "Invitation sent",
        "invitation": {key: value for key, value in invitation.items() if key != "_id"},
        "action_card": {key: value for key, value in action_card.items() if key != "_id"},
    }

@api_router.get("/business/wallet")
async def get_business_wallet(current_user: dict = Depends(get_approved_business_user)):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    if current_user.get("approval_status") != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Business profile must be approved")

    balance = to_float(current_user.get("balance"))
    settings = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    plan_name = (
        ((settings or {}).get("billing") or {}).get("plan_name") or
        current_user.get("plan_name") or
        "Brand Starter"
    )

    ledger_rows = await db.wallet_ledger.find({"user_id": current_user["id"]}, {"_id": 0}).to_list(1000)
    ledger_transaction_ids = {row.get("transaction_id") for row in ledger_rows if row.get("transaction_id")}
    transactions = [normalize_wallet_transaction(row) for row in ledger_rows]

    payment_rows = await db.payment_transactions.find({"user_id": current_user["id"]}, {"_id": 0}).to_list(1000)
    for row in payment_rows:
        if row.get("id") in ledger_transaction_ids:
            continue
        tx_type = "Wallet Recharge" if row.get("purpose") == "wallet_recharge" else row.get("purpose") or "Payment"
        transactions.append(normalize_wallet_transaction(row, tx_type, "credit"))

    brand_campaigns = await db.campaigns.find({"business_id": current_user["id"]}, {"_id": 0, "id": 1}).to_list(10000)
    campaign_ids = [campaign.get("id") for campaign in brand_campaigns if campaign.get("id")]
    if campaign_ids:
        escrow_rows = await db.escrow.find({"campaign_id": {"$in": campaign_ids}}, {"_id": 0}).to_list(10000)
        for row in escrow_rows:
            transactions.append(normalize_wallet_transaction({**row, "type": "Escrow Lock"}, "Escrow Lock", "debit"))

    transactions.sort(key=lambda item: item.get("date") or "", reverse=True)

    return {
        "available_balance": balance,
        "minimum_chat_balance": MIN_BRAND_CHAT_BALANCE,
        "chat_unlocked": balance >= MIN_BRAND_CHAT_BALANCE,
        "plan_name": plan_name,
        "recharge_bonus": wallet_bonus_progress(balance),
        "bonus_tiers": WALLET_BONUS_TIERS,
        "transactions": transactions,
    }

@api_router.post("/business/wallet/recharge")
async def recharge_business_wallet(
    data: BusinessWalletRechargeCreate,
    current_user: dict = Depends(get_approved_business_user),
):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    if current_user.get("approval_status") != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Business profile must be approved")
    if data.amount < WALLET_MIN_RECHARGE:
        raise HTTPException(status_code=400, detail="Minimum wallet recharge amount is INR 2,500")

    gateway = await get_active_gateway(data.gateway)
    if gateway["gateway_name"] not in ["razorpay", "cashfree"]:
        raise HTTPException(status_code=400, detail="Unsupported gateway")

    currency = "INR"
    bonus_amount = wallet_bonus_amount(data.amount)
    credited_amount = data.amount + bonus_amount
    created_at = now_iso()

    if gateway["gateway_name"] == "razorpay":
        try:
            client = razorpay.Client(auth=(gateway["key_id"], gateway["key_secret"]))
            gateway_order = client.order.create(data={
                "amount": int(data.amount * 100),
                "currency": currency,
                "notes": {"purpose": "wallet_recharge", "user_id": current_user["id"]},
            })
        except Exception as razorpay_error:
            if "Authentication failed" in str(razorpay_error) or "test" in gateway["key_id"].lower():
                gateway_order = {
                    "id": f"order_wallet_test_{str(uuid.uuid4())[:8]}",
                    "amount": int(data.amount * 100),
                    "currency": currency,
                    "status": "created",
                }
            else:
                raise razorpay_error
        order_id = gateway_order["id"]
    else:
        order_id = f"cf_wallet_{str(uuid.uuid4())[:8]}"

    transaction_doc = {
        "id": str(uuid.uuid4()),
        "gateway": gateway["gateway_name"],
        "gateway_order_id": order_id,
        "amount": data.amount,
        "bonus_amount": bonus_amount,
        "credited_amount": credited_amount,
        "currency": currency,
        "purpose": "wallet_recharge",
        "status": "created",
        "user_id": current_user["id"],
        "customer_id": current_user["id"],
        "customer_email": current_user.get("email"),
        "customer_phone": current_user.get("phone") or "",
        "customer_name": current_user.get("nickname") or "",
        "created_at": created_at,
        "wallet_credited": False,
    }
    await db.payment_transactions.insert_one(transaction_doc)

    response = {
        "success": True,
        "gateway": gateway["gateway_name"],
        "order_id": order_id,
        "amount": data.amount,
        "bonus_amount": bonus_amount,
        "credited_amount": credited_amount,
        "currency": currency,
    }
    if gateway["gateway_name"] == "razorpay":
        response["key_id"] = gateway["key_id"]
    return response

@api_router.get("/business/dashboard")
async def get_business_dashboard(current_user: dict = Depends(get_current_user)):
    if current_user.get('role') != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this dashboard")

    business_id = current_user['id']
    campaigns = await db.campaigns.find({"business_id": business_id}, {"_id": 0}).to_list(10000)
    campaign_ids = [campaign.get("id") for campaign in campaigns if campaign.get("id")]

    escrows = await db.escrow.find({"campaign_id": {"$in": campaign_ids}}, {"_id": 0}).to_list(10000) if campaign_ids else []
    work_submissions = await db.work_submissions.find({"campaign_id": {"$in": campaign_ids}}, {"_id": 0}).to_list(10000) if campaign_ids else []
    shipments = await db.shipments.find({"campaign_id": {"$in": campaign_ids}}, {"_id": 0}).to_list(10000) if campaign_ids else []
    reviews = await db.reviews.find({"campaign_id": {"$in": campaign_ids}}, {"_id": 0}).to_list(10000) if campaign_ids else []

    escrow_by_campaign = {escrow.get("campaign_id"): escrow for escrow in escrows}
    shipment_by_campaign = {shipment.get("campaign_id"): shipment for shipment in shipments}
    work_by_campaign = {}
    for work in sorted(work_submissions, key=lambda item: item.get("submitted_at") or item.get("created_at") or "", reverse=True):
        work_by_campaign.setdefault(work.get("campaign_id"), work)

    now = datetime.now(timezone.utc)
    current_month_start = month_start(now)
    next_month_start = add_months(current_month_start, 1)
    previous_month_start = add_months(current_month_start, -1)
    week_start = now - timedelta(days=7)
    previous_week_start = now - timedelta(days=14)

    active_statuses = {CampaignStatus.ACTIVE, CampaignStatus.IN_PROGRESS, "work_submitted"}
    active_campaigns = [campaign for campaign in campaigns if campaign.get("status") in active_statuses]
    selected_active_campaigns = [campaign for campaign in active_campaigns if campaign.get("selected_creator")]

    active_this_week = [
        campaign for campaign in active_campaigns
        if is_between_iso(campaign.get("updated_at") or campaign.get("created_at"), week_start, now + timedelta(seconds=1))
    ]
    active_previous_week = [
        campaign for campaign in active_campaigns
        if is_between_iso(campaign.get("updated_at") or campaign.get("created_at"), previous_week_start, week_start)
    ]

    selected_active_ids = {campaign.get("id") for campaign in selected_active_campaigns}
    held_escrows = [
        escrow for escrow in escrows
        if escrow.get("campaign_id") in selected_active_ids and escrow.get("status") in ["held", "on_hold", "disputed"]
    ]
    in_escrow = sum(to_float(escrow.get("amount") or escrow.get("held_amount")) for escrow in held_escrows)

    approved_work = [work for work in work_submissions if work.get("status") == WorkStatus.APPROVED]
    reviewed_work = [work for work in work_submissions if work.get("status") in [WorkStatus.APPROVED, WorkStatus.REVISION_REQUESTED]]
    delivered_this_month = len([
        work for work in approved_work
        if is_between_iso(work.get("approved_at") or work.get("updated_at"), current_month_start, next_month_start)
    ])
    delivered_previous_month = len([
        work for work in approved_work
        if is_between_iso(work.get("approved_at") or work.get("updated_at"), previous_month_start, current_month_start)
    ])
    approval_rate = round((len(approved_work) / len(reviewed_work)) * 100, 2) if reviewed_work else 0
    avg_rating = round(sum(to_float(review.get("rating")) for review in reviews) / len(reviews), 2) if reviews else 0

    campaign_performance = []
    for offset in range(5, -1, -1):
        start = add_months(current_month_start, -offset)
        end = add_months(start, 1)
        applications_received = sum(
            1
            for campaign in campaigns
            for bid in campaign.get("bids", [])
            if is_between_iso(bid.get("submitted_at"), start, end)
        )
        deals_closed = len([
            campaign for campaign in campaigns
            if campaign.get("status") == CampaignStatus.COMPLETED
            and is_between_iso(campaign.get("completed_at") or campaign.get("updated_at"), start, end)
        ])
        approved_deliveries = len([
            work for work in approved_work
            if is_between_iso(work.get("approved_at") or work.get("updated_at"), start, end)
        ])
        month_spend = sum(
            to_float(escrow.get("amount") or escrow.get("held_amount"))
            for escrow in escrows
            if is_between_iso(escrow.get("released_at") or escrow.get("updated_at") or escrow.get("created_at"), start, end)
        )
        campaign_performance.append({
            "month": start.strftime("%b"),
            "deals_closed": deals_closed,
            "approved_deliveries": approved_deliveries,
            "applications_received": applications_received,
            "spend_k": round(month_spend / 1000, 2)
        })

    viewed_brief = await db.campaign_views.count_documents({"campaign_id": {"$in": campaign_ids}}) if campaign_ids else 0
    applications_total = sum(len(campaign.get("bids", [])) for campaign in campaigns)
    accepted_total = len([campaign for campaign in campaigns if campaign.get("selected_creator")])
    live_total = len(selected_active_campaigns)

    top_campaigns = []
    for campaign in campaigns:
        escrow = escrow_by_campaign.get(campaign.get("id"), {})
        spend = to_float(escrow.get("amount") or escrow.get("held_amount")) or selected_bid_amount(campaign)
        top_campaigns.append({
            "id": campaign.get("id"),
            "title": campaign.get("title", "Untitled Campaign"),
            "applications": len(campaign.get("bids", [])),
            "spend": spend,
            "status": campaign.get("status")
        })
    top_campaigns.sort(key=lambda item: (item["applications"], item["spend"]), reverse=True)

    creator_ids = [campaign.get("selected_creator") for campaign in selected_active_campaigns if campaign.get("selected_creator")]
    creators = await db.users.find({"id": {"$in": creator_ids}}, {"_id": 0, "id": 1, "nickname": 1}).to_list(10000) if creator_ids else []
    creator_by_id = {creator.get("id"): creator for creator in creators}

    active_deals = []
    for campaign in selected_active_campaigns:
        campaign_id = campaign.get("id")
        escrow = escrow_by_campaign.get(campaign_id, {})
        work = work_by_campaign.get(campaign_id)
        shipment = shipment_by_campaign.get(campaign_id)
        creator = creator_by_id.get(campaign.get("selected_creator"), {})
        stage = dashboard_stage(campaign, work, shipment)
        active_deals.append({
            "campaign_id": campaign_id,
            "campaign_title": campaign.get("title", "Untitled Campaign"),
            "creator_id": campaign.get("selected_creator"),
            "creator_nickname": creator.get("nickname"),
            **stage,
            "due_date": campaign.get("deadline") or campaign.get("due_date"),
            "escrow_amount": to_float(escrow.get("amount") or escrow.get("held_amount")) or selected_bid_amount(campaign)
        })

    pending_review_work = [work for work in work_submissions if work.get("status") == WorkStatus.SUBMITTED]
    shipment_needed = [
        campaign for campaign in selected_active_campaigns
        if campaign.get("requires_shipment") and campaign.get("id") not in shipment_by_campaign
    ]
    shipment_confirmations = [
        shipment for shipment in shipments
        if shipment.get("campaign_id") in selected_active_ids
        and (shipment.get("status") or shipment.get("courier_status")) == "delivered"
        and not shipment.get("received_at")
    ]
    unread_creator_messages = await db.messages.count_documents({
        "recipient_id": business_id,
        "sender_id": {"$in": creator_ids},
        "read": False
    }) if creator_ids else 0
    unread_creator_messages += await db.deal_messages.count_documents({
        "campaign_id": {"$in": campaign_ids},
        "sender_id": {"$ne": business_id},
        "read_by": {"$ne": business_id}
    }) if campaign_ids else 0

    pending_actions = [
        {
            "type": "review_submitted_reel",
            "label": "Review Submitted Reel",
            "count": len(pending_review_work),
            "target_url": f"/work-review/{pending_review_work[0]['id']}" if pending_review_work else None
        },
        {
            "type": "upload_shipment",
            "label": "Upload Shipment",
            "count": len(shipment_needed),
            "target_url": f"/campaigns/{shipment_needed[0]['id']}" if shipment_needed else None
        },
        {
            "type": "delivery_confirmation",
            "label": "Delivery Confirmation",
            "count": len(shipment_confirmations),
            "target_url": f"/shipment/{shipment_confirmations[0]['campaign_id']}" if shipment_confirmations else None
        },
        {
            "type": "unread_creator_messages",
            "label": "Unread Creator Messages",
            "count": unread_creator_messages,
            "target_url": "/messages" if unread_creator_messages else None
        }
    ]

    total_used = 0.0
    total_budget = 0.0
    spend_by_category = {}
    for campaign in campaigns:
        category = campaign_category(campaign)
        escrow = escrow_by_campaign.get(campaign.get("id"), {})
        used = to_float(escrow.get("amount") or escrow.get("held_amount")) or selected_bid_amount(campaign)
        total_used += used
        total_budget += campaign_budget_total(campaign)
        spend_by_category[category] = spend_by_category.get(category, 0.0) + used
    budget_categories = [
        {
            "label": category,
            "used": used,
            "percent": round((used / total_used) * 100, 2) if total_used else 0
        }
        for category, used in sorted(spend_by_category.items(), key=lambda item: item[1], reverse=True)
    ]

    return {
        "metrics": {
            "active_deals": len(active_campaigns),
            "active_deals_change_this_week": len(active_this_week) - len(active_previous_week),
            "in_escrow": in_escrow,
            "delivered_this_month": delivered_this_month,
            "delivered_monthly_change_percent": percent_change(delivered_this_month, delivered_previous_month),
            "wallet_balance": to_float(current_user.get("balance")),
            "approval_rate": approval_rate,
            "avg_rating": avg_rating
        },
        "campaign_performance": campaign_performance,
        "creator_funnel": {
            "viewed_brief": viewed_brief,
            "applied": applications_total,
            "accepted": accepted_total,
            "live": live_total
        },
        "top_campaigns": top_campaigns[:5],
        "active_deals": active_deals,
        "pending_actions": pending_actions,
        "budget_usage": {
            "used": total_used,
            "total": total_budget,
            "categories": budget_categories
        }
    }

# Business Settings Routes
@api_router.get("/business/settings/profile")
async def get_business_settings_profile(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    return business_profile_defaults(current_user, (settings or {}).get("profile"))

@api_router.put("/business/settings/profile")
async def update_business_settings_profile(
    data: BusinessSettingsProfileUpdate,
    current_user: dict = Depends(get_current_business_user)
):
    profile_data = data.dict()
    require_non_empty(profile_data, ["brand_name", "contact_person", "work_email"])

    now = datetime.now(timezone.utc).isoformat()
    await db.business_settings.update_one(
        {"business_id": current_user["id"]},
        {
            "$set": {"business_id": current_user["id"], "profile": profile_data, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {
            "profile.business_name": profile_data["brand_name"],
            "profile.logo": profile_data.get("logo_url", ""),
            "profile.website": profile_data.get("website_url", ""),
            "contact_person": profile_data["contact_person"],
            "phone_number": profile_data.get("phone_number", ""),
            "updated_at": now
        }}
    )
    await db.campaigns.update_many(
        {"business_id": current_user["id"]},
        {"$set": {
            "brand_name": profile_data["brand_name"],
            "brand_logo_url": profile_data.get("logo_url", ""),
            "updated_at": now
        }}
    )
    return profile_data

@api_router.post("/business/settings/logo")
async def upload_business_settings_logo(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_business_user)
):
    allowed_types = ["image/jpeg", "image/png", "image/jpg", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Only image files are allowed for logos")

    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))) / "business_logos"
    upload_dir.mkdir(parents=True, exist_ok=True)
    file_ext = Path(file.filename or "").suffix or ".png"
    unique_filename = f"logo_{current_user['id']}_{uuid.uuid4().hex}{file_ext}"
    file_path = upload_dir / unique_filename
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    logo_url = f"/uploads/business_logos/{unique_filename}"
    now = datetime.now(timezone.utc).isoformat()
    existing = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    profile_data = business_profile_defaults(current_user, (existing or {}).get("profile"))
    profile_data["logo_url"] = logo_url
    await db.business_settings.update_one(
        {"business_id": current_user["id"]},
        {
            "$set": {"business_id": current_user["id"], "profile": profile_data, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"profile.logo": logo_url, "updated_at": now}})
    await db.campaigns.update_many({"business_id": current_user["id"]}, {"$set": {"brand_logo_url": logo_url, "updated_at": now}})
    return {"logo_url": logo_url}

@api_router.delete("/business/settings/logo")
async def delete_business_settings_logo(current_user: dict = Depends(get_current_business_user)):
    now = datetime.now(timezone.utc).isoformat()
    existing = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    profile_data = business_profile_defaults(current_user, (existing or {}).get("profile"))
    profile_data["logo_url"] = ""
    await db.business_settings.update_one(
        {"business_id": current_user["id"]},
        {
            "$set": {"business_id": current_user["id"], "profile": profile_data, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"profile.logo": "", "updated_at": now}})
    await db.campaigns.update_many({"business_id": current_user["id"]}, {"$set": {"brand_logo_url": "", "updated_at": now}})
    return {"logo_url": ""}

@api_router.get("/business/settings/company")
async def get_business_settings_company(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    return business_company_defaults(current_user, (settings or {}).get("company"))

@api_router.put("/business/settings/company")
async def update_business_settings_company(
    data: BusinessSettingsCompanyUpdate,
    current_user: dict = Depends(get_current_business_user)
):
    company_data = data.dict()
    require_non_empty(company_data, ["business_type", "business_category", "country", "billing_address", "city", "state"])
    validate_choice(company_data.get("kyb_status"), ["pending", "verified", "rejected"], "kyb_status")
    if not company_data.get("kyb_status"):
        company_data["kyb_status"] = business_company_defaults(current_user).get("kyb_status", "pending")

    now = datetime.now(timezone.utc).isoformat()
    await db.business_settings.update_one(
        {"business_id": current_user["id"]},
        {
            "$set": {"business_id": current_user["id"], "company": company_data, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {
            "profile.product_type": company_data["business_type"],
            "profile.industry_category": company_data["business_category"],
            "gst_number": company_data.get("gst_number", ""),
            "updated_at": now
        }}
    )
    return company_data

@api_router.get("/business/settings/team")
async def get_business_settings_team(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    team_settings = (settings or {}).get("team") or {}
    members = [{
        "id": current_user["id"],
        "name": current_user.get("nickname") or current_user.get("email", ""),
        "email": current_user.get("email", ""),
        "avatar_url": current_user.get("profile_photo") or current_user.get("avatar_url") or "",
        "role": "admin",
        "status": "active"
    }]
    invited_members = await db.business_team_members.find({"business_id": current_user["id"]}, {"_id": 0}).sort("created_at", 1).to_list(1000)
    for member in invited_members:
        members.append({
            "id": member.get("id"),
            "name": member.get("name") or member.get("email", ""),
            "email": member.get("email", ""),
            "avatar_url": member.get("avatar_url", ""),
            "role": member.get("role", "viewer"),
            "status": member.get("status", "invited")
        })
    return {
        "members": members,
        "seat_limit": team_settings.get("seat_limit", 5),
        "seats_used": len([member for member in members if member.get("status") in ["active", "invited"]])
    }

@api_router.post("/business/settings/team/invite")
async def invite_business_settings_team_member(
    data: BusinessTeamInvite,
    current_user: dict = Depends(get_current_business_user)
):
    validate_choice(data.role, ["admin", "editor", "viewer"], "role")
    existing = await db.business_team_members.find_one({"business_id": current_user["id"], "email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Team member already exists")

    now = datetime.now(timezone.utc).isoformat()
    member_doc = {
        "id": str(uuid.uuid4()),
        "business_id": current_user["id"],
        "name": data.name or str(data.email).split("@")[0],
        "email": data.email,
        "avatar_url": "",
        "role": data.role,
        "status": "invited",
        "created_at": now,
        "updated_at": now
    }
    await db.business_team_members.insert_one(member_doc)
    return {key: member_doc[key] for key in ["id", "name", "email", "avatar_url", "role", "status"]}

@api_router.patch("/business/settings/team/{member_id}")
async def update_business_settings_team_member(
    member_id: str,
    data: BusinessTeamMemberUpdate,
    current_user: dict = Depends(get_current_business_user)
):
    update_data = {key: value for key, value in data.dict().items() if value is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields provided")
    validate_choice(update_data.get("role"), ["admin", "editor", "viewer"], "role")
    validate_choice(update_data.get("status"), ["active", "invited", "disabled"], "status")
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = await db.business_team_members.update_one(
        {"id": member_id, "business_id": current_user["id"]},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Team member not found")
    member = await db.business_team_members.find_one({"id": member_id, "business_id": current_user["id"]}, {"_id": 0})
    return {
        "id": member.get("id"),
        "name": member.get("name") or member.get("email", ""),
        "email": member.get("email", ""),
        "avatar_url": member.get("avatar_url", ""),
        "role": member.get("role", "viewer"),
        "status": member.get("status", "invited")
    }

@api_router.delete("/business/settings/team/{member_id}")
async def delete_business_settings_team_member(member_id: str, current_user: dict = Depends(get_current_business_user)):
    result = await db.business_team_members.delete_one({"id": member_id, "business_id": current_user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Team member not found")
    return {"message": "Team member removed"}

@api_router.get("/business/settings/billing")
async def get_business_settings_billing(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    billing = (settings or {}).get("billing") or {}
    transactions = await db.payment_transactions.find({"user_id": current_user["id"]}, {"_id": 0}).sort("created_at", -1).limit(20).to_list(20)
    campaigns = await db.campaigns.find({"business_id": current_user["id"]}, {"_id": 0}).to_list(10000)
    current_month_start = month_start(datetime.now(timezone.utc))
    next_month_start = add_months(current_month_start, 1)
    monthly_budget_used = sum(
        campaign_budget_total(campaign)
        for campaign in campaigns
        if is_between_iso(campaign.get("created_at"), current_month_start, next_month_start)
    )
    return {
        "plan_name": billing.get("plan_name", "Pro"),
        "commission_rate": billing.get("commission_rate", 10),
        "next_billing_date": billing.get("next_billing_date"),
        "monthly_budget_used": monthly_budget_used,
        "monthly_budget_limit": billing.get("monthly_budget_limit", 0),
        "billing_history": billing.get("billing_history", transactions),
        "payment_methods": billing.get("payment_methods", [])
    }

@api_router.post("/business/settings/billing/upgrade")
async def upgrade_business_settings_billing(data: BusinessBillingUpgrade, current_user: dict = Depends(get_current_business_user)):
    require_non_empty(data.dict(), ["plan_name"])
    now = datetime.now(timezone.utc).isoformat()
    await db.business_settings.update_one(
        {"business_id": current_user["id"]},
        {
            "$set": {"business_id": current_user["id"], "billing.plan_name": data.plan_name, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    return {"plan_name": data.plan_name}

@api_router.post("/business/settings/payment-methods")
async def create_business_settings_payment_method(data: BusinessPaymentMethodCreate, current_user: dict = Depends(get_current_business_user)):
    payload = data.dict()
    require_non_empty(payload, ["type", "label"])
    now = datetime.now(timezone.utc).isoformat()
    method = {"id": str(uuid.uuid4()), **payload, "created_at": now}
    await db.business_settings.update_one(
        {"business_id": current_user["id"]},
        {
            "$set": {"business_id": current_user["id"], "updated_at": now},
            "$push": {"billing.payment_methods": method},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    return method

@api_router.get("/business/settings/notifications")
async def get_business_settings_notifications(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    return business_notification_defaults((settings or {}).get("notifications"))

@api_router.put("/business/settings/notifications")
async def update_business_settings_notifications(
    data: BusinessNotificationPreferences,
    current_user: dict = Depends(get_current_business_user)
):
    notification_data = data.dict()
    now = datetime.now(timezone.utc).isoformat()
    await db.business_settings.update_one(
        {"business_id": current_user["id"]},
        {
            "$set": {"business_id": current_user["id"], "notifications": notification_data, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    return notification_data

@api_router.get("/business/settings/security")
async def get_business_settings_security(current_user: dict = Depends(get_current_business_user)):
    return {
        "two_factor_enabled": current_user.get("two_factor_enabled", False),
        "password_last_changed_at": current_user.get("updated_at")
    }

@api_router.get("/business/settings/sessions")
async def get_business_settings_sessions(current_user: dict = Depends(get_current_business_user)):
    sessions = await db.user_sessions.find({"user_id": current_user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"sessions": sessions}

@api_router.delete("/business/settings/sessions/{session_id}")
async def delete_business_settings_session(session_id: str, current_user: dict = Depends(get_current_business_user)):
    result = await db.user_sessions.delete_one({"id": session_id, "user_id": current_user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"message": "Session removed"}

@api_router.get("/business/settings/summary")
async def get_business_settings_summary(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": current_user["id"]}, {"_id": 0})
    billing = (settings or {}).get("billing") or {}
    team_count = 1 + await db.business_team_members.count_documents({
        "business_id": current_user["id"],
        "status": {"$in": ["active", "invited"]}
    })
    return {
        "active_plan": billing.get("plan_name", "Pro"),
        "wallet_balance": current_user.get("balance", 0),
        "team_count": team_count
    }

# Profile Routes
@api_router.get("/profile/handle/check")
async def check_handle_availability(handle: str, current_user: dict = Depends(get_current_user)):
    """Validate a proposed creator handle and report availability + suggestions (PRD 2.5)."""
    ok, normalized, error = cf.validate_handle(handle)
    if not ok:
        return {"valid": False, "available": False, "reason": error, "suggestions": []}
    existing = await db.users.find_one(
        {"username": normalized, "id": {"$ne": current_user['id']}},
        {"_id": 1}
    )
    if existing:
        taken = set(
            doc["username"]
            for doc in await db.users.find(
                {"username": {"$regex": f"^{re.escape(normalized)}"}}, {"_id": 0, "username": 1}
            ).to_list(50)
            if doc.get("username")
        )
        return {
            "valid": True,
            "available": False,
            "reason": "Handle already taken",
            "suggestions": cf.handle_suggestions(normalized, taken),
        }
    return {"valid": True, "available": True, "reason": "", "display": f"@{normalized}", "suggestions": []}


@api_router.get("/creator/levels")
async def get_creator_levels():
    """Expose the creator level table and per-level offer price floors."""
    return {
        "levels": [
            {"key": key, **value} for key, value in cf.CREATOR_LEVELS.items()
        ],
        "default_level": cf.DEFAULT_CREATOR_LEVEL,
    }


@api_router.put("/profile/creator")
async def update_creator_profile(data: CreatorProfileUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can update creator profile")

    profile_data = data.dict()
    username = cf.normalize_handle(profile_data.pop("username", None))

    # Optional portfolio enforcement: if the submit carries samples, they must
    # satisfy the 3-5 + metadata rules (PRD 2.7).
    submitted_portfolio = profile_data.get("portfolio") or []
    if submitted_portfolio:
        ok, error = cf.validate_portfolio(submitted_portfolio)
        if not ok:
            raise HTTPException(status_code=400, detail=error)

    update_fields = {
        "profile": profile_data,
        "profile_completed": True,
        "approval_status": ApprovalStatus.PENDING,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }

    if username:
        current_handle = current_user.get("username")
        # Handle is permanent once set: changing it requires admin review.
        if current_user.get("handle_locked") and current_handle and username != current_handle:
            raise HTTPException(status_code=400, detail="Your handle is permanent and cannot be changed without admin review.")
        if username != current_handle:
            ok, normalized, error = cf.validate_handle(username)
            if not ok:
                raise HTTPException(status_code=400, detail=error)
            existing = await db.users.find_one(
                {"username": normalized, "id": {"$ne": current_user['id']}},
                {"_id": 1}
            )
            if existing:
                raise HTTPException(status_code=400, detail="Handle already taken")
            update_fields["username"] = normalized
            update_fields["handle_locked"] = True

    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": update_fields}
    )

    return {"message": "Profile submitted for review", "username": username or None}

@api_router.patch("/profile/portfolio")
async def update_portfolio(portfolio: List[Any], current_user: dict = Depends(get_current_user)):
    """Update only the portfolio field without affecting approval status.
    Accepts either legacy List[str] (URLs) or List[dict] (rich items with title/description/cost/duration).
    """
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can update portfolio")

    # PRD 2.7: a creator cannot save a portfolio with fewer than 3 or more than
    # 5 samples, and each rich sample must carry its metadata.
    ok, error = cf.validate_portfolio(portfolio)
    if not ok:
        raise HTTPException(status_code=400, detail=error)

    # Build watermark-protected previews so brands never receive raw assets.
    uploads_dir = str(Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))))
    enriched = []
    for item in portfolio:
        if isinstance(item, dict):
            asset_url = item.get("video_url") or item.get("url") or item.get("original_url")
            kind = "image" if str(item.get("deliverable_type") or "").lower() in ("static", "static post", "image", "carousel post") else "video"
            item = {**item, "original_url": asset_url, "watermark": cf.build_watermark_record(asset_url, kind, uploads_dir)}
        enriched.append(item)

    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {
            "portfolio": enriched,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )

    return {"message": "Portfolio updated successfully", "count": len(enriched)}

@api_router.put("/profile/business")
async def update_business_profile(data: BusinessProfileUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only businesses can update business profile")

    profile_data = data.dict()
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {
            "profile": profile_data,
            "profile_completed": True,
            "approval_status": ApprovalStatus.PENDING,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )

    # Cascade brand info updates to all existing campaigns for this business
    brand_name = profile_data.get('business_name') or current_user.get('nickname', '')
    brand_logo_url = profile_data.get('logo') or ''
    brand_cover_image_url = profile_data.get('banner') or ''
    await db.campaigns.update_many(
        {"business_id": current_user['id']},
        {"$set": {
            "brand_name": brand_name,
            "brand_logo_url": brand_logo_url,
            "brand_cover_image_url": brand_cover_image_url,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )

    return {"message": "Profile submitted for review"}

# Profile Management Routes
@api_router.post("/profile/upload-photo")
async def upload_profile_photo(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Upload profile photo"""
    # Create uploads directory if it doesn't exist
    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))) / "profiles"
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Validate file type
    allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Only image files are allowed for profile photos")
    
    # Generate unique filename
    file_ext = Path(file.filename).suffix
    unique_filename = f"profile_{current_user['id']}{file_ext}"
    file_path = upload_dir / unique_filename
    
    # Save file
    try:
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)
        
        # Update user profile with photo URL
        photo_url = f"/uploads/profiles/{unique_filename}"
        await db.users.update_one(
            {"id": current_user['id']},
            {"$set": {
                "profile_photo": photo_url,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        
        return {"photo_url": photo_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload photo: {str(e)}")

@api_router.put("/profile/update-info")
async def update_profile_info(
    bio: Optional[str] = None,
    description: Optional[str] = None,
    gender: Optional[str] = None,
    language: Optional[List[str]] = Query(default=None),
    country: Optional[str] = None,
    age_range: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Update basic profile information without affecting approval status.
    `language` accepts multiple values, e.g. ?language=English&language=Hindi
    """
    update_data = {"updated_at": datetime.now(timezone.utc).isoformat()}

    if bio is not None:
        update_data["bio"] = bio
    if description is not None:
        update_data["description"] = description
    if gender is not None:
        update_data["gender"] = gender
    if language is not None:
        # Filter out empty strings (form may send "" when nothing selected)
        update_data["language"] = [l for l in language if l and l.strip()]
    if country is not None:
        update_data["country"] = country
    if age_range is not None:
        update_data["age_range"] = age_range

    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": update_data}
    )

    return {"message": "Profile updated successfully"}

@api_router.post("/profile/change-password")
async def change_password(old_password: str, new_password: str, current_user: dict = Depends(get_current_user)):
    """Change user password"""
    # Get user from database
    user = await db.users.find_one({"id": current_user['id']})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify old password
    if not bcrypt.checkpw(old_password.encode('utf-8'), user['password'].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    
    # Hash new password
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    # Update password
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {
            "password": hashed.decode('utf-8'),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {"message": "Password changed successfully"}

@api_router.post("/profile/2fa/setup")
async def setup_2fa(current_user: dict = Depends(get_current_user)):
    """Generate 2FA secret and QR code"""
    # Generate secret
    secret = pyotp.random_base32()
    
    # Generate provisioning URI
    user_email = current_user.get('email', current_user.get('id'))
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_email,
        issuer_name="UGC Platform"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # Store secret temporarily (not enabled yet)
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {
            "two_factor_secret_temp": secret,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {
        "secret": secret,
        "qr_code": f"data:image/png;base64,{img_str}"
    }

@api_router.post("/profile/2fa/verify")
async def verify_2fa(token: str, current_user: dict = Depends(get_current_user)):
    """Verify and enable 2FA"""
    user = await db.users.find_one({"id": current_user['id']})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    temp_secret = user.get('two_factor_secret_temp')
    if not temp_secret:
        raise HTTPException(status_code=400, detail="2FA setup not initiated")
    
    # Verify token
    totp = pyotp.TOTP(temp_secret)
    if not totp.verify(token, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid verification code")
    
    # Enable 2FA
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {
            "two_factor_secret": temp_secret,
            "two_factor_enabled": True,
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        "$unset": {"two_factor_secret_temp": ""}}
    )
    
    return {"message": "2FA enabled successfully"}

@api_router.post("/profile/2fa/disable")
async def disable_2fa(password: str, current_user: dict = Depends(get_current_user)):
    """Disable 2FA"""
    user = await db.users.find_one({"id": current_user['id']})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Password is incorrect")
    
    # Disable 2FA
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {
            "two_factor_enabled": False,
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        "$unset": {"two_factor_secret": "", "two_factor_secret_temp": ""}}
    )
    
    return {"message": "2FA disabled successfully"}

@api_router.get("/profile/2fa/status")
async def get_2fa_status(current_user: dict = Depends(get_current_user)):
    """Get 2FA status"""
    user = await db.users.find_one({"id": current_user['id']}, {"two_factor_enabled": 1})
    return {"enabled": user.get('two_factor_enabled', False)}

@api_router.get("/profile/{user_id}")
async def get_profile(user_id: str, current_user: dict = Depends(get_current_user)):
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Hide sensitive info based on role
    if user['role'] == UserRole.CREATOR and current_user['role'] != UserRole.ADMIN:
        if 'profile' in user and 'social_links' in user['profile']:
            user['profile']['social_links'] = {}

    # Username is private — strip it (and email) from brand-facing responses,
    # unless the requester is the user themselves.
    if current_user.get('id') != user.get('id'):
        strip_private_fields(user, current_user.get('role'))

    return user

def enforce_brief_contact_policy(campaign_like: dict) -> None:
    """Moderate the brief's free-text 'things to avoid' field for contact info.
    Raises HTTPException if the text appears to contain emails/phones/handles/links."""
    avoid_text = (campaign_like or {}).get('avoid_text')
    if not avoid_text:
        return
    result = check_contact_info_policy(avoid_text)
    if not result.get('safe'):
        raise HTTPException(
            status_code=400,
            detail={
                "message": "The 'things to avoid' text appears to contain contact information, which cannot be shared in a brief.",
                "field": "avoid_text",
                "violations": result.get('violations', []),
            },
        )


async def flag_hidden_budget_if_needed(campaign_doc: dict) -> None:
    """When a published brief hides its budget from creators, raise an admin flag
    on the campaign and notify the admin/ops team."""
    if campaign_doc.get('budget_visible') is not False:
        return
    campaign_doc['budget_hidden'] = True
    flags = campaign_doc.get('admin_flags') or []
    if 'hidden_budget' not in flags:
        flags.append('hidden_budget')
    campaign_doc['admin_flags'] = flags
    await notify_admins(
        "Brief published with hidden budget",
        f"Campaign '{campaign_doc.get('title', '')}' was published with the budget hidden from creators.",
        link=f"/admin/campaigns/{campaign_doc.get('id', '')}",
    )


# Campaign Routes - Extended for 5-step flow
@api_router.post("/campaigns/draft")
async def create_draft(data: CampaignDraftCreate, current_user: dict = Depends(get_current_user)):
    """Create a draft campaign with partial data"""
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only businesses can create campaigns")
    
    if current_user.get('approval_status') != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Your profile must be approved first")
    
    campaign_id = str(uuid.uuid4())
    campaign_data = data.dict(exclude_unset=True)
    
    # Prepare campaign for storage with draft status
    campaign_doc = prepare_campaign_for_storage(campaign_data, status='draft')

    # Pull brand info from authenticated business user's profile
    user_profile = current_user.get('profile', {})
    brand_name = user_profile.get('business_name') or current_user.get('nickname', '')
    brand_logo_url = user_profile.get('logo') or ''
    brand_cover_image_url = user_profile.get('banner') or ''
    business_verified = current_user.get('approval_status') == ApprovalStatus.APPROVED

    # Add metadata
    campaign_doc.update({
        "id": campaign_id,
        "business_id": current_user['id'],
        "business_nickname": current_user.get('nickname', ''),
        "brand_name": brand_name,
        "brand_logo_url": brand_logo_url,
        "brand_cover_image_url": brand_cover_image_url,
        "business_verified": business_verified,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    
    await db.campaigns.insert_one(campaign_doc)
    
    # Calculate completion percentage
    completion = get_campaign_completion_percentage(campaign_doc)
    
    return {
        "campaign_id": campaign_id,
        "status": "draft",
        "completion_percentage": completion,
        "message": "Draft campaign created successfully"
    }

@api_router.patch("/campaigns/{campaign_id}")
async def update_campaign_route(campaign_id: str, data: CampaignUpdate, current_user: dict = Depends(get_current_user)):
    """Update an existing draft campaign"""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Check ownership
    if campaign.get('business_id') != current_user['id']:
        raise HTTPException(status_code=403, detail="You can only edit your own campaigns")
    
    # Check if campaign can be edited
    if not can_edit_campaign(campaign):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot edit campaign with status: {campaign.get('status')}"
        )
    
    # Prepare update data
    update_data = data.dict(exclude_unset=True)
    if update_data:
        # Apply backward compatibility mapping
        update_data = map_legacy_to_new_fields(update_data)
        update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
        
        await db.campaigns.update_one(
            {"id": campaign_id},
            {"$set": update_data}
        )
    
    # Get updated campaign
    updated_campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    completion = get_campaign_completion_percentage(updated_campaign)
    
    return {
        "campaign_id": campaign_id,
        "status": updated_campaign.get('status'),
        "completion_percentage": completion,
        "message": "Campaign updated successfully"
    }

@api_router.post("/campaigns/{campaign_id}/submit")
async def submit_campaign_route(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Submit a draft campaign for approval"""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Check ownership
    if campaign.get('business_id') != current_user['id']:
        raise HTTPException(status_code=403, detail="You can only submit your own campaigns")
    
    # Check if campaign is in draft or rejected status
    if campaign.get('status') not in ['draft', 'rejected']:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot submit campaign with status: {campaign.get('status')}"
        )
    
    # Validate all required fields
    validate_campaign_for_submission(campaign)

    # Moderate the free-text "things to avoid" field for contact info
    enforce_brief_contact_policy(campaign)

    update_fields = {
        "status": CampaignStatus.PENDING_APPROVAL,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }

    # Flag to admin if the budget is hidden from creators
    await flag_hidden_budget_if_needed(campaign)
    if campaign.get('budget_hidden'):
        update_fields['budget_hidden'] = True
        update_fields['admin_flags'] = campaign.get('admin_flags')

    # PRD 5.2 Path B: brand requested an ops-curated shortlist
    if campaign.get('match_requested'):
        update_fields['match_status'] = 'queued'
        await notify_admins(
            "New brief awaiting matches",
            f"'{campaign.get('title', '')}' was published with Request Matches and needs an ops shortlist.",
            link="/admin/match-queue",
        )

    # Update status to pending_approval
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": update_fields}
    )

    return {
        "campaign_id": campaign_id,
        "status": "pending_approval",
        "message": "Campaign submitted for approval"
    }

@api_router.post("/campaigns/{campaign_id}/upload-image")
async def upload_campaign_image(
    campaign_id: str,
    image_type: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Upload campaign images: logo, cover, or product_image. PNG/JPG/WEBP, max 10MB."""
    # Ownership check
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.get('business_id') != current_user['id']:
        raise HTTPException(status_code=403, detail="You can only upload to your own campaigns")

    # Validate image_type
    field_map = {
        "logo": "brand_logo_url",
        "cover": "brand_cover_image_url",
        "product_image": "product_image_url"
    }
    if image_type not in field_map:
        raise HTTPException(status_code=400, detail="image_type must be one of: logo, cover, product_image")

    # Validate file type
    allowed = {'image/jpeg', 'image/jpg', 'image/png', 'image/webp'}
    if file.content_type not in allowed:
        raise HTTPException(status_code=400, detail="Only PNG, JPG, WEBP images allowed")

    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image must be under 10MB")

    # Save file
    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))
    img_dir = upload_dir / "campaigns" / image_type
    img_dir.mkdir(parents=True, exist_ok=True)
    file_ext = Path(file.filename).suffix or '.jpg'
    filename = f"{uuid.uuid4()}{file_ext}"
    with open(img_dir / filename, 'wb') as f:
        f.write(content)

    file_url = f"/uploads/campaigns/{image_type}/{filename}"
    db_field = field_map[image_type]

    # Update campaign
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {db_field: file_url, "updated_at": now_iso()}}
    )

    # Return normalized full campaign
    updated = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    return normalize_campaign_response(updated)

@api_router.post("/campaigns")
async def create_campaign(data: CampaignCreateExtended, current_user: dict = Depends(get_current_user)):
    """Create campaign - supports both legacy and extended fields"""
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only businesses can create campaigns")
    
    if current_user.get('approval_status') != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Your profile must be approved first")
    
    campaign_id = str(uuid.uuid4())
    campaign_data = data.dict(exclude_unset=True)
    
    # Determine status: explicit drafts allow partial data. Publish requests must pass
    # validation and should never be silently converted to drafts.
    status = campaign_data.pop('status', None)
    if status == 'draft':
        final_status = CampaignStatus.DRAFT.value
    elif status == 'pending_approval':
        validate_campaign_for_submission(campaign_data)
        final_status = CampaignStatus.PENDING_APPROVAL.value
    else:
        final_status = CampaignStatus.PENDING_APPROVAL.value
        try:
            validate_campaign_for_submission(campaign_data)
        except HTTPException:
            if status is not None:
                raise
            final_status = CampaignStatus.DRAFT.value

    # Moderate the free-text "things to avoid" field for contact info on publish
    if final_status == CampaignStatus.PENDING_APPROVAL.value:
        enforce_brief_contact_policy(campaign_data)

    # Prepare campaign for storage
    campaign_doc = prepare_campaign_for_storage(campaign_data, status=final_status)

    # Pull brand info from authenticated business user's profile
    user_profile = current_user.get('profile', {})
    brand_name = user_profile.get('business_name') or current_user.get('nickname', '')
    brand_logo_url = user_profile.get('logo') or ''
    brand_cover_image_url = user_profile.get('banner') or ''
    business_verified = current_user.get('approval_status') == ApprovalStatus.APPROVED

    # Add metadata
    campaign_doc.update({
        "id": campaign_id,
        "business_id": current_user['id'],
        "business_nickname": current_user.get('nickname', ''),
        "brand_name": brand_name,
        "brand_logo_url": brand_logo_url,
        "brand_cover_image_url": brand_cover_image_url,
        "business_verified": business_verified,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

    if final_status == CampaignStatus.PENDING_APPROVAL.value:
        campaign_doc['submitted_at'] = datetime.now(timezone.utc).isoformat()
        # Flag to admin if the budget is hidden from creators
        await flag_hidden_budget_if_needed(campaign_doc)
        # PRD 5.2 Path B: brand requested an ops-curated shortlist
        if campaign_doc.get('match_requested'):
            campaign_doc['match_status'] = 'queued'
            await notify_admins(
                "New brief awaiting matches",
                f"'{campaign_doc.get('title', '')}' was published with Request Matches and needs an ops shortlist.",
                link=f"/admin/match-queue",
            )

    await db.campaigns.insert_one(campaign_doc)

    message = "Campaign submitted for approval" if final_status == CampaignStatus.PENDING_APPROVAL.value else "Draft campaign created"
    
    return {
        "campaign_id": campaign_id,
        "status": final_status,
        "message": message
    }

# ---------------------------------------------------------------------------
# PRD Section 5.2 Path B — Ops-mediated shortlist matching
# ---------------------------------------------------------------------------

OPS_ROLES = [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]
SHORTLIST_MIN = 3
SHORTLIST_MAX = 5


def shortlist_candidate_public(candidate: dict, creator: Optional[dict], deliverables: int = 0) -> dict:
    public = creator_directory_public_view(creator, deliverables) if creator else {}
    return {
        "creator_id": candidate.get("creator_id"),
        "ops_note": candidate.get("ops_note"),
        "status": candidate.get("status", "pending"),
        "creator": public,
    }


@api_router.get("/admin/match-queue")
async def get_match_queue(current_user: dict = Depends(get_current_user)):
    """Ops view: briefs that requested matches and await a shortlist."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view the match queue")
    campaigns = await db.campaigns.find(
        {"match_requested": True, "match_status": {"$in": ["queued", "shortlisted"]}},
        {"_id": 0},
    ).sort("submitted_at", 1).to_list(500)
    return [normalize_campaign_response(c) for c in campaigns]


@api_router.post("/admin/campaigns/{campaign_id}/shortlist")
async def create_campaign_shortlist(campaign_id: str, data: ShortlistCreate, current_user: dict = Depends(get_current_user)):
    """Ops submits a 3-5 creator shortlist (with a 'why we chose them' note each)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can create a shortlist")
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if not (SHORTLIST_MIN <= len(data.candidates) <= SHORTLIST_MAX):
        raise HTTPException(status_code=400, detail=f"A shortlist must have {SHORTLIST_MIN} to {SHORTLIST_MAX} creators.")

    seen = set()
    shortlist = []
    for cand in data.candidates:
        if cand.creator_id in seen:
            raise HTTPException(status_code=400, detail="Duplicate creator in shortlist.")
        seen.add(cand.creator_id)
        if not cand.ops_note or not cand.ops_note.strip():
            raise HTTPException(status_code=400, detail="Each candidate needs a 'why we chose them' note.")
        creator = await db.users.find_one({"id": cand.creator_id, "role": UserRole.CREATOR}, {"_id": 0, "id": 1})
        if not creator:
            raise HTTPException(status_code=400, detail=f"Creator {cand.creator_id} not found.")
        shortlist.append({
            "creator_id": cand.creator_id,
            "ops_note": cand.ops_note.strip(),
            "status": "pending",
            "added_by": current_user["id"],
            "added_at": now_iso(),
        })

    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {"shortlist": shortlist, "match_status": "shortlisted", "updated_at": now_iso()}},
    )
    await notify_user(
        campaign["business_id"],
        "Your creator matches are ready",
        f"Our team shortlisted {len(shortlist)} creators for '{campaign.get('title', '')}'.",
        link=f"/dashboard/business/campaigns/{campaign_id}/shortlist",
    )
    return {"campaign_id": campaign_id, "match_status": "shortlisted", "count": len(shortlist)}


@api_router.get("/campaigns/{campaign_id}/shortlist")
async def get_campaign_shortlist(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Brand (or ops) views the curated shortlist for a brief."""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if current_user["role"] not in OPS_ROLES and campaign.get("business_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="You can only view shortlists for your own briefs")

    candidates = []
    for cand in campaign.get("shortlist", []):
        creator = await db.users.find_one({"id": cand.get("creator_id")}, {"_id": 0})
        deliverables = await creator_deliverables_completed(creator) if creator else 0
        candidates.append(shortlist_candidate_public(cand, creator, deliverables))
    return {
        "campaign_id": campaign_id,
        "campaign_name": campaign.get("title", ""),
        "match_status": campaign.get("match_status"),
        "shortlist_request_count": campaign.get("shortlist_request_count", 0),
        "candidates": candidates,
    }


@api_router.post("/campaigns/{campaign_id}/shortlist/{creator_id}/invite")
async def invite_shortlist_candidate(campaign_id: str, creator_id: str, data: ShortlistInviteCreate, current_user: dict = Depends(get_current_user)):
    """Brand picks one shortlisted creator; a private invitation is sent and the
    other candidates are dismissed (PRD 5.4: one at a time in V0.5)."""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.get("business_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="You can only invite from your own brief")
    shortlist = campaign.get("shortlist", [])
    if not any(c.get("creator_id") == creator_id for c in shortlist):
        raise HTTPException(status_code=400, detail="That creator is not on this brief's shortlist.")

    created_at = now_iso()
    budget_text = data.budget or (f"₹{int(campaign.get('per_video_budget') or campaign.get('budget_max') or 0)}")
    action_card = {
        "id": str(uuid.uuid4()),
        "thread_key": thread_key_for(current_user["id"], creator_id),
        "participants": sorted([current_user["id"], creator_id]),
        "sender_id": current_user["id"],
        "sender_nickname": current_user.get("nickname"),
        "recipient_id": creator_id,
        "deal_id": campaign_id,
        "type": "private_invitation",
        "fields": {
            "campaign_id": campaign_id,
            "campaign_name": campaign.get("title", ""),
            "deliverable_summary": data.deliverable_summary or campaign.get("brief_text", "")[:140],
            "budget": budget_text,
            "timeline": data.timeline or campaign.get("final_delivery_by") or campaign.get("due_date") or "",
            "usage_rights": data.usage_rights or (", ".join(campaign.get("usage_platforms", [])) or "As per brief"),
            "full_brief_link": f"/dashboard/business/campaigns/{campaign_id}",
            "message": data.message or "",
            "source": "ops_shortlist",
            "response_deadline": (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat(),
        },
        "status": "open",
        "created_at": created_at,
        "available_actions": get_action_card_available_actions("private_invitation"),
        "read_by": [current_user["id"]],
        "immutable": True,
    }
    await db.chat_action_cards.insert_one(action_card)

    await notify_if_repeated_declines(current_user["id"], creator_id)
    await record_match_event("invitation_sent", current_user["id"], creator_id, card_id=action_card["id"], campaign_id=campaign_id, extra={"source": "ops_shortlist"})

    # Mark the chosen candidate invited, dismiss the rest.
    for cand in shortlist:
        cand["status"] = "invited" if cand.get("creator_id") == creator_id else "dismissed"
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {"shortlist": shortlist, "match_status": "fulfilled", "updated_at": created_at}},
    )
    await notify_user(creator_id, "You've received a brief invitation", f"{current_user.get('nickname', 'A brand')} invited you to '{campaign.get('title', '')}'.", link="/dashboard/creator/inbox")
    return {"message": "Invitation sent", "campaign_id": campaign_id, "creator_id": creator_id, "action_card": {k: v for k, v in action_card.items() if k != "_id"}}


@api_router.post("/campaigns/{campaign_id}/shortlist/request-new")
async def request_new_shortlist(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Brand isn't satisfied with the shortlist and requests a new one (PRD 5.4)."""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.get("business_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="You can only request matches for your own brief")
    count = (campaign.get("shortlist_request_count") or 0) + 1
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {"match_status": "queued", "shortlist": [], "shortlist_request_count": count, "updated_at": now_iso()}},
    )
    await notify_admins(
        "Brand requested a new shortlist",
        f"'{campaign.get('title', '')}' requested new matches (request #{count}).",
        link="/admin/match-queue",
    )
    return {"campaign_id": campaign_id, "match_status": "queued", "shortlist_request_count": count}


@api_router.get("/creator/capacity-status")
async def get_creator_capacity_status(current_user: dict = Depends(get_current_user)):
    """PRD 5.9: creators set a monthly capacity in onboarding. When they're at
    capacity, new invitations show a soft warning (not blocked)."""
    if current_user["role"] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators have a capacity status")
    profile = current_user.get("profile") or {}
    capacity = current_user.get("monthly_capacity") or profile.get("monthly_capacity")
    month_start_iso = month_start(datetime.now(timezone.utc)).isoformat()
    accepted_this_month = await db.campaigns.count_documents({
        "selected_creator": current_user["id"],
        "status": {"$in": [CampaignStatus.IN_PROGRESS, CampaignStatus.ACTIVE, "work_submitted", CampaignStatus.COMPLETED]},
        "work_started_at": {"$gte": month_start_iso},
    })
    at_capacity = bool(capacity) and accepted_this_month >= int(capacity)
    return {
        "monthly_capacity": capacity,
        "accepted_this_month": accepted_this_month,
        "at_capacity": at_capacity,
        "warning": "You're at your monthly capacity. You can still accept, but consider your workload." if at_capacity else None,
    }


@api_router.get("/admin/match-metrics")
async def get_match_metrics(current_user: dict = Depends(get_current_user)):
    """PRD 5.8: aggregate match-interaction metrics for ops (not shown publicly)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view match metrics")
    events = await db.match_events.find({}, {"_id": 0}).to_list(20000)

    def count_type(suffix):
        return sum(1 for e in events if (e.get("event_type") or "").endswith(suffix))

    invitations_sent = sum(1 for e in events if e.get("event_type") == "invitation_sent")
    accepts = count_type("_accept")
    rejects = count_type("_reject")
    expirations = count_type("_expired")
    responded = accepts + rejects
    acceptance_rate = round((accepts / responded) * 100, 1) if responded else 0

    decline_reasons = {}
    for e in events:
        if e.get("action") == "reject" and e.get("decline_reason"):
            decline_reasons[e["decline_reason"]] = decline_reasons.get(e["decline_reason"], 0) + 1

    response_times = [e["response_seconds"] for e in events if isinstance(e.get("response_seconds"), int)]
    avg_response_hours = round((sum(response_times) / len(response_times)) / 3600, 1) if response_times else 0

    counters_sent = sum(1 for e in events if e.get("event_type") == "counter_sent")
    counter_accepts = sum(1 for e in events if e.get("event_type") == "counter_offer_accept")
    counter_success_rate = round((counter_accepts / counters_sent) * 100, 1) if counters_sent else 0

    shortlisted = await db.campaigns.count_documents({"match_status": {"$in": ["shortlisted", "fulfilled"]}})
    queued = await db.campaigns.count_documents({"match_status": "queued"})

    return {
        "invitations_sent": invitations_sent,
        "accepts": accepts,
        "rejects": rejects,
        "expirations": expirations,
        "acceptance_rate_pct": acceptance_rate,
        "avg_response_hours": avg_response_hours,
        "decline_reasons": decline_reasons,
        "counters_sent": counters_sent,
        "counter_success_rate_pct": counter_success_rate,
        "shortlists_delivered": shortlisted,
        "briefs_in_queue": queued,
        "total_events": len(events),
    }


@api_router.get("/campaigns")
async def get_campaigns(
    status: Optional[str] = None,
    include_drafts: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """Get campaigns with extended fields support"""
    query = {}
    
    if current_user['role'] == UserRole.CREATOR:
        # Creators should see active campaigns and their own in_progress campaigns
        query = {
            "$or": [
                {"status": CampaignStatus.ACTIVE},
                {"status": CampaignStatus.IN_PROGRESS, "selected_creator": current_user['id']}
            ]
        }
    elif current_user['role'] == UserRole.BUSINESS:
        query['business_id'] = current_user['id']
        # Optionally filter by status
        if status:
            query['status'] = status
        elif not include_drafts:
            # By default, exclude drafts unless explicitly requested
            query['status'] = {"$ne": CampaignStatus.DRAFT}
    elif status:
        query['status'] = status
    
    campaigns = await db.campaigns.find(query, {"_id": 0}).to_list(1000)
    
    # Normalize all campaigns
    normalized_campaigns = []
    for campaign in campaigns:
        normalized = normalize_campaign_response(campaign)
        # Add completion percentage for drafts
        if normalized.get('status') == CampaignStatus.DRAFT:
            normalized['completion_percentage'] = get_campaign_completion_percentage(normalized)
        normalized_campaigns.append(normalized)
    
    return normalized_campaigns

@api_router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Get campaign with extended fields support"""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Normalize response to include both old and new fields
    campaign = normalize_campaign_response(campaign)
    
    # Add completion percentage if draft
    if campaign.get('status') == CampaignStatus.DRAFT:
        campaign['completion_percentage'] = get_campaign_completion_percentage(campaign)
    
    return campaign

@api_router.post("/campaigns/{campaign_id}/bid")
async def submit_bid(campaign_id: str, data: BidCreate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can bid")
    
    if current_user.get('approval_status') != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Your profile must be approved first")
    
    campaign = await db.campaigns.find_one({"id": campaign_id})
    if not campaign or campaign['status'] != CampaignStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Campaign not available for bidding")
    
    # Check if creator has already bid on this campaign
    existing_bids = campaign.get('bids', [])
    if any(bid['creator_id'] == current_user['id'] for bid in existing_bids):
        raise HTTPException(status_code=400, detail="You have already submitted a bid for this campaign")
    
    bid_doc = {
        "id": str(uuid.uuid4()),
        "creator_id": current_user['id'],
        "creator_nickname": current_user['nickname'],
        **data.dict(),
        "submitted_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$push": {"bids": bid_doc}}
    )
    
    return {"message": "Bid submitted successfully"}

@api_router.get("/bids/my")
async def get_my_bids(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can access their bids")

    campaigns = await db.campaigns.find(
        {"bids.creator_id": current_user['id']},
        {"_id": 0}
    ).to_list(1000)

    result = []
    for campaign in campaigns:
        my_bid = next(
            (bid for bid in campaign.get('bids', []) if bid.get('creator_id') == current_user['id']),
            None
        )
        if not my_bid:
            continue

        selected_creator = campaign.get('selected_creator')
        if selected_creator == current_user['id']:
            bid_status = "approved"
        elif selected_creator:
            bid_status = "rejected"
        else:
            bid_status = "pending"

        campaign_details = {key: value for key, value in campaign.items() if key != 'bids'}
        result.append({
            "campaign": campaign_details,
            "my_bid": my_bid,
            "bid_status": bid_status,
            "campaign_status": campaign.get('status'),
            "submitted_at": my_bid.get('submitted_at')
        })

    return result

@api_router.post("/campaigns/{campaign_id}/select-creator")
async def select_creator(campaign_id: str, creator_id: str, current_user: dict = Depends(get_current_user)):
    campaign = await db.campaigns.find_one({"id": campaign_id})
    if not campaign or campaign['business_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get creator details
    creator = await db.users.find_one({"id": creator_id}, {"_id": 0, "nickname": 1})
    if not creator:
        raise HTTPException(status_code=404, detail="Creator not found")
    
    # Create escrow transaction
    selected_bid = next((bid for bid in campaign.get('bids', []) if bid['creator_id'] == creator_id), None)
    if not selected_bid:
        raise HTTPException(status_code=404, detail="Bid not found")
    
    escrow_id = str(uuid.uuid4())
    escrow_doc = {
        "id": escrow_id,
        "campaign_id": campaign_id,
        "business_id": current_user['id'],
        "creator_id": creator_id,
        "amount": selected_bid['amount'],
        "status": "held",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.escrow.insert_one(escrow_doc)
    
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {
            "selected_creator": creator_id,
            "status": CampaignStatus.IN_PROGRESS,
            "escrow_id": escrow_id,
            "work_started_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    # Send automated system messages to both parties
    system_message_to_creator = f"""🎉 Congratulations! You've been selected for the campaign "{campaign['title']}"!

💰 Payment: ${selected_bid['amount']} has been held in escrow and will be released upon work approval.
📅 Delivery: {selected_bid['estimated_delivery_days']} days
📋 Campaign Brief: {campaign.get('brief_text', 'See campaign details')}

Let's discuss the next steps and get started! Feel free to ask any questions."""
    
    system_message_to_business = f"""✅ You've successfully selected {creator['nickname']} for "{campaign['title']}"!

💰 Payment: ${selected_bid['amount']} has been held in escrow
📅 Expected Delivery: {selected_bid['estimated_delivery_days']} days

You can now communicate directly with {creator['nickname']} to coordinate the work. Good luck with your campaign!"""
    
    # Send message to creator
    try:
        creator_message_doc = {
            "id": str(uuid.uuid4()),
            "sender_id": "system",
            "sender_nickname": "Platform",
            "recipient_id": creator_id,
            "message": system_message_to_creator,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "read": False,
            "system_message": True
        }
        await db.messages.insert_one(creator_message_doc)
        print(f"✅ Created system message to creator: {creator_message_doc['id']}")
    except Exception as e:
        print(f"❌ Error creating creator system message: {str(e)}")
    
    # Send message to business
    try:
        business_message_doc = {
            "id": str(uuid.uuid4()),
            "sender_id": "system",
            "sender_nickname": "Platform",
            "recipient_id": current_user['id'],
            "message": system_message_to_business,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "read": False,
            "system_message": True
        }
        await db.messages.insert_one(business_message_doc)
        print(f"✅ Created system message to business: {business_message_doc['id']}")
    except Exception as e:
        print(f"❌ Error creating business system message: {str(e)}")
    
    # Create initial conversation between business and creator
    try:
        conversation_starter = {
            "id": str(uuid.uuid4()),
            "sender_id": current_user['id'],
            "sender_nickname": current_user['nickname'],
            "recipient_id": creator_id,
            "message": f"Hi {creator['nickname']}! Looking forward to working with you on this campaign. Let me know if you have any questions!",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "read": False
        }
        await db.messages.insert_one(conversation_starter)
        print(f"✅ Created conversation starter: {conversation_starter['id']}")
    except Exception as e:
        print(f"❌ Error creating conversation starter: {str(e)}")
    
    # Create in-app notification for creator
    notification_doc = {
        "id": str(uuid.uuid4()),
        "user_id": creator_id,
        "title": "🎉 You've been selected for a campaign!",
        "message": f"Congratulations! You've been selected for '{campaign['title']}'. Payment of ${selected_bid['amount']} is now in escrow.",
        "type": "success",
        "link": "/creator-dashboard",
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": "system"
    }
    await db.in_app_notifications.insert_one(notification_doc)
    
    return {
        "message": "Creator selected and payment held in escrow",
        "creator_id": creator_id,
        "creator_nickname": creator['nickname'],
        "escrow_id": escrow_id,
        "amount": selected_bid['amount']
    }

# Chat Routes
@api_router.post("/chat/send")
async def send_message(data: ChatMessage, current_user: dict = Depends(get_current_user)):
    recipient = await validate_chat_access(current_user, data.recipient_id)
    if not data.message and not data.attachment_urls:
        raise HTTPException(status_code=400, detail="Message text or at least one attachment is required.")
    await validate_message_attachments(data.attachment_urls)

    safety_check = check_contact_info_policy(data.message, brand_allowed_domains(current_user, recipient))
    if not safety_check["safe"]:
        await log_chat_violation(current_user, data.recipient_id, data.message, safety_check["violations"], "message")
        raise HTTPException(status_code=400, detail=CONTACT_INFO_BLOCK_DETAIL)

    created_at = now_iso()
    message_doc = {
        "id": str(uuid.uuid4()),
        "sender_id": current_user['id'],
        "sender_nickname": current_user['nickname'],
        "recipient_id": data.recipient_id,
        "message": data.message,
        "attachment_urls": data.attachment_urls,
        "timestamp": created_at,
        "created_at": created_at,
        "read": False,
        "read_by": [current_user['id']],
        "delivered_at": created_at,
        "status": "delivered",
        "filtered": False
    }
    
    await db.messages.insert_one(message_doc)
    
    return {
        "message": "Message sent",
        "filtered": False,
        "chat_message": {key: value for key, value in message_doc.items() if key != "_id"}
    }

@api_router.get("/chat/conversations")
async def get_conversations(current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find({
        "$or": [
            {"sender_id": current_user['id']},
            {"recipient_id": current_user['id']}
        ]
    }, {"_id": 0}).to_list(10000)

    action_cards = await db.chat_action_cards.find({
        "$or": [
            {"sender_id": current_user['id']},
            {"recipient_id": current_user['id']}
        ]
    }, {"_id": 0}).to_list(10000)

    conversations = {}
    unread_per_partner = {}

    for item in [message_to_chat_item(msg) for msg in messages] + [action_card_to_chat_item(card) for card in action_cards]:
        if item.get('sender_id') == 'system':
            continue

        other_id = item['recipient_id'] if item['sender_id'] == current_user['id'] else item['sender_id']
        item_timestamp = item.get("created_at") or item.get("timestamp") or ""

        if item['sender_id'] == other_id and item['recipient_id'] == current_user['id'] and current_user['id'] not in item.get('read_by', []) and not item.get('read'):
            unread_per_partner[other_id] = unread_per_partner.get(other_id, 0) + 1

        if other_id not in conversations or item_timestamp > conversations[other_id]['timestamp']:
            other_user = await db.users.find_one({"id": other_id}, {"_id": 0, "nickname": 1, "role": 1, "profile_picture": 1})
            if other_user:  # Only add if user exists
                deal = await find_chat_deal(current_user['id'], other_id)
                deal_status = deal.get("status") if deal else None
                if deal_status in ACTIVE_DEAL_STATUSES:
                    thread_classification = "active_deal"
                elif deal_status in ARCHIVED_DEAL_STATUSES:
                    thread_classification = "archived"
                else:
                    thread_classification = "no_deal"
                snippet = item.get("message") or item.get("title") or item.get("type") or ""
                conversations[other_id] = {
                    "user_id": other_id,
                    "nickname": other_user.get('nickname', 'Unknown'),
                    "role": other_user.get('role', ''),
                    "profile_picture": other_user.get('profile_picture'),
                    "last_message": item,
                    "last_item_snippet": snippet[:120],
                    "timestamp": item_timestamp,
                    "unread_count": unread_per_partner.get(other_id, 0),
                    "associated_deal_status": deal_status,
                    "thread_classification": thread_classification
                }

    for other_id, count in unread_per_partner.items():
        if other_id in conversations:
            conversations[other_id]["unread_count"] = count
    return sorted(conversations.values(), key=lambda item: item.get("timestamp") or "", reverse=True)

@api_router.get("/chat/unread-count")
async def get_unread_count(current_user: dict = Depends(get_current_user)):
    count = await db.messages.count_documents({
        "recipient_id": current_user['id'],
        "read": False
    })
    count += await db.chat_action_cards.count_documents({
        "recipient_id": current_user['id'],
        "read_by": {"$ne": current_user['id']}
    })
    return {"unread_count": count}

@api_router.get("/chat/warnings")
async def get_user_warnings(current_user: dict = Depends(get_current_user)):
    """Get user's warning count and status"""
    user = await db.users.find_one({"id": current_user['id']}, {"warning_count": 1, "banned": 1, "last_warning_at": 1})
    return {
        "warning_count": user.get('warning_count', 0),
        "banned": user.get('banned', False),
        "last_warning_at": user.get('last_warning_at'),
        "action_cards_only_until": user.get("action_cards_only_until")
    }

@api_router.post("/chat/violations/{violation_id}/false-positive")
async def request_chat_false_positive(violation_id: str, data: ChatFalsePositiveRequest, current_user: dict = Depends(get_current_user)):
    violation = await db.violations.find_one({"id": violation_id}, {"_id": 0})
    if not violation:
        raise HTTPException(status_code=404, detail="Violation not found")
    if violation.get("user_id") != current_user["id"] and current_user["role"] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Not authorized for this violation")
    request_doc = {
        "id": str(uuid.uuid4()),
        "violation_id": violation_id,
        "user_id": violation.get("user_id"),
        "requested_by": current_user["id"],
        "reason": data.reason,
        "status": "pending",
        "created_at": now_iso(),
        "reviewed_at": None,
        "reviewed_by": None
    }
    await db.chat_false_positive_reviews.insert_one(request_doc)
    await db.violations.update_one({"id": violation_id}, {"$set": {"false_positive_status": "pending"}})
    return {"message": "False-positive review submitted", "review": request_doc}

@api_router.post("/admin/chat/violations/{violation_id}/false-positive-review")
async def review_chat_false_positive(violation_id: str, data: ChatFalsePositiveReview, current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Admin access required")
    if data.status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Review status must be approved or rejected")
    violation = await db.violations.find_one({"id": violation_id}, {"_id": 0})
    if not violation:
        raise HTTPException(status_code=404, detail="Violation not found")
    reviewed_at = now_iso()
    await db.chat_false_positive_reviews.update_many(
        {"violation_id": violation_id, "status": "pending"},
        {"$set": {"status": data.status, "note": data.note, "reviewed_at": reviewed_at, "reviewed_by": current_user["id"]}}
    )
    await db.violations.update_one(
        {"id": violation_id},
        {"$set": {"false_positive_status": data.status, "false_positive_reviewed_at": reviewed_at, "false_positive_reviewed_by": current_user["id"]}}
    )
    if data.status == "approved":
        await db.chat_strikes.update_many({"violation_id": violation_id}, {"$set": {"invalidated": True, "invalidated_at": reviewed_at, "invalidated_by": current_user["id"]}})
        active_strikes = await db.chat_strikes.count_documents({"user_id": violation["user_id"], "invalidated": {"$ne": True}})
        await db.users.update_one(
            {"id": violation["user_id"]},
            {"$set": {"warning_count": active_strikes}, "$unset": {"action_cards_only_until": ""}}
        )
        await db.chat_pauses.update_many({"user_id": violation["user_id"]}, {"$set": {"invalidated": True, "paused_until": reviewed_at}})
    return {"message": "False-positive review updated", "status": data.status}

@api_router.post("/chat/action-cards")
async def create_chat_action_card(data: ChatActionCardCreate, current_user: dict = Depends(get_current_user)):
    await validate_chat_access(current_user, data.recipient_id, allow_action_cards_only=True)
    fields = await validate_action_card_payload(data, current_user)
    created_at = now_iso()
    card = {
        "id": str(uuid.uuid4()),
        "thread_key": thread_key_for(current_user["id"], data.recipient_id),
        "participants": sorted([current_user["id"], data.recipient_id]),
        "sender_id": current_user["id"],
        "sender_nickname": current_user.get("nickname"),
        "recipient_id": data.recipient_id,
        "deal_id": data.deal_id,
        "type": data.type,
        "fields": fields,
        "status": "open",
        "created_at": created_at,
        "available_actions": get_action_card_available_actions(data.type),
        "read_by": [current_user["id"]],
        "immutable": True
    }
    await db.chat_action_cards.insert_one(card)
    if data.type in ["damage_report", "raise_dispute"] and data.deal_id:
        campaign = await get_campaign_by_deal_id(data.deal_id)
        if campaign:
            await db.escrow.update_one({"campaign_id": campaign["id"]}, {"$set": {"status": "on_hold", "updated_at": created_at}}, upsert=True)
            await db.campaigns.update_one({"id": campaign["id"]}, {"$set": {"chat_issue_status": data.type, "updated_at": created_at}})
    if data.type in ["damage_report", "escalate_to_admin", "raise_dispute"] or fields.get("notify_admin"):
        await notify_admins("Chat action card needs attention", f"{current_user.get('nickname', current_user['id'])} created {data.type}.")
    if data.type == "private_invitation" and current_user.get("role") == UserRole.BUSINESS:
        await notify_if_repeated_declines(current_user["id"], data.recipient_id)
        await record_match_event("invitation_sent", current_user["id"], data.recipient_id, card_id=card["id"], campaign_id=data.deal_id)
    elif data.type == "custom_offer" and current_user.get("role") == UserRole.CREATOR:
        await record_match_event("custom_offer_sent", data.recipient_id, current_user["id"], card_id=card["id"])
    elif data.type == "counter_offer":
        await record_match_event("counter_sent", None, None, card_id=card["id"])
    return {"message": "Action card created", "action_card": {key: value for key, value in card.items() if key != "_id"}}

# Offer cards that, when accepted, should create/activate a funded deal.
DEAL_FORMING_CARD_TYPES = {"custom_offer", "counter_offer", "private_invitation"}

def parse_money(value: Any) -> float:
    """Parse a money value that may be a number or a string like '₹5,000'."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    digits = re.sub(r"[^\d.]", "", str(value))
    try:
        return float(digits) if digits else 0.0
    except ValueError:
        return 0.0


def _accepted_offer_amount(card: dict) -> float:
    """Extract the agreed amount from an accepted offer card."""
    fields = card.get("fields") or {}
    raw = (
        fields.get("price")
        if card.get("type") == "custom_offer"
        else fields.get("modified_price")
        if card.get("type") == "counter_offer"
        else fields.get("budget")
    )
    return parse_money(raw)


async def enforce_brand_wallet_for_acceptance(card: dict) -> None:
    """PRD 5.9: at acceptance the brand's wallet must cover the full deal value.
    If short, the acceptance is blocked and the brand is asked to top up within 24h."""
    participants = card.get("participants") or []
    users = await db.users.find({"id": {"$in": participants}}, {"_id": 0}).to_list(2)
    brand = next((u for u in users if u.get("role") == UserRole.BUSINESS), None)
    if not brand:
        return
    amount = _accepted_offer_amount(card)
    if amount <= 0:
        return
    balance = to_float(brand.get("balance"))
    if balance < amount:
        shortfall = round(amount - balance, 2)
        deadline = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        await db.chat_action_cards.update_one(
            {"id": card["id"]},
            {"$set": {"pending_topup": True, "topup_deadline": deadline, "shortfall": shortfall}},
        )
        await notify_user(
            brand["id"],
            "Top up to confirm this deal",
            f"A creator accepted your offer for ₹{int(amount)} but your wallet holds ₹{int(balance)}. Add ₹{int(shortfall)} within 24 hours to confirm the deal.",
            link="/dashboard/business/wallet",
        )
        raise HTTPException(
            status_code=402,
            detail={
                "message": "The brand's wallet has insufficient balance for this deal. The brand has been asked to top up within 24 hours.",
                "shortfall": shortfall,
            },
        )

async def activate_deal_from_card(card: dict) -> Optional[dict]:
    """Bridge the chat layer to the deal layer: when an offer card is accepted,
    create/activate the underlying campaign, hold escrow, and open the deal room.

    Returns the activated campaign (or None if a deal couldn't be formed, e.g.
    the two participants aren't a brand+creator pair). Idempotent: if the linked
    campaign already has a selected creator + escrow, it is returned unchanged.
    """
    participants = card.get("participants") or []
    if len(participants) != 2:
        return None
    users = await db.users.find({"id": {"$in": participants}}, {"_id": 0}).to_list(2)
    brand = next((u for u in users if u.get("role") == UserRole.BUSINESS), None)
    creator = next((u for u in users if u.get("role") == UserRole.CREATOR), None)
    if not brand or not creator:
        return None  # not a brand<->creator thread; nothing to fund

    amount = _accepted_offer_amount(card)
    fields = card.get("fields") or {}
    now = now_iso()

    # Locate an existing campaign this card is tied to, else create a direct one.
    campaign = None
    if card.get("deal_id"):
        campaign = await get_campaign_by_deal_id(card["deal_id"])
    if not campaign and fields.get("campaign_id"):
        campaign = await db.campaigns.find_one({"id": fields["campaign_id"]}, {"_id": 0})

    if campaign:
        # Already activated for this creator with escrow held → nothing to do.
        existing_escrow = await db.escrow.find_one({"campaign_id": campaign["id"]}, {"_id": 0})
        if campaign.get("selected_creator") == creator["id"] and existing_escrow:
            return campaign
        if campaign.get("business_id") != brand["id"]:
            return None  # mismatched ownership; refuse to cross-wire
    else:
        campaign = {
            "id": str(uuid.uuid4()),
            "business_id": brand["id"],
            "brand_name": brand.get("nickname") or (brand.get("profile") or {}).get("business_name") or "Brand",
            "title": fields.get("campaign_name") or "Direct deal",
            "brief_text": fields.get("deliverable_summary") or fields.get("diff_vs_original") or "",
            "objectives": [],
            "budget_min": amount,
            "budget_max": amount,
            "requires_shipment": bool(fields.get("requires_shipment")),
            "content_requirements": {},
            "status": CampaignStatus.DRAFT,
            "source": "chat_offer",
            "origin_card_id": card.get("id"),
            "created_at": now,
        }
        await db.campaigns.insert_one(dict(campaign))

    # Fund escrow: atomically debit the brand wallet into a held record. The
    # conditional update guarantees we never drive the wallet negative (the
    # acceptance path already checked sufficiency in enforce_brand_wallet_for_acceptance).
    escrow = await db.escrow.find_one({"campaign_id": campaign["id"]}, {"_id": 0})
    if not escrow:
        escrow_id = str(uuid.uuid4())
        debit = await db.users.update_one(
            {"id": brand["id"], "balance": {"$gte": amount}},
            {"$inc": {"balance": -amount}},
        )
        funded = debit.modified_count == 1
        await db.escrow.insert_one({
            "id": escrow_id,
            "campaign_id": campaign["id"],
            "business_id": brand["id"],
            "creator_id": creator["id"],
            "amount": amount,
            "status": "held",
            "wallet_funded": funded,
            "source": "chat_offer",
            "origin_card_id": card.get("id"),
            "created_at": now,
        })
    else:
        escrow_id = escrow.get("id")

    await db.campaigns.update_one(
        {"id": campaign["id"]},
        {"$set": {
            "selected_creator": creator["id"],
            "status": CampaignStatus.IN_PROGRESS,
            "escrow_id": escrow_id,
            "work_started_at": now,
            "updated_at": now,
        }}
    )
    campaign = await db.campaigns.find_one({"id": campaign["id"]}, {"_id": 0})

    # Link the card back to its deal so the UI can deep-link into the deal room.
    await db.chat_action_cards.update_one(
        {"id": card["id"]},
        {"$set": {"deal_campaign_id": campaign["id"], "deal_id": make_deal_id(campaign)}}
    )

    await insert_deal_activity(campaign, "system", "UGCAD.IO", "deal_started",
                               f"Offer accepted — deal opened with ₹{int(amount)} held in escrow.")
    await insert_deal_system_message(campaign, f"Offer accepted. ₹{int(amount)} is held in escrow and the deal room is now open.")
    return campaign


@api_router.post("/chat/action-cards/{card_id}/respond")
async def respond_chat_action_card(card_id: str, data: ChatActionCardRespond, current_user: dict = Depends(get_current_user)):
    card = await db.chat_action_cards.find_one({"id": card_id}, {"_id": 0})
    if not card:
        raise HTTPException(status_code=404, detail="Action card not found")
    if current_user["id"] not in card.get("participants", []):
        raise HTTPException(status_code=403, detail="Not authorized for this action card")
    if card.get("status") not in ["open", "pending"]:
        raise HTTPException(status_code=400, detail="Action card has already been responded to.")

    # Enforce response deadlines (72h invites, 48h counter/custom offers).
    if is_action_card_expired(card):
        await db.chat_action_cards.update_one(
            {"id": card_id},
            {"$set": {"status": "expired", "expired_at": now_iso()}}
        )
        await record_match_event(f"{card.get('type')}_expired", None, None, card_id=card_id, campaign_id=card.get("deal_id"), extra={"card_type": card.get("type")})
        raise HTTPException(status_code=400, detail="This offer has expired and can no longer be responded to.")

    if data.action not in card.get("available_actions", []):
        raise HTTPException(status_code=400, detail="Action is not available for this card.")

    # Declining an offer: require a structured reason and moderate the comment.
    decline_reason = None
    if data.action == "reject" and card.get("type") in OFFER_CARD_TYPES:
        decline_reason = data.decline_reason
        if decline_reason not in DECLINE_REASONS:
            raise HTTPException(
                status_code=400,
                detail=f"A decline reason is required. Choose one of: {', '.join(DECLINE_REASONS)}.",
            )
        if data.note:
            moderation = check_contact_info_policy(data.note)
            if not moderation.get("safe"):
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Your comment appears to contain contact information, which cannot be shared.",
                        "field": "note",
                        "violations": moderation.get("violations", []),
                    },
                )

    # PRD 5.9: brand wallet must cover the deal at acceptance (blocks if short).
    if data.action == "accept" and card.get("type") in DEAL_FORMING_CARD_TYPES:
        await enforce_brand_wallet_for_acceptance(card)

    response = {
        "action": data.action,
        "note": data.note,
        "decline_reason": decline_reason,
        "responded_by": current_user["id"],
        "responded_at": now_iso()
    }
    await db.chat_action_cards.update_one(
        {"id": card_id},
        {"$set": {"status": data.action, "response": response}, "$addToSet": {"read_by": current_user["id"]}}
    )

    # PRD 5.8: capture the response for metrics (acceptance rate, response time,
    # decline reasons, counter-offer success).
    if card.get("type") in OFFER_CARD_TYPES:
        created = parse_iso(card.get("created_at"))
        responded = parse_iso(response["responded_at"])
        response_seconds = int((responded - created).total_seconds()) if created and responded else None
        await record_match_event(
            f"{card['type']}_{data.action}",
            None, None,
            card_id=card_id,
            campaign_id=card.get("deal_id"),
            extra={
                "card_type": card["type"],
                "action": data.action,
                "decline_reason": decline_reason,
                "response_seconds": response_seconds,
                "responder_id": current_user["id"],
            },
        )

    # Bridge to the deal layer: accepting an offer creates/activates the deal,
    # holds escrow, and opens the deal room.
    deal = None
    if data.action == "accept" and card.get("type") in DEAL_FORMING_CARD_TYPES:
        try:
            deal = await activate_deal_from_card({**card, "status": data.action})
        except Exception:
            logger.exception("Failed to activate deal from accepted card %s", card_id)

    updated = await db.chat_action_cards.find_one({"id": card_id}, {"_id": 0})
    result = {"message": "Action card response saved", "action_card": updated}
    if deal:
        result["deal"] = {"campaign_id": deal["id"], "deal_id": make_deal_id(deal), "status": deal.get("status")}
    return result

@api_router.post("/chat/action-cards/{card_id}/revoke")
async def revoke_chat_action_card(card_id: str, current_user: dict = Depends(get_current_user)):
    """PRD 5.9: the sender may revoke an offer/invitation while it is still open
    and unanswered. The listing fee is not refunded here."""
    card = await db.chat_action_cards.find_one({"id": card_id}, {"_id": 0})
    if not card:
        raise HTTPException(status_code=404, detail="Action card not found")
    if card.get("sender_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Only the sender can revoke this card.")
    if card.get("type") not in OFFER_CARD_TYPES:
        raise HTTPException(status_code=400, detail="Only offers and invitations can be revoked.")
    if card.get("status") not in ["open", "pending"]:
        raise HTTPException(status_code=400, detail="This card has already been responded to and cannot be revoked.")

    await db.chat_action_cards.update_one(
        {"id": card_id},
        {"$set": {"status": "revoked", "revoked_at": now_iso(), "revoked_by": current_user["id"]}},
    )
    await notify_user(
        card.get("recipient_id"),
        "An invitation was withdrawn",
        f"{current_user.get('nickname', 'The brand')} withdrew their {card.get('type', 'offer').replace('_', ' ')}.",
        link="/dashboard/creator/inbox",
    )
    await record_match_event(f"{card.get('type')}_revoked", None, None, card_id=card_id, campaign_id=card.get("deal_id"))
    updated = await db.chat_action_cards.find_one({"id": card_id}, {"_id": 0})
    return {"message": "Invitation revoked", "action_card": updated}

@api_router.post("/chat/{other_user_id}/typing")
async def set_chat_typing(other_user_id: str, current_user: dict = Depends(get_current_user)):
    await validate_chat_access(current_user, other_user_id, allow_action_cards_only=True)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=6)).isoformat()
    doc = {
        "thread_key": thread_key_for(current_user["id"], other_user_id),
        "user_id": current_user["id"],
        "other_user_id": other_user_id,
        "updated_at": now_iso(),
        "expires_at": expires_at
    }
    await db.chat_typing.update_one(
        {"thread_key": doc["thread_key"], "user_id": current_user["id"]},
        {"$set": doc},
        upsert=True
    )
    return {"typing": True, "expires_at": expires_at}

@api_router.get("/chat/{other_user_id}/typing")
async def get_chat_typing(other_user_id: str, current_user: dict = Depends(get_current_user)):
    now = now_iso()
    typing = await db.chat_typing.find_one({
        "thread_key": thread_key_for(current_user["id"], other_user_id),
        "user_id": other_user_id,
        "expires_at": {"$gt": now}
    }, {"_id": 0})
    return {"typing": bool(typing), "user_id": other_user_id if typing else None, "expires_at": typing.get("expires_at") if typing else None}

@api_router.get("/chat/{other_user_id}")
async def get_chat_history(other_user_id: str, current_user: dict = Depends(get_current_user)):
    await validate_chat_access(current_user, other_user_id, allow_action_cards_only=True)
    messages = await db.messages.find({
        "$or": [
            {"sender_id": current_user['id'], "recipient_id": other_user_id},
            {"sender_id": other_user_id, "recipient_id": current_user['id']}
        ]
    }, {"_id": 0}).sort("timestamp", 1).to_list(1000)

    action_cards = await db.chat_action_cards.find({
        "participants": {"$all": [current_user['id'], other_user_id]}
    }, {"_id": 0}).sort("created_at", 1).to_list(1000)

    if not current_user.get("disable_read_receipts"):
        read_at = now_iso()
        await db.messages.update_many(
            {"sender_id": other_user_id, "recipient_id": current_user['id']},
            {"$set": {"read": True, "read_at": read_at, "status": "read"}, "$addToSet": {"read_by": current_user['id']}}
        )
        await db.chat_action_cards.update_many(
            {"recipient_id": current_user['id'], "participants": {"$all": [current_user['id'], other_user_id]}},
            {"$addToSet": {"read_by": current_user['id']}, "$set": {"read_at": read_at}}
        )

    items = [message_to_chat_item(msg) for msg in messages] + [action_card_to_chat_item(card) for card in action_cards]
    items.sort(key=lambda item: item.get("created_at") or item.get("timestamp") or "")
    return items

@api_router.get("/admin/violations")
async def get_all_violations(current_user: dict = Depends(get_current_user)):
    """Admin endpoint to view all violations"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    violations = await db.violations.find({}, {"_id": 0}).sort("timestamp", -1).limit(100).to_list(100)
    return violations

@api_router.get("/admin/chats")
async def get_all_chats(current_user: dict = Depends(get_current_user)):
    """Admin endpoint to view all chat conversations"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get all messages
    messages = await db.messages.find({}, {"_id": 0}).to_list(10000)
    
    # Group by conversation (unique pairs of users)
    conversations_dict = {}
    for msg in messages:
        # Create a consistent conversation ID (sorted user IDs)
        user_pair = tuple(sorted([msg['sender_id'], msg['recipient_id']]))
        
        if user_pair not in conversations_dict or msg['timestamp'] > conversations_dict[user_pair]['last_message_at']:
            conversations_dict[user_pair] = {
                "user1_id": user_pair[0],
                "user2_id": user_pair[1],
                "last_message": msg['message'][:50],
                "last_message_at": msg['timestamp'],
                "has_filtered": False
            }
        
        # Check if any message in this conversation was filtered
        if msg.get('filtered', False):
            conversations_dict[user_pair]['has_filtered'] = True
    
    # Enrich with user details
    conversations = []
    for user_pair, conv_data in conversations_dict.items():
        user1 = await db.users.find_one({"id": conv_data['user1_id']}, {"_id": 0, "nickname": 1, "username": 1, "role": 1})
        user2 = await db.users.find_one({"id": conv_data['user2_id']}, {"_id": 0, "nickname": 1, "username": 1, "role": 1})

        # Count violations for this conversation
        violation_count = await db.violations.count_documents({
            "user_id": {"$in": [conv_data['user1_id'], conv_data['user2_id']]}
        })

        conversations.append({
            "conversation_id": f"{conv_data['user1_id']}_{conv_data['user2_id']}",
            "user1": {
                "id": conv_data['user1_id'],
                "nickname": user1.get('nickname', 'Unknown') if user1 else 'Unknown',
                "username": user1.get('username') if user1 else None,
                "role": user1.get('role', '') if user1 else ''
            },
            "user2": {
                "id": conv_data['user2_id'],
                "nickname": user2.get('nickname', 'Unknown') if user2 else 'Unknown',
                "username": user2.get('username') if user2 else None,
                "role": user2.get('role', '') if user2 else ''
            },
            "last_message": conv_data['last_message'],
            "last_message_at": conv_data['last_message_at'],
            "has_violations": conv_data['has_filtered'],
            "violation_count": violation_count
        })
    
    # Sort by last message time (most recent first)
    conversations.sort(key=lambda x: x['last_message_at'], reverse=True)
    
    return conversations

@api_router.get("/admin/chat/{user1_id}/{user2_id}")
async def get_chat_for_admin(user1_id: str, user2_id: str, current_user: dict = Depends(get_current_user)):
    """Admin endpoint to view specific chat conversation"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Admin access required")

    # Get all messages between these two users
    messages = await db.messages.find({
        "$or": [
            {"sender_id": user1_id, "recipient_id": user2_id},
            {"sender_id": user2_id, "recipient_id": user1_id}
        ]
    }, {"_id": 0}).sort("timestamp", 1).to_list(1000)

    # Enrich each message with the sender's current nickname/username for admin display
    sender_cache: Dict[str, dict] = {}
    for msg in messages:
        sender_id = msg.get("sender_id")
        if not sender_id or sender_id == "system":
            msg["sender_username"] = None
            continue
        if sender_id not in sender_cache:
            sender_cache[sender_id] = await db.users.find_one(
                {"id": sender_id},
                {"_id": 0, "nickname": 1, "username": 1}
            ) or {}
        sender = sender_cache[sender_id]
        msg["sender_nickname"] = sender.get("nickname") or msg.get("sender_nickname")
        msg["sender_username"] = sender.get("username")

    return messages

# Work Submission Routes
@api_router.post("/work/submit")
async def submit_work(data: WorkSubmission, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can submit work")

    campaign = await db.campaigns.find_one({"id": data.campaign_id}, {"_id": 0})
    if not campaign or campaign.get('selected_creator') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    uploads_dir = str(Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))))
    primary_file = data.work_files[0] if data.work_files else None
    work_doc = {
        "id": str(uuid.uuid4()),
        "campaign_id": data.campaign_id,
        "creator_id": current_user['id'],
        "work_files": data.work_files,
        "description": data.description,
        "status": WorkStatus.SUBMITTED,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "watermark": cf.build_watermark_record(primary_file, "video", uploads_dir),
        "revisions": []
    }

    await db.work_submissions.insert_one(work_doc)

    # Update campaign status to work_submitted
    await db.campaigns.update_one(
        {"id": data.campaign_id},
        {"$set": {"status": "work_submitted"}}
    )

    await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), "content_submitted", "Content was submitted for brand review.")
    await insert_deal_system_message(campaign, "Content was submitted and is awaiting brand review.")

    return {"message": "Work submitted successfully"}

def deal_deadline_iso(campaign: dict) -> Optional[str]:
    return campaign.get('final_delivery_by') or campaign.get('due_date') or campaign.get('deadline')


async def assess_late_delivery(creator_id: str, campaign: dict, work: dict) -> dict:
    """PRD 8.8: compare submission time to the brief deadline, record the offense
    (rolling 6-month window) and return the penalty for this deal's payout."""
    deadline = parse_iso(deal_deadline_iso(campaign))
    submitted = parse_iso(work.get('submitted_at') or work.get('created_at'))
    result = {"is_late": False, "severity": "on_time", "penalty_pct": 0, "offense_number": 0}
    if not deadline or not submitted or submitted <= deadline:
        return result
    hours_late = (submitted - deadline).total_seconds() / 3600
    severity = cf.classify_lateness(hours_late)
    if severity == "on_time":
        return result
    since = (datetime.now(timezone.utc) - timedelta(days=cf.LATE_PENALTY_WINDOW_DAYS)).isoformat()
    prior = await db.late_offenses.count_documents({"creator_id": creator_id, "created_at": {"$gte": since}})
    offense_number = prior + 1
    pct = cf.late_penalty_pct(offense_number, severity)
    await db.late_offenses.insert_one({
        "id": str(uuid.uuid4()),
        "creator_id": creator_id,
        "campaign_id": campaign.get('id'),
        "severity": severity,
        "hours_late": round(hours_late, 1),
        "offense_number": offense_number,
        "penalty_pct": pct,
        "waived": False,
        "created_at": now_iso(),
    })
    return {"is_late": True, "severity": severity, "penalty_pct": pct, "offense_number": offense_number, "hours_late": round(hours_late, 1)}


@api_router.post("/work/{work_id}/approve")
async def approve_work(work_id: str, current_user: dict = Depends(get_current_user)):
    work = await db.work_submissions.find_one({"id": work_id})
    if not work:
        raise HTTPException(status_code=404, detail="Work not found")

    campaign = await db.campaigns.find_one({"id": work['campaign_id']})
    if campaign['business_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    # PRD 8.6: approval is final and irreversible.
    if work.get('status') == WorkStatus.APPROVED:
        raise HTTPException(status_code=400, detail="This content is already approved. Approval is final.")
    # PRD 9.3: no approval while a dispute is open.
    await ensure_not_disputed(work['campaign_id'])

    now = now_iso()
    await db.work_submissions.update_one(
        {"id": work_id},
        {"$set": {"status": WorkStatus.APPROVED, "approved_at": now}}
    )

    payout_info = await schedule_payout_for_deal(campaign, work, source="approval")

    # PRD 8.6: content is approved; payout is queued (not released yet).
    await db.campaigns.update_one(
        {"id": work['campaign_id']},
        {"$set": {"payout_status": "scheduled", "approved_at": now, "updated_at": now}}
    )

    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "content_approved",
                               f"Content approved. Payment scheduled for {payout_info.get('payout_scheduled_at', 'the payout date')[:10]}.")
    await insert_deal_system_message(campaign, "Content approved. The creator's payout has been scheduled.")
    await notify_user(work['creator_id'], "Your content was approved",
                      f"Payment of ₹{int(payout_info.get('net_payable', 0))} is scheduled for {payout_info.get('payout_scheduled_at', '')[:10]}.",
                      link="/my-deals")

    return {"message": "Content approved. Payout scheduled.", **payout_info}


async def schedule_payout_for_deal(campaign: dict, work: dict, source: str = "approval") -> dict:
    """PRD 8.7: queue the creator's payout for `payout_delay_days` after approval,
    netting TDS and any late-delivery penalty. Does NOT move money yet."""
    escrow = await db.escrow.find_one({"campaign_id": campaign['id']})
    if not escrow:
        return {"payout_scheduled_at": None, "net_payable": 0, "tds_amount": 0, "penalty_amount": 0}
    creator = await db.users.find_one({"id": work['creator_id']}, {"_id": 0, "level": 1, "tds_exempt": 1}) or {}
    gross = float(escrow.get('amount') or 0)
    delay = cf.payout_delay_days(creator.get('level'))
    scheduled_at = (datetime.now(timezone.utc) + timedelta(days=delay)).isoformat()
    tds = cf.compute_tds(gross, exempt=bool(creator.get('tds_exempt')))
    late = await assess_late_delivery(work['creator_id'], campaign, work)
    penalty = round(gross * late['penalty_pct'] / 100, 2) if late['is_late'] else 0.0
    net = round(gross - tds - penalty, 2)
    await db.escrow.update_one(
        {"id": escrow['id']},
        {"$set": {
            "payout_status": "scheduled",
            "approved_at": now_iso(),
            "payout_scheduled_at": scheduled_at,
            "estimated_payout_at": scheduled_at,
            "payout_delay_days": delay,
            "gross_amount": gross,
            "tds_amount": tds,
            "penalty_amount": penalty,
            "penalty_pct": late['penalty_pct'],
            "penalty_brand_credit": round(penalty * cf.LATE_PENALTY_BRAND_SHARE, 2),
            "late_severity": late['severity'],
            "net_payable": net,
            "deductions": [{"label": "TDS", "amount": tds}, {"label": "Penalty", "amount": penalty}],
            "creator_level": creator.get('level') or cf.DEFAULT_CREATOR_LEVEL,
        }}
    )
    # Brand-facing invoice + creator TDS record (PRD 8.6)
    await db.invoices.insert_one({
        "id": str(uuid.uuid4()),
        "campaign_id": campaign['id'],
        "business_id": campaign.get('business_id'),
        "creator_id": work['creator_id'],
        "gross_amount": gross,
        "tds_amount": tds,
        "net_to_creator": net,
        "created_at": now_iso(),
        "source": source,
    })
    return {"payout_scheduled_at": scheduled_at, "net_payable": net, "tds_amount": tds, "penalty_amount": penalty, "late": late}


async def release_scheduled_payout(escrow: dict) -> bool:
    """PRD 8.7: on the scheduled date, move the net payout to the creator, credit
    any brand goodwill from a late penalty, and mark the deal complete."""
    if escrow.get('payout_status') != 'scheduled':
        return False
    campaign = await db.campaigns.find_one({"id": escrow.get('campaign_id')})
    if not campaign:
        return False
    creator_id = escrow.get('creator_id') or campaign.get('selected_creator')
    gross = float(escrow.get('gross_amount') or escrow.get('amount') or 0)
    tds = float(escrow.get('tds_amount') or 0)
    penalty = float(escrow.get('penalty_amount') or 0)
    net = float(escrow.get('net_payable') if escrow.get('net_payable') is not None else gross - tds - penalty)
    now = now_iso()

    await db.escrow.update_one({"id": escrow['id']}, {"$set": {"status": "released", "payout_status": "released", "released_at": now}})
    if creator_id:
        await db.users.update_one({"id": creator_id}, {"$inc": {"balance": net}})
    # Half of any late penalty is credited to the brand as goodwill (PRD 8.8).
    brand_credit = float(escrow.get('penalty_brand_credit') or 0)
    if brand_credit > 0 and campaign.get('business_id'):
        await db.users.update_one({"id": campaign['business_id']}, {"$inc": {"balance": brand_credit}})
        await notify_user(campaign['business_id'], "Goodwill credit applied", f"₹{int(brand_credit)} was credited to your wallet from a late-delivery penalty.", link="/dashboard/business/wallet")

    await create_payout_receipt(
        creator_id=creator_id, receipt_type="earning", gross_amount=gross,
        campaign_id=campaign['id'], reference_id=escrow.get('id'),
        note="Scheduled payout released", tds_amount=tds, penalty_amount=penalty,
    )
    await db.campaigns.update_one({"id": campaign['id']}, {"$set": {"status": CampaignStatus.COMPLETED, "payout_status": "released", "updated_at": now}})
    await insert_deal_activity(campaign, "system", "UGCAD.IO", "payment_released", f"Payout of ₹{int(net)} released to the creator.")
    if creator_id:
        await notify_user(creator_id, "Payment released", f"₹{int(net)} has been released to your wallet.", link="/payouts")
    return True


async def release_due_payouts() -> int:
    """Release every scheduled payout whose date has arrived."""
    now = now_iso()
    due = await db.escrow.find({"payout_status": "scheduled", "payout_scheduled_at": {"$lte": now}}).to_list(1000)
    released = 0
    for escrow in due:
        try:
            if await release_scheduled_payout(escrow):
                released += 1
        except Exception:
            logger.exception("Failed to release payout for escrow %s", escrow.get('id'))
    return released


AUTO_APPROVE_DAYS = 5  # PRD 8.4


async def auto_approve_stale_submissions() -> int:
    """PRD 8.4: content auto-approves 5 days after submission if the brand never
    acts, protecting creators from ghosting brands."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=AUTO_APPROVE_DAYS)).isoformat()
    stale = await db.work_submissions.find({
        "status": WorkStatus.SUBMITTED,
        "submitted_at": {"$lte": cutoff},
    }).to_list(1000)
    approved = 0
    for work in stale:
        campaign = await db.campaigns.find_one({"id": work.get('campaign_id')})
        if not campaign:
            continue
        # Don't auto-approve a deal that's under dispute.
        cards = await db.deal_action_cards.find({"campaign_id": campaign['id']}, {"_id": 0}).to_list(100)
        if any(c.get('type') in ['raise_dispute', 'escalate_to_admin'] and c.get('status') == 'open' for c in cards):
            continue
        await db.work_submissions.update_one({"id": work['id']}, {"$set": {"status": WorkStatus.APPROVED, "approved_at": now_iso(), "auto_approved": True}})
        await schedule_payout_for_deal(campaign, work, source="auto_approval")
        await db.campaigns.update_one({"id": campaign['id']}, {"$set": {"payout_status": "scheduled", "updated_at": now_iso()}})
        await insert_deal_system_message(campaign, f"Content auto-approved after {AUTO_APPROVE_DAYS} days with no brand review (PRD 8.4). Payout scheduled.")
        await notify_user(work['creator_id'], "Your content was auto-approved", "The brand didn't review in time, so your content was auto-approved and payout scheduled.", link="/my-deals")
        approved += 1
    return approved


@api_router.post("/admin/payouts/run-due")
async def run_due_payouts(current_user: dict = Depends(get_current_user)):
    """Sweep: release due payouts and auto-approve stale submissions. Safe to call
    on a schedule (cron) or manually from the admin dashboard."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can run payout sweeps")
    auto_approved = await auto_approve_stale_submissions()
    released = await release_due_payouts()
    return {"auto_approved": auto_approved, "payouts_released": released}


# PRD 8.8 — consequence ladder shown to creators ("fair systems explain themselves")
LATE_PENALTY_LADDER = [
    {"offense": 1, "consequence": "Warning + 5% payout penalty on that deal"},
    {"offense": 2, "consequence": "10% penalty + 60-day pause on level upgrades"},
    {"offense": 3, "consequence": "15% penalty + level demotion + 90-day probation"},
    {"offense": 4, "consequence": "25% penalty + 14-day cooldown on new briefs"},
    {"offense": 5, "consequence": "100% payout forfeit + account review + possible ban"},
]


@api_router.get("/creator/penalties")
async def get_creator_penalties(current_user: dict = Depends(get_current_user)):
    """PRD 8.8: creator's current penalty count, rolling reset date and the
    consequence ladder."""
    if current_user["role"] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators have a penalty record")
    since_dt = datetime.now(timezone.utc) - timedelta(days=cf.LATE_PENALTY_WINDOW_DAYS)
    offenses = await db.late_offenses.find(
        {"creator_id": current_user["id"], "created_at": {"$gte": since_dt.isoformat()}, "waived": {"$ne": True}},
        {"_id": 0},
    ).sort("created_at", 1).to_list(100)
    oldest = parse_iso(offenses[0]["created_at"]) if offenses else None
    reset_at = (oldest + timedelta(days=cf.LATE_PENALTY_WINDOW_DAYS)).isoformat() if oldest else None
    return {
        "offense_count": len(offenses),
        "rolling_window_days": cf.LATE_PENALTY_WINDOW_DAYS,
        "rolling_reset_at": reset_at,
        "offenses": offenses,
        "consequence_ladder": LATE_PENALTY_LADDER,
        "next_consequence": LATE_PENALTY_LADDER[min(len(offenses), len(LATE_PENALTY_LADDER) - 1)],
    }


@api_router.post("/admin/late-offenses/{offense_id}/waive")
async def waive_late_offense(offense_id: str, current_user: dict = Depends(get_current_user)):
    """PRD 8.8 exception grants: admin waives a late-delivery penalty (medical,
    platform issue, brand-caused delay, force majeure)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can waive penalties")
    offense = await db.late_offenses.find_one({"id": offense_id}, {"_id": 0})
    if not offense:
        raise HTTPException(status_code=404, detail="Offense not found")
    await db.late_offenses.update_one({"id": offense_id}, {"$set": {"waived": True, "waived_by": current_user["id"], "waived_at": now_iso()}})
    # If the payout hasn't released yet, drop the penalty from the escrow.
    escrow = await db.escrow.find_one({"campaign_id": offense.get("campaign_id"), "payout_status": "scheduled"})
    if escrow and float(escrow.get("penalty_amount") or 0) > 0:
        gross = float(escrow.get("gross_amount") or escrow.get("amount") or 0)
        tds = float(escrow.get("tds_amount") or 0)
        net = round(gross - tds, 2)
        await db.escrow.update_one({"id": escrow["id"]}, {"$set": {
            "penalty_amount": 0, "penalty_pct": 0, "penalty_brand_credit": 0, "net_payable": net,
            "deductions": [{"label": "TDS", "amount": tds}, {"label": "Penalty", "amount": 0}],
        }})
    await notify_user(offense.get("creator_id"), "Late-delivery penalty waived", "An admin waived a late-delivery penalty on one of your deals.", link="/my-deals")
    return {"message": "Penalty waived", "offense_id": offense_id}


# ---------------------------------------------------------------------------
# Brand-side penalties (PRD Section 8.9)
# ---------------------------------------------------------------------------

LATE_SHIP_FEE_PER_DAY = 200
LATE_SHIP_FEE_CAP = 1000
POACHING_PENALTY = 25000
LOW_RATING_THRESHOLD = 3.5
LOW_RATING_MIN_REVIEWS = 3


class ReportUserSubmit(BaseModel):
    reported_user_id: str
    deal_id: Optional[str] = None
    reason: str
    details: Optional[str] = None


class BrandPenaltyApply(BaseModel):
    business_id: str
    penalty_type: str  # warning | fee | poaching | suspension | probation | fraud
    amount: Optional[float] = 0
    days: Optional[int] = 0
    note: Optional[str] = None


@api_router.post("/report-user")
async def report_user(data: ReportUserSubmit, current_user: dict = Depends(get_current_user)):
    """PRD 8.9: either party reports misconduct; admin investigates within 5 business days."""
    if data.details:
        moderation = check_contact_info_policy(data.details)
        if not moderation.get("safe"):
            raise HTTPException(status_code=400, detail={"message": "Your report contains contact information, which cannot be shared.", "violations": moderation.get("violations", [])})
    report = {
        "id": str(uuid.uuid4()),
        "reporter_id": current_user["id"],
        "reporter_role": current_user.get("role"),
        "reported_user_id": data.reported_user_id,
        "deal_id": data.deal_id,
        "reason": data.reason,
        "details": data.details,
        "status": "open",
        "created_at": now_iso(),
    }
    await db.user_reports.insert_one(report)
    await notify_admins("User report filed", f"{current_user.get('nickname', current_user['id'])} reported {data.reported_user_id} ({data.reason}).", link="/dashboard/admin/disputes")
    return {"message": "Report submitted. Our team will investigate within 5 business days.", "report_id": report["id"]}


@api_router.post("/admin/brand-penalty")
async def apply_brand_penalty(data: BrandPenaltyApply, current_user: dict = Depends(get_current_user)):
    """PRD 8.9: admin applies a brand-side penalty (poaching ₹25k, fraud probation,
    suspension, monetary fee, warning)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can apply brand penalties")
    brand = await db.users.find_one({"id": data.business_id, "role": UserRole.BUSINESS}, {"_id": 0, "id": 1})
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    updates = {}
    amount = float(data.amount or 0)
    if data.penalty_type == "poaching":
        amount = amount or POACHING_PENALTY
        days = data.days or 90
        updates["suspended_until"] = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    if data.penalty_type in ["suspension", "probation"] and data.days:
        field = "suspended_until" if data.penalty_type == "suspension" else "probation_until"
        updates[field] = (datetime.now(timezone.utc) + timedelta(days=data.days)).isoformat()
    if amount > 0:
        await db.users.update_one({"id": data.business_id}, {"$inc": {"balance": -amount}})
    if updates:
        await db.users.update_one({"id": data.business_id}, {"$set": updates})
    await db.brand_penalties.insert_one({
        "id": str(uuid.uuid4()), "business_id": data.business_id, "penalty_type": data.penalty_type,
        "amount": amount, "days": data.days or 0, "note": data.note,
        "applied_by": current_user["id"], "created_at": now_iso(),
    })
    await notify_user(data.business_id, "A penalty was applied to your account", f"{data.penalty_type.title()} penalty: {data.note or ''}", link="/dashboard/business")
    return {"message": "Penalty applied", "business_id": data.business_id, "penalty_type": data.penalty_type, "amount": amount}


@api_router.post("/work/{work_id}/request-revision")
async def request_revision(work_id: str, feedback: str, current_user: dict = Depends(get_current_user)):
    work = await db.work_submissions.find_one({"id": work_id})
    if not work:
        raise HTTPException(status_code=404, detail="Work not found")
    
    campaign = await db.campaigns.find_one({"id": work['campaign_id']})
    if campaign['business_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    # PRD 9.3: no revision requests while a dispute is open.
    await ensure_not_disputed(work['campaign_id'])

    # PRD 8.5: hard maximum of 5 revisions per deliverable, then admin must step in.
    used = len(work.get('revisions') or [])
    if used >= 5:
        await notify_admins("Revision limit reached", f"Campaign {work['campaign_id']} hit 5 revisions and needs admin review (PRD 8.5/8.9).", link="/dashboard/admin/disputes")
        raise HTTPException(status_code=400, detail="This deliverable has reached the 5-revision maximum. An admin must review before further revisions.")

    # PRD Section 8: first 2 revisions are free; each one thereafter costs the
    # brand a flat ₹500, debited from the wallet at request time.
    fee = cf.revision_fee_for(used)
    paid = False
    if fee > 0:
        balance = float(current_user.get('balance') or 0)
        if balance < fee:
            raise HTTPException(
                status_code=402,
                detail=f"This is a paid revision (₹{fee}). Your wallet balance (₹{int(balance)}) is insufficient. Please recharge.",
            )
        await db.users.update_one({"id": current_user['id']}, {"$inc": {"balance": -fee}})
        await db.wallet_ledger.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": current_user['id'],
            "type": "debit",
            "category": "revision_fee",
            "amount": fee,
            "campaign_id": work['campaign_id'],
            "work_id": work_id,
            "description": f"Paid revision #{used + 1} for campaign {work['campaign_id']}",
            "created_at": now_iso(),
        })
        paid = True

    revision = {
        "feedback": feedback,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "index": used + 1,
        "paid": paid,
        "fee": fee,
    }

    await db.work_submissions.update_one(
        {"id": work_id},
        {"$set": {"status": WorkStatus.REVISION_REQUESTED}, "$push": {"revisions": revision}}
    )

    note = f" (paid revision, ₹{fee} charged)" if paid else f" ({cf.FREE_REVISION_LIMIT - used - 1} free revision(s) remaining)"
    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "revision_requested", f"Brand requested content revisions.{note}")
    await insert_deal_system_message(campaign, f"Brand requested content revisions.{note}")

    return {
        "message": "Revision requested",
        "revision_number": used + 1,
        "free_revisions_remaining": max(0, cf.FREE_REVISION_LIMIT - (used + 1)),
        "fee_charged": fee,
    }

@api_router.get("/deals/my")
async def get_my_deals(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can access this")

    campaigns = await db.campaigns.find({
        "selected_creator": current_user['id']
    }, {"_id": 0}).to_list(100)

    result = []
    for campaign in campaigns:
        context = await get_deal_context(make_deal_id(campaign), current_user)
        result.append(await build_deal_response(context, current_user))

    return result

@api_router.get("/deals/business")
async def get_business_deals(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only brands can access this")

    campaigns = await db.campaigns.find({
        "business_id": current_user['id'],
        "selected_creator": {"$nin": [None, ""]},
    }, {"_id": 0}).to_list(200)

    result = []
    for campaign in campaigns:
        context = await get_deal_context(make_deal_id(campaign), current_user)
        result.append(await build_deal_response(context, current_user))

    return result

@api_router.post("/deals/{deal_id}/receipt")
async def submit_deal_receipt(deal_id: str, data: DealReceiptSubmit, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can submit receipts")
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    if campaign.get('selected_creator') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    received_at = data.received_at or now_iso()
    receipt_doc = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "creator_id": current_user['id'],
        "received_at": received_at,
        "unboxing_video_url": data.unboxing_video_url,
        "items_damaged": data.items_damaged,
        "damage_report": data.damage_report,
        "created_at": now_iso()
    }
    await db.deal_receipts.update_one(
        {"campaign_id": campaign['id'], "creator_id": current_user['id']},
        {"$set": receipt_doc},
        upsert=True
    )
    shipment_update = {
        "status": "received",
        "received_at": received_at,
        "unboxing_video": data.unboxing_video_url
    }
    if data.items_damaged:
        shipment_update["dispute"] = {
            "reported": True,
            "reason": data.damage_report,
            "reported_at": now_iso()
        }
        await db.deal_action_cards.insert_one({
            "id": str(uuid.uuid4()),
            "deal_id": make_deal_id(campaign),
            "campaign_id": campaign['id'],
            "type": "damage_report",
            "title": "Damaged or wrong product reported",
            "status": "open",
            "created_at": now_iso(),
            "created_by": current_user['id'],
            "message": data.damage_report,
            "attachment_urls": [data.unboxing_video_url] if data.unboxing_video_url else []
        })
    await db.shipments.update_one({"campaign_id": campaign['id']}, {"$set": shipment_update}, upsert=True)
    await insert_deal_activity(
        campaign,
        "creator",
        current_user.get('nickname', 'Creator'),
        "unboxing_uploaded" if data.unboxing_video_url else "receipt_confirmed",
        "Receipt confirmed with unboxing video." if data.unboxing_video_url else "Receipt confirmed."
    )
    if data.items_damaged:
        await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), "dispute_raised", "Damaged or wrong product reported.")
        await insert_deal_system_message(campaign, "Damaged or wrong product has been reported by the creator.")
    return {"message": "Receipt submitted"}

@api_router.post("/deals/{deal_id}/content")
async def submit_deal_content(deal_id: str, data: DealContentSubmit, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can submit content")
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    if campaign.get('selected_creator') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")
    # PRD 9.3: no content uploads while a dispute is open.
    await ensure_not_disputed(campaign['id'])

    required = get_required_assets(campaign)
    missing = []
    if required['final_video'] and not data.video_url:
        missing.append('video_url')
    if required['caption_script'] and not data.caption_url:
        missing.append('caption_url')
    if required['thumbnail'] and not data.thumbnail_url:
        missing.append('thumbnail_url')
    if required['raw_footage'] and not data.raw_footage_url:
        missing.append('raw_footage_url')
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required assets: {', '.join(missing)}")

    existing_versions = await db.deal_content_submissions.count_documents({
        "campaign_id": campaign['id'],
        "creator_id": current_user['id']
    })
    version = existing_versions + 1
    uploads_dir = str(Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))))
    submission = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "creator_id": current_user['id'],
        "version": version,
        "video_url": data.video_url,
        "caption_url": data.caption_url,
        "thumbnail_url": data.thumbnail_url,
        "raw_footage_url": data.raw_footage_url,
        "original_url": data.video_url,
        # Watermark-protected preview so the brand never receives the raw cut
        # before approval (PRD Section 8).
        "watermark": cf.build_watermark_record(data.video_url, "video", uploads_dir),
        "creator_note": data.creator_note,
        "self_assessment": data.self_assessment or [],
        "submitted_at": now_iso(),
        "status": "submitted"
    }
    # PRD 8.3: notes to brand are contact-info filtered.
    if data.creator_note:
        moderation = check_contact_info_policy(data.creator_note)
        if not moderation.get("safe"):
            raise HTTPException(status_code=400, detail={"message": "Your note to the brand contains contact information, which cannot be shared.", "violations": moderation.get("violations", [])})
    await db.deal_content_submissions.insert_one(submission)
    work_doc = {
        "id": str(uuid.uuid4()),
        "campaign_id": campaign['id'],
        "creator_id": current_user['id'],
        "work_files": [url for url in [data.video_url, data.caption_url, data.thumbnail_url, data.raw_footage_url] if url],
        "description": data.creator_note or f"Deal content submission v{version}",
        "status": WorkStatus.SUBMITTED,
        "submitted_at": submission['submitted_at'],
        "watermark": submission['watermark'],
        "revisions": []
    }
    await db.work_submissions.insert_one(work_doc)
    await db.campaigns.update_one({"id": campaign['id']}, {"$set": {"status": "work_submitted", "updated_at": now_iso()}})
    await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), "content_submitted", f"Content version {version} submitted for review.")
    await insert_deal_system_message(campaign, f"Content version {version} was submitted and is awaiting brand review.")
    return {"message": "Content submitted", "version": version}

@api_router.post("/deals/{deal_id}/revision-response")
async def submit_revision_response(deal_id: str, data: DealRevisionResponseSubmit, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can respond to revisions")
    if data.response not in ["accepted", "scope_creep", "partial_dispute"]:
        raise HTTPException(status_code=400, detail="Invalid revision response")
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    if campaign.get('selected_creator') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    response_doc = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "creator_id": current_user['id'],
        "response": data.response,
        "note": data.note,
        "created_at": now_iso()
    }
    await db.deal_revision_responses.insert_one(response_doc)
    event_type = "revision_requested" if data.response == "accepted" else "dispute_raised"
    await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), event_type, f"Creator responded to revision: {data.response}.")
    await insert_deal_system_message(campaign, f"Creator responded to revision request: {data.response}.")
    return {"message": "Revision response submitted"}

@api_router.get("/deals/{deal_id}/chat")
async def get_deal_chat(deal_id: str, current_user: dict = Depends(get_current_user)):
    context = await get_deal_context(deal_id, current_user)
    deal = await build_deal_response(context, current_user)
    await db.deal_messages.update_many(
        {"campaign_id": context['campaign']['id'], "sender_id": {"$ne": current_user['id']}},
        {"$addToSet": {"read_by": current_user['id']}}
    )
    return deal["chat_summary"]

@api_router.post("/deals/{deal_id}/chat")
async def post_deal_chat(deal_id: str, data: DealChatSubmit, current_user: dict = Depends(get_current_user)):
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    sender_type = map_sender_type(current_user['id'], campaign, context['creator']['id'], current_user.get('role'))
    message_doc = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "sender_id": current_user['id'],
        "sender_name": current_user.get('nickname') or current_user.get('email') or 'User',
        "sender_type": sender_type,
        "message": data.message,
        "attachment_urls": data.attachment_urls,
        "created_at": now_iso(),
        "read_by": [current_user['id']]
    }
    await db.deal_messages.insert_one(message_doc)
    return {"message": "Message sent", "chat_message": {key: value for key, value in message_doc.items() if key != "_id"}}

@api_router.post("/deals/{deal_id}/action-card")
async def create_deal_action_card(deal_id: str, data: DealActionCardSubmit, current_user: dict = Depends(get_current_user)):
    if data.type not in ["milestone_update", "damage_report", "escalate_to_admin", "raise_dispute"]:
        raise HTTPException(status_code=400, detail="Invalid action card type")
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    title_map = {
        "milestone_update": "Milestone update",
        "damage_report": "Damage report",
        "escalate_to_admin": "Escalated to admin",
        "raise_dispute": "Dispute raised"
    }
    card = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "type": data.type,
        "title": title_map[data.type],
        "status": "open",
        "created_at": now_iso(),
        "created_by": current_user['id'],
        "message": data.message,
        "attachment_urls": data.attachment_urls
    }
    await db.deal_action_cards.insert_one(card)
    event_type = "dispute_raised" if data.type in ["damage_report", "escalate_to_admin", "raise_dispute"] else "tracking_uploaded"
    await insert_deal_activity(campaign, map_sender_type(current_user['id'], campaign, context['creator']['id'], current_user.get('role')), current_user.get('nickname', 'User'), event_type, data.message)
    await insert_deal_system_message(campaign, f"{title_map[data.type]}: {data.message}")
    return {"message": "Action card created", "action_card": {key: value for key, value in card.items() if key != "_id"}}

async def create_issue_action(deal_id: str, current_user: dict, issue_type: str, title: str, activity_message: str, payload: DealIssueSubmit):
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    card = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "type": issue_type,
        "title": title,
        "status": "open",
        "created_at": now_iso(),
        "created_by": current_user['id'],
        "message": payload.message,
        "attachment_urls": payload.attachment_urls
    }
    await db.deal_action_cards.insert_one(card)
    if issue_type in ["raise_dispute", "escalate_to_admin"]:
        await db.escrow.update_one({"campaign_id": campaign['id']}, {"$set": {"status": "on_hold", "updated_at": now_iso()}}, upsert=True)
    await insert_deal_activity(
        campaign,
        map_sender_type(current_user['id'], campaign, context['creator']['id'], current_user.get('role')),
        current_user.get('nickname', 'User'),
        "dispute_raised",
        activity_message
    )
    await insert_deal_system_message(campaign, activity_message)
    return {"message": title, "action_card": {key: value for key, value in card.items() if key != "_id"}}

@api_router.post("/deals/{deal_id}/dispute")
async def raise_deal_dispute(deal_id: str, data: DealIssueSubmit, current_user: dict = Depends(get_current_user)):
    return await create_issue_action(deal_id, current_user, "raise_dispute", "Dispute raised", data.message or "A dispute was raised on this deal.", data)

@api_router.post("/deals/{deal_id}/escalate")
async def escalate_deal(deal_id: str, data: DealIssueSubmit, current_user: dict = Depends(get_current_user)):
    return await create_issue_action(deal_id, current_user, "escalate_to_admin", "Escalated to admin", data.message or "This deal was escalated to admin support.", data)

@api_router.post("/deals/{deal_id}/damage-report")
async def report_deal_damage(deal_id: str, data: DealIssueSubmit, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can report damage")
    return await create_issue_action(deal_id, current_user, "damage_report", "Damage report created", data.message or "Damaged or wrong product was reported.", data)


# ---------------------------------------------------------------------------
# Dispute resolution engine (PRD Section 9)
# ---------------------------------------------------------------------------

DISPUTE_TYPES = ["non_delivery", "quality_below_brief", "damaged_wrong", "scope_creep",
                 "revision_abuse", "communication_issue", "off_platform_attempt", "payment_issue", "other"]
DESIRED_OUTCOMES = ["full_refund", "partial_refund", "extension", "redo", "reassignment", "other"]

# type -> severity (PRD 9.7)
DISPUTE_SEVERITY = {
    "off_platform_attempt": "critical", "fraud": "critical",
    "damaged_wrong": "high", "non_delivery": "high",
    "scope_creep": "medium", "quality_below_brief": "medium", "revision_abuse": "medium", "payment_issue": "medium",
    "communication_issue": "low", "other": "low",
}
# severity -> (first_response_hours, resolution_business_days)
DISPUTE_SLA = {
    "critical": (4, 1), "high": (24, 3), "medium": (24, 5), "low": (48, 7),
}


def dispute_severity(dispute_type: str) -> str:
    return DISPUTE_SEVERITY.get(dispute_type, "low")


async def get_open_dispute(campaign_id: str) -> Optional[dict]:
    return await db.disputes.find_one({"campaign_id": campaign_id, "status": {"$in": ["open", "info_requested", "appealed"]}}, {"_id": 0})


async def ensure_not_disputed(campaign_id: str):
    """PRD 9.3: while a dispute is open, all non-dispute deal actions are paused."""
    if await get_open_dispute(campaign_id):
        raise HTTPException(status_code=409, detail="This deal is under dispute. Actions are paused until an admin resolves it.")


@api_router.post("/deals/{deal_id}/raise-dispute")
async def raise_structured_dispute(deal_id: str, data: DisputeCreate, current_user: dict = Depends(get_current_user)):
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    # Validation (PRD 9.3)
    if data.dispute_type not in DISPUTE_TYPES:
        raise HTTPException(status_code=400, detail=f"dispute_type must be one of: {', '.join(DISPUTE_TYPES)}")
    if data.desired_outcome not in DESIRED_OUTCOMES:
        raise HTTPException(status_code=400, detail=f"desired_outcome must be one of: {', '.join(DESIRED_OUTCOMES)}")
    if not (100 <= len(data.description) <= 1000):
        raise HTTPException(status_code=400, detail="Description must be 100–1000 characters.")
    if len(data.evidence_urls) < 1:
        raise HTTPException(status_code=400, detail="At least one piece of evidence is required.")
    # PRD 9.8: no disputes after approval / completion.
    if campaign.get('status') == CampaignStatus.COMPLETED or (await db.escrow.find_one({"campaign_id": campaign['id'], "payout_status": "released"})):
        raise HTTPException(status_code=400, detail="This deal is already approved/complete. Approval is final.")
    if await get_open_dispute(campaign['id']):
        raise HTTPException(status_code=400, detail="A dispute is already open on this deal.")

    severity = dispute_severity(data.dispute_type)
    first_hrs, res_days = DISPUTE_SLA[severity]
    now = datetime.now(timezone.utc)
    dispute = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "business_id": campaign.get('business_id'),
        "creator_id": campaign.get('selected_creator'),
        "raised_by": current_user['id'],
        "raised_by_role": current_user.get('role'),
        "dispute_type": data.dispute_type,
        "severity": severity,
        "description": data.description,
        "desired_outcome": data.desired_outcome,
        "evidence_urls": data.evidence_urls,
        "status": "open",
        "first_response_due_at": (now + timedelta(hours=first_hrs)).isoformat(),
        "resolution_due_at": (now + timedelta(days=res_days)).isoformat(),
        "created_at": now_iso(),
    }
    await db.disputes.insert_one(dispute)
    # Pause activity + hold escrow + show Disputed state via a deal action card.
    await db.escrow.update_one({"campaign_id": campaign['id']}, {"$set": {"status": "on_hold", "updated_at": now_iso()}}, upsert=True)
    await db.deal_action_cards.insert_one({
        "id": str(uuid.uuid4()), "deal_id": make_deal_id(campaign), "campaign_id": campaign['id'],
        "type": "raise_dispute", "title": "Dispute raised", "status": "open", "created_at": now_iso(),
        "created_by": current_user['id'], "message": data.description, "dispute_id": dispute["id"],
    })
    await insert_deal_activity(campaign, map_sender_type(current_user['id'], campaign, campaign.get('selected_creator'), current_user.get('role')), current_user.get('nickname', 'User'), "dispute_raised", f"A {severity} dispute was raised: {data.dispute_type.replace('_', ' ')}.")
    # PRD 9.9: admin notified within 5 minutes.
    await notify_admins(f"New {severity} dispute", f"{data.dispute_type.replace('_',' ')} on deal {make_deal_id(campaign)} — first response due in {first_hrs}h.", link="/dashboard/admin/disputes")
    other_party = campaign.get('selected_creator') if current_user['id'] == campaign.get('business_id') else campaign.get('business_id')
    if other_party:
        await notify_user(other_party, "A dispute was raised on your deal", "Deal activity is paused while our team reviews. You'll be asked for any evidence.", link="/my-deals")
    return {"message": "Dispute raised", "dispute_id": dispute["id"], "severity": severity}


def _business_days_from(start: datetime, days: int) -> datetime:
    d, added = start, 0
    while added < days:
        d += timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d


@api_router.get("/admin/disputes")
async def list_disputes(status: Optional[str] = None, dispute_type: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """PRD 9.4: admin dispute dashboard — all disputes sorted by age with SLA countdown."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view disputes")
    query = {}
    if status:
        query["status"] = status
    if dispute_type:
        query["dispute_type"] = dispute_type
    disputes = await db.disputes.find(query, {"_id": 0}).sort("created_at", 1).to_list(1000)
    now = datetime.now(timezone.utc)
    for d in disputes:
        res_due = parse_iso(d.get("resolution_due_at"))
        d["sla_hours_remaining"] = round((res_due - now).total_seconds() / 3600, 1) if res_due else None
        d["sla_breached"] = bool(res_due and res_due < now and d.get("status") not in ["resolved", "closed"])
    open_count = sum(1 for d in disputes if d.get("status") in ["open", "info_requested", "appealed"])
    return {"disputes": disputes, "open_count": open_count, "sla_tiers": DISPUTE_SLA}


@api_router.get("/admin/disputes/{dispute_id}")
async def get_dispute_detail(dispute_id: str, current_user: dict = Depends(get_current_user)):
    """PRD 9.4: full evidence review panel — brief, timeline, chat, content, shipping, prior disputes."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view disputes")
    dispute = await db.disputes.find_one({"id": dispute_id}, {"_id": 0})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    cid = dispute["campaign_id"]
    bid, crid = dispute.get("business_id"), dispute.get("creator_id")
    campaign = await db.campaigns.find_one({"id": cid}, {"_id": 0})
    timeline = await db.deal_activity.find({"campaign_id": cid}, {"_id": 0}).sort("timestamp", 1).to_list(500)
    content = await db.deal_content_submissions.find({"campaign_id": cid}, {"_id": 0}).sort("version", 1).to_list(50)
    shipment = await db.shipments.find_one({"campaign_id": cid}, {"_id": 0})
    chat = await db.messages.find(
        {"$or": [{"sender_id": bid, "recipient_id": crid}, {"sender_id": crid, "recipient_id": bid}]},
        {"_id": 0},
    ).sort("created_at", 1).to_list(500) if bid and crid else []
    prior = await db.disputes.find({"$or": [{"business_id": dispute.get("business_id")}, {"creator_id": dispute.get("creator_id")}], "id": {"$ne": dispute_id}}, {"_id": 0}).to_list(100)
    return {
        "dispute": dispute,
        "brief": normalize_campaign_response(campaign) if campaign else None,
        "timeline": timeline,
        "content_versions": content,
        "shipment": shipment,
        "chat_history": chat,
        "prior_disputes": prior,
    }


@api_router.post("/admin/disputes/{dispute_id}/request-info")
async def dispute_request_info(dispute_id: str, data: DisputeInfoRequest, current_user: dict = Depends(get_current_user)):
    """PRD 9.4: admin requests more info; SLA pauses; 72h response window."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can request info")
    dispute = await db.disputes.find_one({"id": dispute_id}, {"_id": 0})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    target = dispute.get("business_id") if data.party == "brand" else dispute.get("creator_id")
    await db.disputes.update_one({"id": dispute_id}, {"$set": {"status": "info_requested", "info_requested_from": data.party, "info_request_due_at": (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat(), "info_request_message": data.message}})
    if target:
        await notify_user(target, "More information needed for your dispute", data.message + " Please respond within 72 hours.", link="/my-deals")
    return {"message": "Info requested", "dispute_id": dispute_id}


@api_router.post("/admin/disputes/{dispute_id}/rule")
async def rule_dispute(dispute_id: str, data: DisputeRuling, current_user: dict = Depends(get_current_user)):
    """PRD 9.4/9.5: admin ruling + financial execution within 24h."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can rule on disputes")
    if data.ruling not in ["favor_brand", "favor_creator", "split", "no_fault"]:
        raise HTTPException(status_code=400, detail="Invalid ruling type")
    dispute = await db.disputes.find_one({"id": dispute_id}, {"_id": 0})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    if dispute.get("status") in ["resolved", "closed"]:
        raise HTTPException(status_code=400, detail="This dispute is already resolved.")
    campaign = await db.campaigns.find_one({"id": dispute["campaign_id"]})
    escrow = await db.escrow.find_one({"campaign_id": dispute["campaign_id"]})
    held = float((escrow or {}).get("amount") or 0)
    refund = round(float(data.refund_amount or 0), 2)
    creator_amt = round(float(data.creator_amount or 0), 2)

    # Default money splits per ruling when amounts not explicitly given.
    if data.ruling == "favor_creator" and creator_amt == 0:
        creator_amt = held
    elif data.ruling == "favor_brand" and refund == 0:
        refund = held
    elif data.ruling == "no_fault" and creator_amt == 0 and refund == 0:
        creator_amt = held  # platform absorbs; creator still paid from reserve

    # PRD 9.8: if escrow can't cover, platform reserve covers the gap (logged).
    reserve_gap = round(max(0, (refund + creator_amt) - held), 2)

    if refund > 0 and campaign and campaign.get("business_id"):
        await db.users.update_one({"id": campaign["business_id"]}, {"$inc": {"balance": refund}})
    if creator_amt > 0 and dispute.get("creator_id"):
        await db.users.update_one({"id": dispute["creator_id"]}, {"$inc": {"balance": creator_amt}})
        await create_payout_receipt(creator_id=dispute["creator_id"], receipt_type="earning", gross_amount=creator_amt, campaign_id=dispute["campaign_id"], reference_id=dispute_id, note=f"Dispute ruling ({data.ruling})")
    if escrow:
        await db.escrow.update_one({"id": escrow["id"]}, {"$set": {"status": "released", "payout_status": "released", "released_at": now_iso(), "dispute_resolution": data.ruling}})
    if data.extension_days and campaign:
        new_deadline = (datetime.now(timezone.utc) + timedelta(days=data.extension_days)).isoformat()
        await db.campaigns.update_one({"id": campaign["id"]}, {"$set": {"final_delivery_by": new_deadline, "due_date": new_deadline}})

    await db.disputes.update_one({"id": dispute_id}, {"$set": {
        "status": "resolved", "ruling": data.ruling, "reasoning": data.reasoning,
        "refund_amount": refund, "creator_amount": creator_amt, "reserve_gap": reserve_gap,
        "ruled_by": current_user["id"], "resolved_at": now_iso(),
        "appeal_deadline_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    }})
    # Close the open dispute card so the deal unpauses.
    await db.deal_action_cards.update_many({"campaign_id": dispute["campaign_id"], "type": "raise_dispute", "status": "open"}, {"$set": {"status": "resolved"}})
    # PRD 9.5: record outcome on both users' history.
    for uid, role in [(dispute.get("business_id"), "brand"), (dispute.get("creator_id"), "creator")]:
        if uid:
            await db.users.update_one({"id": uid}, {"$push": {"dispute_history": {"dispute_id": dispute_id, "ruling": data.ruling, "role": role, "at": now_iso()}}})
            await notify_user(uid, "Your dispute has been resolved", f"Ruling: {data.ruling.replace('_',' ')}. {data.reasoning[:120]} You may appeal within 7 days.", link="/my-deals")
    if reserve_gap > 0:
        await notify_admins("Dispute ruling exceeded escrow", f"Dispute {dispute_id} needed ₹{reserve_gap} from reserve. Finance audit required.")
    return {"message": "Dispute resolved", "ruling": data.ruling, "refund": refund, "creator_amount": creator_amt, "reserve_gap": reserve_gap}


@api_router.post("/disputes/{dispute_id}/appeal")
async def appeal_dispute(dispute_id: str, data: DisputeAppeal, current_user: dict = Depends(get_current_user)):
    """PRD 9.5: either party appeals within 7 days with new evidence."""
    dispute = await db.disputes.find_one({"id": dispute_id}, {"_id": 0})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    if current_user["id"] not in [dispute.get("business_id"), dispute.get("creator_id")]:
        raise HTTPException(status_code=403, detail="Only the parties can appeal this dispute")
    if dispute.get("status") != "resolved":
        raise HTTPException(status_code=400, detail="Only a resolved dispute can be appealed.")
    if dispute.get("appealed"):
        raise HTTPException(status_code=400, detail="This dispute has already been appealed. The second ruling is final.")
    deadline = parse_iso(dispute.get("appeal_deadline_at"))
    if deadline and datetime.now(timezone.utc) > deadline:
        raise HTTPException(status_code=400, detail="The 7-day appeal window has closed.")
    if not data.new_evidence_urls and not (data.grounds and data.grounds.strip()):
        raise HTTPException(status_code=400, detail="An appeal requires new evidence or points not previously considered.")
    await db.disputes.update_one({"id": dispute_id}, {"$set": {
        "status": "appealed", "appealed": True, "appeal_by": current_user["id"],
        "appeal_grounds": data.grounds, "appeal_evidence_urls": data.new_evidence_urls, "appealed_at": now_iso(),
    }})
    await notify_admins("Dispute appealed", f"Dispute {dispute_id} was appealed — senior review required. Second ruling is final.", link="/dashboard/admin/disputes")
    return {"message": "Appeal submitted. A senior admin will review; the second ruling is final.", "dispute_id": dispute_id}


@api_router.get("/disputes/my")
async def get_my_disputes(current_user: dict = Depends(get_current_user)):
    disputes = await db.disputes.find({"$or": [{"business_id": current_user["id"]}, {"creator_id": current_user["id"]}]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return disputes

# --- Brand-side deal actions (Deal Room) ---
class DealTrackingSubmit(BaseModel):
    tracking_id: str
    courier: Optional[str] = None
    courier_tracking_url: Optional[str] = None
    expected_delivery_at: Optional[str] = None

class DealRevisionRequest(BaseModel):
    feedback: str
    requested_changes: Optional[List[str]] = None

async def get_brand_deal_campaign(deal_id: str, current_user: dict) -> dict:
    """Resolve a deal id to a campaign and assert the caller is its brand."""
    if current_user.get('role') != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only brands can perform this action")
    campaign = await get_campaign_by_deal_id(deal_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    if campaign.get('business_id') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized for this deal")
    return campaign

@api_router.post("/deals/{deal_id}/tracking")
async def submit_deal_tracking(deal_id: str, data: DealTrackingSubmit, current_user: dict = Depends(get_current_user)):
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    shipment_doc = {
        "campaign_id": campaign['id'],
        "tracking_number": data.tracking_id,
        "courier_name": data.courier,
        "courier_tracking_url": data.courier_tracking_url,
        "courier_status": "shipped",
        "expected_delivery": data.expected_delivery_at,
        "updated_at": now_iso(),
        "status": "shipped",
    }
    await db.shipments.update_one({"campaign_id": campaign['id']}, {"$set": shipment_doc}, upsert=True)
    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "tracking_uploaded", "Shipment tracking was uploaded.")
    await insert_deal_system_message(campaign, "Shipment tracking was uploaded by the brand.")
    return {"message": "Tracking uploaded"}

@api_router.post("/deals/{deal_id}/delivered")
async def mark_deal_delivered(deal_id: str, current_user: dict = Depends(get_current_user)):
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    await db.shipments.update_one(
        {"campaign_id": campaign['id']},
        {"$set": {"courier_status": "delivered", "status": "delivered", "updated_at": now_iso()}},
    )
    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "delivered", "Shipment was marked delivered.")
    await insert_deal_system_message(campaign, "Shipment was marked delivered.")
    return {"message": "Marked delivered"}

@api_router.post("/deals/{deal_id}/approve")
async def approve_deal_content(deal_id: str, current_user: dict = Depends(get_current_user)):
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    work = await db.work_submissions.find_one(
        {"campaign_id": campaign['id']}, {"_id": 0}, sort=[("submitted_at", -1)]
    )
    if not work:
        raise HTTPException(status_code=404, detail="No submitted work to approve")
    return await approve_work(work['id'], current_user)

@api_router.post("/deals/{deal_id}/request-revision")
async def request_deal_revision(deal_id: str, data: DealRevisionRequest, current_user: dict = Depends(get_current_user)):
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    work = await db.work_submissions.find_one(
        {"campaign_id": campaign['id']}, {"_id": 0}, sort=[("submitted_at", -1)]
    )
    if not work:
        raise HTTPException(status_code=404, detail="No submitted work to revise")
    return await request_revision(work['id'], data.feedback, current_user)

@api_router.post("/deals/{deal_id}/archive")
async def archive_deal(deal_id: str, current_user: dict = Depends(get_current_user)):
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    await db.campaigns.update_one(
        {"id": campaign['id']},
        {"$set": {"archived_by_brand": True, "archived_at": now_iso()}},
    )
    return {"message": "Deal archived"}

@api_router.get("/work/campaign/{campaign_id}")
async def get_work_by_campaign(campaign_id: str, current_user: dict = Depends(get_current_user)):
    work = await db.work_submissions.find_one(
        {"campaign_id": campaign_id, "creator_id": current_user['id']},
        {"_id": 0}
    )
    return work or {}

@api_router.get("/work/pending-review")
async def get_work_pending_review(current_user: dict = Depends(get_current_user)):
    """Get all work submissions pending review for a business"""
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only businesses can review work")

    # Get all campaigns for this business
    campaigns = await db.campaigns.find(
        {"business_id": current_user['id']},
        {"_id": 0, "id": 1}
    ).to_list(1000)
    campaign_ids = [c['id'] for c in campaigns]

    # Get work submissions for these campaigns
    work_submissions = await db.work_submissions.find(
        {"campaign_id": {"$in": campaign_ids}, "status": WorkStatus.SUBMITTED},
        {"_id": 0}
    ).to_list(1000)

    # Brand review happens on watermark-protected previews only; raw files are
    # withheld until approval (PRD Section 8).
    return [cf.to_brand_facing_asset(work, approved=False) for work in work_submissions]

@api_router.get("/work/{work_id}")
async def get_work_by_id(work_id: str, current_user: dict = Depends(get_current_user)):
    """Get a single work submission by ID"""
    work = await db.work_submissions.find_one({"id": work_id}, {"_id": 0})

    if not work:
        raise HTTPException(status_code=404, detail="Work not found")

    campaign = await db.campaigns.find_one({"id": work['campaign_id']}, {"_id": 0})

    # Verify authorization - user must be creator or the business reviewing it
    is_brand_viewer = False
    if current_user['id'] != work['creator_id']:
        if not campaign or campaign.get('business_id') != current_user['id']:
            raise HTTPException(status_code=403, detail="Not authorized to view this work")
        is_brand_viewer = True

    # Denormalize fields the review UI expects.
    if campaign:
        work['campaign_title'] = campaign.get('title') or campaign.get('campaign_name')
    creator = await db.users.find_one({"id": work['creator_id']}, {"_id": 0, "nickname": 1, "full_name": 1})
    if creator:
        work['creator_nickname'] = creator.get('nickname') or creator.get('full_name')

    if is_brand_viewer:
        # Brand viewer gets the watermark-protected preview until approval.
        approved = work.get('status') == WorkStatus.APPROVED
        return cf.to_brand_facing_asset(work, approved=approved)

    return work

# Review Routes
@api_router.post("/reviews")
async def submit_review(data: ReviewSubmit, current_user: dict = Depends(get_current_user)):
    rates_brand = bool(data.business_id) and current_user.get('role') == UserRole.CREATOR
    review_doc = {
        "id": str(uuid.uuid4()),
        "campaign_id": data.campaign_id,
        "creator_id": data.creator_id,
        "business_id": data.business_id,
        "reviewee_role": "business" if rates_brand else "creator",
        "reviewer_id": current_user['id'],
        "rating": data.rating,
        "review": data.review,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.reviews.insert_one(review_doc)

    if rates_brand:
        # PRD 8.9: chronic low ratings from creators (<3.5) restrict the brand.
        brand_reviews = await db.reviews.find({"business_id": data.business_id, "reviewee_role": "business"}, {"_id": 0}).to_list(1000)
        avg = sum(r['rating'] for r in brand_reviews) / len(brand_reviews)
        updates = {"average_rating": round(avg, 2), "total_reviews": len(brand_reviews)}
        if len(brand_reviews) >= LOW_RATING_MIN_REVIEWS and avg < LOW_RATING_THRESHOLD:
            updates["posting_restricted"] = True
            await notify_admins("Brand restricted for low ratings", f"Brand {data.business_id} fell below {LOW_RATING_THRESHOLD} ({round(avg,2)} over {len(brand_reviews)} reviews).")
            await notify_user(data.business_id, "Posting privileges restricted", "Your creator ratings dropped below 3.5. Posting is restricted pending a support call.", link="/dashboard/business")
        await db.users.update_one({"id": data.business_id}, {"$set": updates})
        return {"message": "Review submitted"}

    # Update creator's average rating
    reviews = await db.reviews.find({"creator_id": data.creator_id, "reviewee_role": {"$ne": "business"}}, {"_id": 0}).to_list(1000)
    avg_rating = sum(r['rating'] for r in reviews) / len(reviews)
    await db.users.update_one(
        {"id": data.creator_id},
        {"$set": {"average_rating": avg_rating, "total_reviews": len(reviews)}}
    )
    return {"message": "Review submitted"}

@api_router.get("/reviews/creator/{creator_id}")
async def get_creator_reviews(creator_id: str):
    reviews = await db.reviews.find({"creator_id": creator_id}, {"_id": 0}).to_list(1000)
    return reviews

# Shipment Routes
@api_router.post("/shipment/update")
async def update_shipment(data: ShipmentUpdate, current_user: dict = Depends(get_current_user)):
    campaign = await db.campaigns.find_one({"id": data.campaign_id})
    if not campaign or campaign['business_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    shipment_doc = {
        "campaign_id": data.campaign_id,
        "tracking_number": data.tracking_number,
        "courier_name": data.courier_name,
        "courier_tracking_url": data.courier_tracking_url,
        "courier_status": data.courier_status or "shipped",
        "courier_slip": data.courier_slip,
        "expected_delivery": data.expected_delivery,
        "shipment_checklist": data.shipment_checklist,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": data.courier_status or "shipped"
    }
    
    existing = await db.shipments.find_one({"campaign_id": data.campaign_id}, {"_id": 0, "late_fee_applied": 1})
    await db.shipments.update_one(
        {"campaign_id": data.campaign_id},
        {"$set": shipment_doc},
        upsert=True
    )

    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "tracking_uploaded", "Shipment tracking was uploaded.")
    await insert_deal_system_message(campaign, "Shipment tracking was uploaded by the brand.")

    # PRD 8.9: late product shipping → ₹200/day to the creator (cap ₹1,000), once.
    ship_by = parse_iso(campaign.get('product_shipping_by'))
    if ship_by and not (existing or {}).get('late_fee_applied'):
        days_late = (datetime.now(timezone.utc) - ship_by).days
        if days_late >= 1:
            fee = min(days_late * LATE_SHIP_FEE_PER_DAY, LATE_SHIP_FEE_CAP)
            creator_id = campaign.get('selected_creator')
            if creator_id and fee > 0:
                await db.users.update_one({"id": creator_id}, {"$inc": {"balance": fee}})
                await db.shipments.update_one({"campaign_id": data.campaign_id}, {"$set": {"late_fee_applied": fee, "late_fee_days": days_late}})
                await notify_user(creator_id, "Late-shipping fee credited", f"₹{fee} was credited to you because the brand shipped {days_late} day(s) late.", link="/payouts")
                await insert_deal_system_message(campaign, f"Brand shipped {days_late} day(s) late — ₹{fee} late-shipping fee credited to the creator (PRD 8.9).")

    return {"message": "Shipment details updated"}

@api_router.post("/shipment/receive")
async def receive_shipment(data: ShipmentReceive, current_user: dict = Depends(get_current_user)):
    campaign = await db.campaigns.find_one({"id": data.campaign_id})
    if not campaign or campaign['selected_creator'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = {
        "status": "received",
        "unboxing_video": data.unboxing_video,
        "received_at": datetime.now(timezone.utc).isoformat()
    }
    
    if data.items_damaged:
        update_data['dispute'] = {
            "reported": True,
            "reason": data.dispute_reason,
            "reported_at": datetime.now(timezone.utc).isoformat()
        }
    
    await db.shipments.update_one(
        {"campaign_id": data.campaign_id},
        {"$set": update_data}
    )

    await insert_deal_activity(
        campaign,
        "creator",
        current_user.get('nickname', 'Creator'),
        "unboxing_uploaded" if data.unboxing_video else "receipt_confirmed",
        "Shipment receipt confirmed with unboxing video." if data.unboxing_video else "Shipment receipt confirmed."
    )
    if data.items_damaged:
        await db.deal_action_cards.insert_one({
            "id": str(uuid.uuid4()),
            "deal_id": make_deal_id(campaign),
            "campaign_id": campaign['id'],
            "type": "damage_report",
            "title": "Damaged or wrong product reported",
            "status": "open",
            "created_at": now_iso(),
            "created_by": current_user['id'],
            "message": data.dispute_reason,
            "attachment_urls": [data.unboxing_video] if data.unboxing_video else []
        })
        await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), "dispute_raised", "Damaged or wrong product reported.")
        await insert_deal_system_message(campaign, "Damaged or wrong product has been reported by the creator.")
    
    return {"message": "Shipment marked as received"}

@api_router.get("/shipment/{campaign_id}")
async def get_shipment(campaign_id: str, current_user: dict = Depends(get_current_user)):
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    role = current_user.get('role')
    is_party = (
        campaign.get('business_id') == current_user['id']
        or campaign.get('selected_creator') == current_user['id']
        or role in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]
    )
    if not is_party:
        raise HTTPException(status_code=403, detail="Not authorized to view this shipment")
    shipment = await db.shipments.find_one({"campaign_id": campaign_id}, {"_id": 0})
    if not shipment:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return shipment

# Withdrawal Routes
PLATFORM_COMMISSION_PERCENT = 25  # PRD Section 3: platform takes 25%.

async def create_payout_receipt(creator_id: str, receipt_type: str, gross_amount: float,
                                campaign_id: Optional[str] = None, reference_id: Optional[str] = None,
                                note: Optional[str] = None, tds_amount: float = 0.0,
                                penalty_amount: float = 0.0) -> dict:
    """Generate and persist a payout receipt for a creator. receipt_type is
    'earning' (escrow release) or 'withdrawal' (payout to bank/UPI). TDS and any
    late-delivery penalty are recorded as deductions (PRD 8.7/8.8)."""
    commission = round(gross_amount * PLATFORM_COMMISSION_PERCENT / 100, 2) if receipt_type == "earning" else 0.0
    tds_amount = round(float(tds_amount or 0), 2)
    penalty_amount = round(float(penalty_amount or 0), 2)
    net_amount = round(gross_amount - commission - tds_amount - penalty_amount, 2)
    seq = await db.payout_receipts.count_documents({}) + 1
    receipt = {
        "id": str(uuid.uuid4()),
        "receipt_number": f"PR-{datetime.now(timezone.utc).year}-{seq:05d}",
        "creator_id": creator_id,
        "type": receipt_type,
        "gross_amount": gross_amount,
        "commission_percent": PLATFORM_COMMISSION_PERCENT if receipt_type == "earning" else 0,
        "commission_amount": commission,
        "tds_amount": tds_amount,
        "penalty_amount": penalty_amount,
        "net_amount": net_amount,
        "currency": "INR",
        "campaign_id": campaign_id,
        "reference_id": reference_id,
        "note": note,
        "created_at": now_iso(),
    }
    await db.payout_receipts.insert_one(receipt)
    return {k: v for k, v in receipt.items() if k != "_id"}


@api_router.post("/withdrawal/request")
async def request_withdrawal(data: WithdrawalRequest, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can request withdrawals")
    
    if current_user.get('balance', 0) < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    withdrawal_doc = {
        "id": str(uuid.uuid4()),
        "user_id": current_user['id'],
        "amount": data.amount,
        "payment_method": data.payment_method,
        "account_details": data.account_details,
        "status": WithdrawalStatus.PENDING,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "processing_days": 7
    }
    
    await db.withdrawals.insert_one(withdrawal_doc)
    
    # Deduct from available balance
    await db.users.update_one(
        {"id": current_user['id']},
        {"$inc": {"balance": -data.amount}}
    )
    
    return {"message": "Withdrawal request submitted. Processing time: 7 business days"}

@api_router.get("/withdrawal/history")
async def get_withdrawal_history(current_user: dict = Depends(get_current_user)):
    withdrawals = await db.withdrawals.find({"user_id": current_user['id']}, {"_id": 0}).to_list(1000)
    return withdrawals

@api_router.get("/payouts/receipts")
async def get_payout_receipts(current_user: dict = Depends(get_current_user)):
    """All payout receipts (earnings + withdrawals) for the current creator."""
    receipts = await db.payout_receipts.find(
        {"creator_id": current_user['id']}, {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    return receipts

@api_router.get("/payouts/receipts/{receipt_id}")
async def get_payout_receipt(receipt_id: str, current_user: dict = Depends(get_current_user)):
    receipt = await db.payout_receipts.find_one({"id": receipt_id}, {"_id": 0})
    if not receipt:
        raise HTTPException(status_code=404, detail="Receipt not found")
    if receipt['creator_id'] != current_user['id'] and current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Not authorized to view this receipt")
    return receipt

@api_router.get("/payout-ranges")
async def get_payout_ranges(current_user: dict = Depends(get_current_user)):
    """Get available payout ranges for filtering campaigns."""
    ranges = await db.payout_ranges.find(
        {"is_active": True}, {"_id": 0}
    ).sort("sort_order", 1).to_list(100)
    return {
        "ranges": [
            {"key": r["key"], "label": r["label"], "min": r["min_amount"], "max": r["max_amount"]}
            for r in ranges
        ]
    }

# Admin Routes
@api_router.get("/admin/pending-profiles")
async def get_pending_profiles(current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    profiles = await db.users.find(
        {"approval_status": ApprovalStatus.PENDING, "profile_completed": True},
        {"_id": 0, "password": 0}
    ).to_list(1000)
    
    return profiles

@api_router.post("/admin/approve-profile")
async def approve_profile(data: ApprovalAction, current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Admin access required")

    status = ApprovalStatus.APPROVED if data.action == "approve" else ApprovalStatus.REJECTED
    user = await db.users.find_one({"id": data.item_id}, {"_id": 0, "role": 1, "public_creator_id": 1})
    if not user:
        raise HTTPException(status_code=404, detail="Profile not found")
    update_data = {
        "approval_status": status,
        "approval_reason": data.reason,
        "approved_at": datetime.now(timezone.utc).isoformat()
    }
    if user.get("role") == UserRole.CREATOR:
        is_approved = status == ApprovalStatus.APPROVED
        update_data["creator_directory_visible"] = is_approved
        update_data["curated_brand_visible"] = is_approved

        # Generate a unique non-sequential public creator ID on approval (e.g., UGC-aB3kQ7Xz)
        if is_approved and not user.get("public_creator_id"):
            charset = string.ascii_letters + string.digits  # a-z + A-Z + 0-9
            for _ in range(10):
                candidate = "UGC-" + ''.join(random.choices(charset, k=8))
                existing = await db.users.find_one(
                    {"public_creator_id": candidate},
                    {"_id": 1}
                )
                if not existing:
                    update_data["public_creator_id"] = candidate
                    break

    await db.users.update_one(
        {"id": data.item_id},
        {"$set": update_data}
    )

    return {"message": f"Profile {data.action}d"}

@api_router.get("/admin/pending-campaigns")
async def get_pending_campaigns(current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    campaigns = await db.campaigns.find(
        {"status": CampaignStatus.PENDING_APPROVAL},
        {"_id": 0}
    ).to_list(1000)
    
    return campaigns

@api_router.post("/admin/approve-campaign")
async def approve_campaign(data: ApprovalAction, current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")

    campaign = await db.campaigns.find_one({"id": data.item_id}, {"_id": 0, "status": 1})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if campaign.get("status") != CampaignStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail="Only pending approval campaigns can be approved or rejected"
        )
    
    status = CampaignStatus.ACTIVE if data.action == "approve" else CampaignStatus.REJECTED
    
    await db.campaigns.update_one(
        {"id": data.item_id},
        {"$set": {
            "status": status,
            "approval_reason": data.reason,
            "approved_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    # Auto-assign to campaign manager if approved
    if data.action == "approve":
        await auto_assign_campaign_manager(data.item_id)
    
    return {"message": f"Campaign {data.action}d"}

async def auto_assign_campaign_manager(campaign_id: str):
    """Auto-assign campaign to campaign manager with least campaigns"""
    # Get all campaign managers
    campaign_managers = await db.users.find(
        {"role": UserRole.CAMPAIGN_MANAGER},
        {"_id": 0, "id": 1}
    ).to_list(100)
    
    if not campaign_managers:
        return  # No campaign managers available
    
    # Count campaigns per manager
    manager_counts = []
    for manager in campaign_managers:
        count = await db.campaigns.count_documents({"assigned_manager": manager['id']})
        manager_counts.append({"manager_id": manager['id'], "count": count})
    
    # Find manager with least campaigns
    manager_counts.sort(key=lambda x: x['count'])
    selected_manager = manager_counts[0]['manager_id']
    
    # Assign campaign
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {
            "assigned_manager": selected_manager,
            "assigned_at": datetime.now(timezone.utc).isoformat()
        }}
    )

@api_router.post("/admin/assign-campaign")
async def manually_assign_campaign(campaign_id: str, manager_id: str, current_user: dict = Depends(get_current_user)):
    """Manually assign campaign to specific campaign manager"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Verify manager exists and has correct role
    manager = await db.users.find_one({"id": manager_id, "role": UserRole.CAMPAIGN_MANAGER})
    if not manager:
        raise HTTPException(status_code=404, detail="Campaign manager not found")
    
    # Count current campaigns for this manager
    count = await db.campaigns.count_documents({"assigned_manager": manager_id})
    
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {
            "assigned_manager": manager_id,
            "assigned_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {
        "message": "Campaign assigned successfully",
        "manager_nickname": manager['nickname'],
        "manager_campaign_count": count + 1
    }

@api_router.get("/admin/campaign-assignments")
async def get_campaign_assignments(current_user: dict = Depends(get_current_user)):
    """Get all campaign manager assignments"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get all campaign managers
    managers = await db.users.find(
        {"role": UserRole.CAMPAIGN_MANAGER},
        {"_id": 0, "id": 1, "nickname": 1, "email": 1}
    ).to_list(100)
    
    assignments = []
    for manager in managers:
        campaigns = await db.campaigns.find(
            {"assigned_manager": manager['id']},
            {"_id": 0, "id": 1, "title": 1, "status": 1, "created_at": 1}
        ).to_list(100)
        
        assignments.append({
            "manager_id": manager['id'],
            "manager_nickname": manager['nickname'],
            "manager_email": manager['email'],
            "campaign_count": len(campaigns),
            "campaigns": campaigns
        })
    
    return assignments

@api_router.post("/admin/manage-role")
async def manage_role(data: RoleUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    await db.users.update_one(
        {"id": data.user_id},
        {"$set": {
            "role": data.role,
            "permissions": data.permissions,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {"message": "Role updated"}

@api_router.get("/admin/stats")
async def get_admin_stats(current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    total_users = await db.users.count_documents({})
    pending_profiles = await db.users.count_documents({"approval_status": ApprovalStatus.PENDING})
    pending_campaigns = await db.campaigns.count_documents({"status": CampaignStatus.PENDING_APPROVAL})
    active_campaigns = await db.campaigns.count_documents({"status": CampaignStatus.ACTIVE})
    pending_withdrawals = await db.withdrawals.count_documents({"status": WithdrawalStatus.PENDING})
    
    return {
        "total_users": total_users,
        "pending_profiles": pending_profiles,
        "pending_campaigns": pending_campaigns,
        "active_campaigns": active_campaigns,
        "pending_withdrawals": pending_withdrawals
    }

@api_router.get("/admin/users")
async def get_all_users(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.users.find({}, {"_id": 0, "password": 0}).to_list(1000)
    return users

@api_router.get("/admin/user/{user_id}")
async def get_user_details(user_id: str, current_user: dict = Depends(get_current_user)):
    """Get detailed information for a specific user"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

@api_router.post("/admin/user/update")
async def update_user(data: UserUpdateRequest, current_user: dict = Depends(get_current_user)):
    """Update user information"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if user exists
    user = await db.users.find_one({"id": data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Build update dict with only provided fields
    update_data = {}
    if data.nickname is not None:
        update_data["nickname"] = data.nickname
    if data.email is not None:
        # Check if email is already taken by another user
        existing = await db.users.find_one({"email": data.email, "id": {"$ne": data.user_id}})
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        update_data["email"] = data.email
    if data.role is not None:
        update_data["role"] = data.role
    if data.balance is not None:
        update_data["balance"] = data.balance
    
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.users.update_one(
        {"id": data.user_id},
        {"$set": update_data}
    )
    
    return {"message": "User updated successfully"}

@api_router.post("/admin/user/ban")
async def ban_user(data: UserBanRequest, current_user: dict = Depends(get_current_user)):
    """Ban or unban a user"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if user exists
    user = await db.users.find_one({"id": data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent banning self
    if data.user_id == current_user['id']:
        raise HTTPException(status_code=400, detail="Cannot ban yourself")
    
    # Prevent banning other admins
    if user.get('role') == UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="Cannot ban admin users")
    
    update_data = {
        "banned": data.banned,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    if data.banned:
        update_data["ban_reason"] = data.ban_reason or "Violation of terms"
        update_data["banned_at"] = datetime.now(timezone.utc).isoformat()
        update_data["banned_by"] = current_user['id']
    else:
        update_data["ban_reason"] = None
        update_data["banned_at"] = None
        update_data["banned_by"] = None
    
    await db.users.update_one(
        {"id": data.user_id},
        {"$set": update_data}
    )
    
    action = "banned" if data.banned else "unbanned"
    return {"message": f"User {action} successfully"}

@api_router.get("/admin/withdrawals")
async def get_all_withdrawals(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    query = {}
    if status:
        query['status'] = status
    
    withdrawals = await db.withdrawals.find(query, {"_id": 0}).to_list(1000)
    
    # Enrich with user details
    for withdrawal in withdrawals:
        user = await db.users.find_one({"id": withdrawal['user_id']}, {"_id": 0, "nickname": 1, "email": 1})
        if user:
            withdrawal['user_nickname'] = user.get('nickname')
            withdrawal['user_email'] = user.get('email')
    
    return withdrawals

@api_router.post("/admin/withdrawals/{withdrawal_id}/approve")
async def approve_withdrawal(withdrawal_id: str, current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    withdrawal = await db.withdrawals.find_one({"id": withdrawal_id})
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    
    if withdrawal['status'] != WithdrawalStatus.PENDING:
        raise HTTPException(status_code=400, detail="Withdrawal already processed")
    
    receipt = await create_payout_receipt(
        creator_id=withdrawal['user_id'],
        receipt_type="withdrawal",
        gross_amount=float(withdrawal.get('amount') or 0),
        reference_id=withdrawal_id,
        note=f"Payout via {withdrawal.get('payment_method', 'bank/UPI')}",
    )

    await db.withdrawals.update_one(
        {"id": withdrawal_id},
        {"$set": {
            "status": WithdrawalStatus.COMPLETED,
            "approved_by": current_user['id'],
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "receipt_id": receipt['id'],
            "receipt_number": receipt['receipt_number'],
        }}
    )

    return {"message": "Withdrawal approved successfully", "receipt": receipt}

@api_router.post("/admin/withdrawals/{withdrawal_id}/reject")
async def reject_withdrawal(withdrawal_id: str, reason: str, current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    withdrawal = await db.withdrawals.find_one({"id": withdrawal_id})
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    
    if withdrawal['status'] != WithdrawalStatus.PENDING:
        raise HTTPException(status_code=400, detail="Withdrawal already processed")
    
    await db.withdrawals.update_one(
        {"id": withdrawal_id},
        {"$set": {
            "status": WithdrawalStatus.REJECTED,
            "rejected_by": current_user['id'],
            "rejected_at": datetime.now(timezone.utc).isoformat(),
            "rejection_reason": reason
        }}
    )
    
    # Refund the amount back to user's balance
    await db.users.update_one(
        {"id": withdrawal['user_id']},
        {"$inc": {"balance": withdrawal['amount']}}
    )
    
    return {"message": "Withdrawal rejected and amount refunded"}

@api_router.post("/upload/file")
async def upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Upload files for profiles, portfolios, and chat attachments."""
    # Create uploads directory if it doesn't exist
    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))
    upload_dir.mkdir(exist_ok=True)

    # Generate unique filename
    file_ext = Path(file.filename).suffix
    unique_filename = f"{current_user['id']}_{uuid.uuid4()}{file_ext}"
    file_path = upload_dir / unique_filename
    
    # Save file
    try:
        content = await file.read()
        duration_seconds = get_video_duration_seconds(content, file.filename, file.content_type)
        kind = validate_upload_payload(file.content_type, file.filename, len(content), duration_seconds)
        if kind == "image":
            scan = scan_image_for_contact_info(content, file.filename)
            if not scan.get("safe", True):
                await log_chat_violation(current_user, None, file.filename or "image_upload", scan.get("violations", []), "image_ocr")
                raise HTTPException(status_code=400, detail=CONTACT_INFO_BLOCK_DETAIL)
        with open(file_path, 'wb') as f:
            f.write(content)
        
        file_url = f"/uploads/{unique_filename}"
        metadata = {
            "id": str(uuid.uuid4()),
            "file_url": file_url,
            "filename": unique_filename,
            "original_filename": file.filename,
            "content_type": file.content_type,
            "size": len(content),
            "kind": kind,
            "duration_seconds": duration_seconds,
            "uploaded_by": current_user["id"],
            "created_at": now_iso()
        }
        await db.uploaded_files.insert_one(metadata)
        return {key: value for key, value in metadata.items() if key != "_id"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")

@api_router.options("/image/{filename}")
async def image_options(filename: str):
    """Handle CORS preflight requests for images"""
    return {
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "Content-Type, Range",
            "Access-Control-Max-Age": "86400"
        }
    }

@api_router.get("/image/{filename}")
async def get_image(filename: str):
    """Serve images from uploads directory with proper CORS headers"""
    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))

    # Security: Prevent directory traversal
    if ".." in filename or filename.startswith("/"):
        raise HTTPException(status_code=403, detail="Access denied")

    file_path = upload_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Image not found")

    if not file_path.is_file():
        raise HTTPException(status_code=403, detail="Access denied")

    # Determine content type
    suffix = file_path.suffix.lower()
    content_types = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
        '.mp4': 'video/mp4',
        '.webm': 'video/webm',
        '.pdf': 'application/pdf'
    }

    content_type = content_types.get(suffix, 'application/octet-stream')

    return FileResponse(
        path=file_path,
        media_type=content_type,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "Content-Type, Range",
            "Access-Control-Max-Age": "86400",
            "Cache-Control": "public, max-age=31536000, immutable"
        }
    )

@api_router.post("/uploads")
async def upload_campaign_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Upload product/reference media for campaigns. Returns public file URL."""
    allowed_types = {
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
        'video/mp4', 'video/quicktime', 'video/webm',
        'application/pdf'
    }
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"File type {file.content_type} not allowed")

    content = await file.read()
    # PRD 8.3 upload limits: 500MB video, 25MB image, 2GB raw footage, 25MB other.
    ctype = file.content_type or ""
    if ctype.startswith("video/"):
        limit_mb = 2048 if "raw" in (file.filename or "").lower() else 500
    elif ctype.startswith("image/"):
        limit_mb = 25
    else:
        limit_mb = 25
    if len(content) > limit_mb * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File size exceeds {limit_mb}MB limit")

    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))
    campaigns_upload_dir = upload_dir / "campaigns"
    campaigns_upload_dir.mkdir(parents=True, exist_ok=True)

    file_ext = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = campaigns_upload_dir / unique_filename

    try:
        with open(file_path, 'wb') as f:
            f.write(content)
        file_url = f"/uploads/campaigns/{unique_filename}"
        file_doc = {
            "id": str(uuid.uuid4()),
            "file_url": file_url,
            "filename": file.filename,
            "content_type": file.content_type,
            "size": len(content),
            "kind": "image" if file.content_type.startswith("image/") else "video" if file.content_type.startswith("video/") else "pdf",
            "uploaded_by": current_user['id'],
            "created_at": now_iso()
        }
        await db.uploaded_files.insert_one(file_doc)
        return {"file_url": file_url, "filename": file.filename, "content_type": file.content_type, "size": len(content)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")

@api_router.post("/admin/users/{user_id}/update-role")
async def update_user_role(user_id: str, role: UserRole, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only admins can update user roles")
    
    # Validate the role change
    valid_staff_roles = [UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF, UserRole.ADMIN]
    
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow changing creator/business to staff roles and vice versa
    if user['role'] in [UserRole.CREATOR, UserRole.BUSINESS] and role in valid_staff_roles:
        raise HTTPException(status_code=400, detail="Cannot change creator/business to staff role")
    
    if user['role'] in valid_staff_roles and role in [UserRole.CREATOR, UserRole.BUSINESS]:
        raise HTTPException(status_code=400, detail="Cannot change staff to creator/business role")
    
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"role": role}}
    )
    
    return {"message": f"User role updated to {role}"}

# Payment Gateway Management Endpoints
@api_router.post("/admin/payment-gateway")
async def create_payment_gateway(data: PaymentGatewayConfig, current_user: dict = Depends(get_current_user)):
    """Create or update payment gateway configuration"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if gateway already exists
    existing = await db.payment_gateways.find_one({"gateway_name": data.gateway_name})
    
    if existing:
        # Update existing
        await db.payment_gateways.update_one(
            {"gateway_name": data.gateway_name},
            {"$set": {
                "key_id": data.key_id,
                "key_secret": data.key_secret,
                "enabled": data.enabled,
                "is_default": data.is_default,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
    else:
        # Create new
        gateway_doc = {
            "id": str(uuid.uuid4()),
            "gateway_name": data.gateway_name,
            "key_id": data.key_id,
            "key_secret": data.key_secret,
            "enabled": data.enabled,
            "is_default": data.is_default,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        await db.payment_gateways.insert_one(gateway_doc)
    
    # If this is set as default, unset others
    if data.is_default:
        await db.payment_gateways.update_many(
            {"gateway_name": {"$ne": data.gateway_name}},
            {"$set": {"is_default": False}}
        )
    
    return {"message": f"Payment gateway {data.gateway_name} configured successfully"}

@api_router.get("/admin/payment-gateways")
async def get_payment_gateways(current_user: dict = Depends(get_current_user)):
    """Get all payment gateway configurations"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    gateways = await db.payment_gateways.find({}, {"_id": 0, "key_secret": 0}).to_list(100)
    return gateways

@api_router.patch("/admin/payment-gateway/{gateway_name}")
async def update_payment_gateway(
    gateway_name: str,
    data: PaymentGatewayUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update payment gateway settings"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    gateway = await db.payment_gateways.find_one({"gateway_name": gateway_name})
    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")
    
    update_data = {"updated_at": datetime.now(timezone.utc).isoformat()}
    if data.enabled is not None:
        update_data["enabled"] = data.enabled
    if data.is_default is not None:
        update_data["is_default"] = data.is_default
        # If setting as default, unset others
        if data.is_default:
            await db.payment_gateways.update_many(
                {"gateway_name": {"$ne": gateway_name}},
                {"$set": {"is_default": False}}
            )
    
    await db.payment_gateways.update_one(
        {"gateway_name": gateway_name},
        {"$set": update_data}
    )
    
    return {"message": f"Gateway {gateway_name} updated successfully"}

@api_router.delete("/admin/payment-gateway/{gateway_name}")
async def delete_payment_gateway(gateway_name: str, current_user: dict = Depends(get_current_user)):
    """Delete payment gateway configuration"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.payment_gateways.delete_one({"gateway_name": gateway_name})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Gateway not found")
    
    return {"message": f"Gateway {gateway_name} deleted successfully"}

# Payment Processing Endpoints
async def get_active_gateway(gateway_name: Optional[str] = None):
    """Get active payment gateway configuration"""
    if gateway_name:
        gateway = await db.payment_gateways.find_one({
            "gateway_name": gateway_name,
            "enabled": True
        })
    else:
        # Get default gateway
        gateway = await db.payment_gateways.find_one({
            "enabled": True,
            "is_default": True
        })
    
    if not gateway:
        raise HTTPException(status_code=400, detail="No active payment gateway configured")
    
    return gateway

@api_router.post("/payments/create-order")
async def create_payment_order(
    data: PaymentOrderCreate,
    gateway_name: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Create a payment order"""
    try:
        gateway = await get_active_gateway(gateway_name)
        
        # Create order based on gateway
        if gateway['gateway_name'] == 'razorpay':
            try:
                client = razorpay.Client(auth=(gateway['key_id'], gateway['key_secret']))
                
                # Create Razorpay order
                order_data = {
                    "amount": int(data.amount * 100),  # Convert to paise
                    "currency": data.currency,
                    "notes": data.notes or {}
                }
                razorpay_order = client.order.create(data=order_data)
            except Exception as razorpay_error:
                # Handle test credentials or authentication errors by creating mock order
                if "Authentication failed" in str(razorpay_error) or "test" in gateway['key_id'].lower():
                    razorpay_order = {
                        "id": f"order_test_{str(uuid.uuid4())[:8]}",
                        "amount": int(data.amount * 100),
                        "currency": data.currency,
                        "status": "created"
                    }
                else:
                    raise razorpay_error
            
            # Store transaction
            transaction_doc = {
                "id": str(uuid.uuid4()),
                "gateway": "razorpay",
                "gateway_order_id": razorpay_order['id'],
                "amount": data.amount,
                "currency": data.currency,
                "status": "created",
                "customer_id": data.customer_id,
                "customer_email": data.customer_email,
                "customer_phone": data.customer_phone,
                "customer_name": data.customer_name,
                "campaign_id": data.campaign_id,
                "user_id": current_user['id'],
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await db.payment_transactions.insert_one(transaction_doc)
            
            return {
                "success": True,
                "gateway": "razorpay",
                "order_id": razorpay_order['id'],
                "amount": data.amount,
                "currency": data.currency,
                "key_id": gateway['key_id']
            }
        
        elif gateway['gateway_name'] == 'cashfree':
            # Initialize Cashfree (placeholder - would need full SDK implementation)
            # For now, return structure for frontend
            order_id = f"cf_{str(uuid.uuid4())[:8]}"
            
            transaction_doc = {
                "id": str(uuid.uuid4()),
                "gateway": "cashfree",
                "gateway_order_id": order_id,
                "amount": data.amount,
                "currency": data.currency,
                "status": "created",
                "customer_id": data.customer_id,
                "customer_email": data.customer_email,
                "customer_phone": data.customer_phone,
                "customer_name": data.customer_name,
                "campaign_id": data.campaign_id,
                "user_id": current_user['id'],
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await db.payment_transactions.insert_one(transaction_doc)
            
            return {
                "success": True,
                "gateway": "cashfree",
                "order_id": order_id,
                "amount": data.amount,
                "currency": data.currency
            }
        
        else:
            raise HTTPException(status_code=400, detail="Unsupported gateway")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class PaymentVerifyRequest(BaseModel):
    razorpay_order_id: Optional[str] = None
    razorpay_payment_id: Optional[str] = None
    razorpay_signature: Optional[str] = None
    cashfree_order_id: Optional[str] = None
    cashfree_payment_id: Optional[str] = None

@api_router.post("/payments/verify")
async def verify_payment(
    data: PaymentVerifyRequest,
    current_user: dict = Depends(get_current_user)
):
    """Verify payment after completion"""
    try:
        # Determine gateway and order ID from request data
        if data.razorpay_order_id:
            gateway_order_id = data.razorpay_order_id
            gateway_payment_id = data.razorpay_payment_id
            gateway_signature = data.razorpay_signature
        elif data.cashfree_order_id:
            gateway_order_id = data.cashfree_order_id
            gateway_payment_id = data.cashfree_payment_id
            gateway_signature = None
        else:
            raise HTTPException(status_code=400, detail="Missing payment verification data")
        
        # Get transaction
        transaction = await db.payment_transactions.find_one({"gateway_order_id": gateway_order_id})
        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")
        if transaction.get("user_id") != current_user.get("id") and current_user.get("role") not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
            raise HTTPException(status_code=403, detail="Not authorized for this transaction")
        
        # Get gateway config
        gateway = await db.payment_gateways.find_one({"gateway_name": transaction['gateway']})
        if not gateway:
            raise HTTPException(status_code=400, detail="Gateway configuration not found")
        
        if transaction['gateway'] == 'razorpay':
            try:
                # Verify Razorpay signature
                client = razorpay.Client(auth=(gateway['key_id'], gateway['key_secret']))
                
                # Verify signature
                params_dict = {
                    'razorpay_order_id': gateway_order_id,
                    'razorpay_payment_id': gateway_payment_id,
                    'razorpay_signature': gateway_signature
                }
                
                client.utility.verify_payment_signature(params_dict)
                
                await db.payment_transactions.update_one(
                    {"id": transaction["id"]},
                    {"$set": {"gateway_signature": gateway_signature}}
                )
                credit_result = await credit_wallet_for_successful_transaction(transaction, gateway_payment_id)
                
                return {
                    "success": True,
                    "message": "Payment verified successfully",
                    "transaction_id": transaction['id'],
                    "transaction": credit_result["transaction"],
                    "wallet_balance": credit_result["wallet_balance"],
                }
            except Exception as verify_error:
                # Handle test credentials or verification errors
                if "Authentication failed" in str(verify_error) or "test" in gateway['key_id'].lower():
                    raise HTTPException(status_code=400, detail="Invalid payment signature (test mode)")
                else:
                    raise HTTPException(status_code=400, detail="Payment verification failed")
            
            except razorpay.errors.SignatureVerificationError:
                await db.payment_transactions.update_one(
                    {"gateway_order_id": gateway_order_id},
                    {"$set": {"status": "failed", "error": "Signature verification failed"}}
                )
                raise HTTPException(status_code=400, detail="Invalid payment signature")
        
        else:
            # Cashfree verification would go here
            credit_result = await credit_wallet_for_successful_transaction(transaction, gateway_payment_id)
            
            return {
                "success": True,
                "message": "Payment verified successfully",
                "transaction_id": transaction['id'],
                "transaction": credit_result["transaction"],
                "wallet_balance": credit_result["wallet_balance"],
            }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/admin/payment-transactions")
async def get_payment_transactions(current_user: dict = Depends(get_current_user)):
    """Get all payment transactions"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    transactions = await db.payment_transactions.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return transactions

@api_router.get("/payments/my-transactions")
async def get_my_transactions(current_user: dict = Depends(get_current_user)):
    """Get current user's payment transactions"""
    transactions = await db.payment_transactions.find(
        {"user_id": current_user['id']},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    return transactions

# Razorpay Webhook
@api_router.post("/webhooks/razorpay")
async def razorpay_webhook(request: dict):
    """Handle Razorpay webhook notifications"""
    try:
        # Get webhook secret from gateway config
        gateway = await db.payment_gateways.find_one({"gateway_name": "razorpay"})
        if not gateway:
            raise HTTPException(status_code=400, detail="Gateway not configured")
        
        # Verify webhook signature (simplified - production needs proper verification)
        event = request.get("event")
        payload = request.get("payload")
        
        if event == "payment.captured":
            payment = payload.get("payment", {}).get("entity", {})
            order_id = payment.get("order_id")
            payment_id = payment.get("id")
            transaction = await db.payment_transactions.find_one({"gateway_order_id": order_id})
            if transaction:
                await credit_wallet_for_successful_transaction(transaction, payment_id)
                await db.payment_transactions.update_one(
                    {"id": transaction["id"]},
                    {"$set": {"webhook_received": True}}
                )
        
        elif event == "payment.failed":
            payment = payload.get("payment", {}).get("entity", {})
            order_id = payment.get("order_id")
            
            await db.payment_transactions.update_one(
                {"gateway_order_id": order_id},
                {"$set": {
                    "status": "failed",
                    "webhook_received": True,
                    "error": payment.get("error_description")
                }}
            )
        
        return {"status": "ok"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Cashfree Webhook
@api_router.post("/webhooks/cashfree")
async def cashfree_webhook(request: dict):
    """Handle Cashfree webhook notifications"""
    try:
        # Implement Cashfree webhook handling
        event_type = request.get("type")
        data = request.get("data", {})
        
        if event_type == "PAYMENT_SUCCESS_WEBHOOK":
            order = data.get("order", {})
            payment = data.get("payment", {})
            
            order_id = order.get("order_id")
            payment_id = payment.get("cf_payment_id")
            transaction = await db.payment_transactions.find_one({"gateway_order_id": order_id})
            if transaction:
                await credit_wallet_for_successful_transaction(transaction, payment_id)
                await db.payment_transactions.update_one(
                    {"id": transaction["id"]},
                    {"$set": {"webhook_received": True}}
                )
        
        elif event_type == "PAYMENT_FAILED_WEBHOOK":
            order = data.get("order", {})
            order_id = order.get("order_id")
            
            await db.payment_transactions.update_one(
                {"gateway_order_id": order_id},
                {"$set": {
                    "status": "failed",
                    "webhook_received": True
                }}
            )
        
        return {"status": "ok"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Notification Gateway Management Endpoints
@api_router.post("/admin/notification-gateway")
async def create_notification_gateway(data: NotificationGatewayConfig, current_user: dict = Depends(get_current_user)):
    """Create or update notification gateway configuration"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    gateway_id = f"{data.gateway_type}_{data.provider}"
    existing = await db.notification_gateways.find_one({"id": gateway_id})
    
    if existing:
        await db.notification_gateways.update_one(
            {"id": gateway_id},
            {"$set": {
                "config": data.config,
                "enabled": data.enabled,
                "is_default": data.is_default,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
    else:
        gateway_doc = {
            "id": gateway_id,
            "gateway_type": data.gateway_type,
            "provider": data.provider,
            "config": data.config,
            "enabled": data.enabled,
            "is_default": data.is_default,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        await db.notification_gateways.insert_one(gateway_doc)
    
    if data.is_default:
        await db.notification_gateways.update_many(
            {"id": {"$ne": gateway_id}, "gateway_type": data.gateway_type},
            {"$set": {"is_default": False}}
        )
    
    return {"message": f"Notification gateway {data.provider} configured successfully"}

@api_router.get("/admin/notification-gateways")
async def get_notification_gateways(current_user: dict = Depends(get_current_user)):
    """Get all notification gateway configurations"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    gateways = await db.notification_gateways.find({}, {"_id": 0}).to_list(100)
    
    # Mask sensitive configuration
    for gateway in gateways:
        if 'config' in gateway:
            masked_config = {}
            for key, value in gateway['config'].items():
                if any(sensitive in key.lower() for sensitive in ['secret', 'token', 'password']):
                    masked_config[key] = '***' + value[-4:] if len(value) > 4 else '****'
                else:
                    masked_config[key] = value
            gateway['config_masked'] = masked_config
    
    return gateways

@api_router.patch("/admin/notification-gateway/{gateway_id}")
async def update_notification_gateway(gateway_id: str, enabled: bool, current_user: dict = Depends(get_current_user)):
    """Toggle notification gateway enabled status"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    gateway = await db.notification_gateways.find_one({"id": gateway_id})
    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")
    
    await db.notification_gateways.update_one(
        {"id": gateway_id},
        {"$set": {"enabled": enabled, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"message": f"Gateway {gateway_id} updated"}

@api_router.delete("/admin/notification-gateway/{gateway_id}")
async def delete_notification_gateway(gateway_id: str, current_user: dict = Depends(get_current_user)):
    """Delete notification gateway"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.notification_gateways.delete_one({"id": gateway_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Gateway not found")
    
    return {"message": f"Gateway {gateway_id} deleted"}

@api_router.post("/notifications/send")
async def send_notification(data: SendNotificationRequest, current_user: dict = Depends(get_current_user)):
    """Send notification via email or SMS"""
    try:
        if data.notification_type == 'email':
            gateway = await db.notification_gateways.find_one({
                "gateway_type": "email",
                "enabled": True,
                "is_default": True
            })
            
            if not gateway:
                raise HTTPException(status_code=400, detail="No email gateway configured")
            
            if gateway['provider'] == 'aws_ses':
                config = gateway['config']
                ses_client = boto3.client(
                    'ses',
                    region_name=config.get('region', 'us-east-1'),
                    aws_access_key_id=config.get('access_key_id'),
                    aws_secret_access_key=config.get('secret_access_key')
                )
                
                response = ses_client.send_email(
                    Source=config.get('sender_email'),
                    Destination={'ToAddresses': [data.recipient]},
                    Message={
                        'Subject': {'Data': data.subject or 'Notification', 'Charset': 'UTF-8'},
                        'Body': {'Text': {'Data': data.message, 'Charset': 'UTF-8'}}
                    }
                )
                
                await db.notification_logs.insert_one({
                    "id": str(uuid.uuid4()),
                    "type": "email",
                    "provider": "aws_ses",
                    "recipient": data.recipient,
                    "subject": data.subject,
                    "message": data.message,
                    "status": "sent",
                    "message_id": response['MessageId'],
                    "user_id": current_user['id'],
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
                
                return {"success": True, "message_id": response['MessageId']}
        
        elif data.notification_type == 'sms':
            gateway = await db.notification_gateways.find_one({
                "gateway_type": "sms",
                "enabled": True,
                "is_default": True
            })
            
            if not gateway:
                raise HTTPException(status_code=400, detail="No SMS gateway configured")
            
            if gateway['provider'] == 'twilio':
                config = gateway['config']
                twilio_client = TwilioClient(
                    config.get('account_sid'),
                    config.get('auth_token')
                )
                
                message = twilio_client.messages.create(
                    body=data.message,
                    from_=config.get('phone_number'),
                    to=data.recipient
                )
                
                await db.notification_logs.insert_one({
                    "id": str(uuid.uuid4()),
                    "type": "sms",
                    "provider": "twilio",
                    "recipient": data.recipient,
                    "message": data.message,
                    "status": "sent",
                    "message_id": message.sid,
                    "user_id": current_user['id'],
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
                
                return {"success": True, "message_id": message.sid}
        
        else:
            raise HTTPException(status_code=400, detail="Invalid notification type")
    
    except BotoClientError as e:
        raise HTTPException(status_code=500, detail=f"AWS SES Error: {str(e)}")
    except TwilioRestException as e:
        raise HTTPException(status_code=500, detail=f"Twilio Error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/admin/notification-logs")
async def get_notification_logs(current_user: dict = Depends(get_current_user)):
    """Get notification sending logs"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = await db.notification_logs.find({}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100)
    return logs

# In-App Notification System
@api_router.get("/notifications/my-notifications")
async def get_my_notifications(current_user: dict = Depends(get_current_user)):
    """Get current user's in-app notifications"""
    notifications = await db.in_app_notifications.find(
        {"user_id": current_user['id']},
        {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)
    return notifications

@api_router.get("/notifications/unread-count")
async def get_unread_count(current_user: dict = Depends(get_current_user)):
    """Get count of unread notifications"""
    count = await db.in_app_notifications.count_documents({
        "user_id": current_user['id'],
        "read": False
    })
    return {"count": count}

@api_router.patch("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: dict = Depends(get_current_user)):
    """Mark a notification as read"""
    result = await db.in_app_notifications.update_one(
        {"id": notification_id, "user_id": current_user['id']},
        {"$set": {"read": True, "read_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    return {"message": "Notification marked as read"}

@api_router.post("/notifications/mark-all-read")
async def mark_all_read(current_user: dict = Depends(get_current_user)):
    """Mark all notifications as read"""
    await db.in_app_notifications.update_many(
        {"user_id": current_user['id'], "read": False},
        {"$set": {"read": True, "read_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"message": "All notifications marked as read"}

@api_router.post("/admin/broadcast-notification")
async def broadcast_notification(data: BroadcastNotification, current_user: dict = Depends(get_current_user)):
    """Broadcast in-app notification to multiple users"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Determine target users
    target_users = []
    
    if data.target_user_ids:
        # Specific users
        target_users = await db.users.find(
            {"id": {"$in": data.target_user_ids}},
            {"_id": 0, "id": 1, "nickname": 1}
        ).to_list(1000)
    elif data.target_roles:
        # Users with specific roles
        target_users = await db.users.find(
            {"role": {"$in": data.target_roles}},
            {"_id": 0, "id": 1, "nickname": 1}
        ).to_list(1000)
    else:
        # All users
        target_users = await db.users.find(
            {},
            {"_id": 0, "id": 1, "nickname": 1}
        ).to_list(10000)
    
    # Create notifications for all target users
    notifications = []
    for user in target_users:
        notification_doc = {
            "id": str(uuid.uuid4()),
            "user_id": user['id'],
            "title": data.title,
            "message": data.message,
            "type": data.type,
            "link": data.link,
            "read": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": current_user['id']
        }
        notifications.append(notification_doc)
    
    if notifications:
        await db.in_app_notifications.insert_many(notifications)
    
    return {
        "message": f"Notification sent to {len(notifications)} users",
        "recipient_count": len(notifications)
    }

@api_router.post("/notifications/create")
async def create_notification(
    user_id: str,
    notification: InAppNotification,
    current_user: dict = Depends(get_current_user)
):
    """Create a notification for a specific user (internal use)"""
    notification_doc = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "title": notification.title,
        "message": notification.message,
        "type": notification.type,
        "link": notification.link,
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": current_user['id']
    }
    
    await db.in_app_notifications.insert_one(notification_doc)
    return {"message": "Notification created", "notification_id": notification_doc['id']}

# Staff Management
@api_router.post("/admin/staff/create")
async def create_staff(data: StaffCreate, current_user: dict = Depends(get_current_user)):
    """Create staff member (campaign manager or support staff)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if data.role not in [UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=400, detail="Can only create campaign manager or support staff")
    
    # Check if email already exists
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    
    if data.password:
        # Direct creation with password
        user_doc = {
            "id": user_id,
            "email": data.email,
            "nickname": data.nickname,
            "password": hash_password(data.password),
            "role": data.role,
            "permissions": data.permissions,
            "approval_status": "approved",
            "balance": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": current_user['id'],
            "banned": False
        }
        await db.users.insert_one(user_doc)
        return {"message": "Staff created successfully", "user_id": user_id}
    else:
        # Create invite token for email invitation
        invite_token = str(uuid.uuid4())
        user_doc = {
            "id": user_id,
            "email": data.email,
            "nickname": data.nickname,
            "role": data.role,
            "permissions": data.permissions,
            "approval_status": "pending_invite",
            "invite_token": invite_token,
            "balance": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": current_user['id'],
            "banned": False
        }
        await db.users.insert_one(user_doc)
        
        # TODO: Send invitation email
        return {
            "message": "Invitation created. Send this link to the staff member.",
            "invite_link": f"/accept-invite/{invite_token}",
            "user_id": user_id
        }

@api_router.get("/admin/staff")
async def get_all_staff(current_user: dict = Depends(get_current_user)):
    """Get all staff members"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    staff = await db.users.find(
        {"role": {"$in": [UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]}},
        {"_id": 0, "password": 0, "invite_token": 0}
    ).to_list(1000)
    return staff

@api_router.patch("/admin/staff/permissions")
async def update_staff_permissions(data: PermissionUpdate, current_user: dict = Depends(get_current_user)):
    """Update staff permissions"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = await db.users.find_one({"id": data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user['role'] not in [UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=400, detail="Can only update staff permissions")
    
    await db.users.update_one(
        {"id": data.user_id},
        {"$set": {"permissions": data.permissions, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"message": "Permissions updated successfully"}

# Payout Ranges Management
@api_router.get("/admin/payout-ranges")
async def admin_get_payout_ranges(current_user: dict = Depends(get_current_user)):
    """Get all payout ranges (including inactive) for admin management."""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    ranges = await db.payout_ranges.find({}, {"_id": 0}).sort("sort_order", 1).to_list(100)
    return {"ranges": ranges}

@api_router.post("/admin/payout-ranges")
async def admin_create_payout_range(data: PayoutRangeCreate, current_user: dict = Depends(get_current_user)):
    """Create a new payout range."""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    if data.min_amount >= data.max_amount:
        raise HTTPException(status_code=400, detail="min_amount must be less than max_amount")
    existing = await db.payout_ranges.find_one({"key": data.key})
    if existing:
        raise HTTPException(status_code=400, detail=f"Range with key '{data.key}' already exists")
    doc = {
        "id": str(uuid.uuid4()),
        "is_active": True,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        **data.dict()
    }
    if doc.get("sort_order") is None:
        count = await db.payout_ranges.count_documents({})
        doc["sort_order"] = count
    await db.payout_ranges.insert_one(doc)
    return doc

@api_router.put("/admin/payout-ranges/{range_id}")
async def admin_update_payout_range(range_id: str, data: PayoutRangeUpdate, current_user: dict = Depends(get_current_user)):
    """Update a payout range."""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    existing = await db.payout_ranges.find_one({"id": range_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Payout range not found")
    update = data.dict(exclude_unset=True)
    if not update:
        raise HTTPException(status_code=400, detail="No fields to update")
    min_val = update.get("min_amount", existing["min_amount"])
    max_val = update.get("max_amount", existing["max_amount"])
    if min_val >= max_val:
        raise HTTPException(status_code=400, detail="min_amount must be less than max_amount")
    update["updated_at"] = now_iso()
    await db.payout_ranges.update_one({"id": range_id}, {"$set": update})
    updated = await db.payout_ranges.find_one({"id": range_id}, {"_id": 0})
    return updated

@api_router.delete("/admin/payout-ranges/{range_id}")
async def admin_delete_payout_range(range_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a payout range."""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    result = await db.payout_ranges.delete_one({"id": range_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Payout range not found")
    return {"message": "Payout range deleted"}

# Analytics Dashboard
@api_router.get("/admin/analytics")
async def get_analytics(current_user: dict = Depends(get_current_user)):
    """Get platform analytics"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Total creators
    total_creators = await db.users.count_documents({"role": UserRole.CREATOR})
    
    # Total businesses
    total_businesses = await db.users.count_documents({"role": UserRole.BUSINESS})
    
    # New creators (last 30 days)
    thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    new_creators = await db.users.count_documents({
        "role": UserRole.CREATOR,
        "created_at": {"$gte": thirty_days_ago}
    })
    
    # New businesses (last 30 days)
    new_businesses = await db.users.count_documents({
        "role": UserRole.BUSINESS,
        "created_at": {"$gte": thirty_days_ago}
    })
    
    # Calculate total earnings (20% commission from all withdrawals)
    withdrawals = await db.withdrawals.find({"status": "approved"}, {"_id": 0, "amount": 1}).to_list(10000)
    total_creator_earnings = sum(w['amount'] for w in withdrawals)
    platform_commission = total_creator_earnings * 0.20
    
    # Total campaigns
    total_campaigns = await db.campaigns.count_documents({})
    active_campaigns = await db.campaigns.count_documents({"status": "active"})
    
    return {
        "total_creators": total_creators,
        "total_businesses": total_businesses,
        "new_creators": new_creators,
        "new_businesses": new_businesses,
        "total_creator_earnings": round(total_creator_earnings, 2),
        "platform_commission": round(platform_commission, 2),
        "commission_rate": 0.20,
        "total_campaigns": total_campaigns,
        "active_campaigns": active_campaigns
    }

# Withdrawal Export
@api_router.get("/admin/withdrawals/export")
async def export_withdrawals(current_user: dict = Depends(get_current_user)):
    """Export withdrawal requests to CSV"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    withdrawals = await db.withdrawals.find({}, {"_id": 0}).to_list(10000)
    
    # Enrich with user bank details
    for withdrawal in withdrawals:
        user = await db.users.find_one(
            {"id": withdrawal['user_id']},
            {"_id": 0, "bank_details": 1, "upi_id": 1, "nickname": 1, "email": 1}
        )
        if user:
            withdrawal['creator_name'] = user.get('nickname', 'N/A')
            withdrawal['creator_email'] = user.get('email', 'N/A')
            withdrawal['bank_name'] = user.get('bank_details', {}).get('bank_name', 'N/A')
            withdrawal['account_number'] = user.get('bank_details', {}).get('account_number', 'N/A')
            withdrawal['ifsc_code'] = user.get('bank_details', {}).get('ifsc_code', 'N/A')
            withdrawal['account_holder'] = user.get('bank_details', {}).get('account_holder_name', 'N/A')
            withdrawal['upi_id'] = user.get('upi_id', 'N/A')
    
    # Generate CSV
    import csv
    from io import StringIO
    
    output = StringIO()
    if withdrawals:
        fieldnames = [
            'id', 'creator_name', 'creator_email', 'amount', 'status',
            'bank_name', 'account_number', 'ifsc_code', 'account_holder',
            'upi_id', 'requested_at', 'processed_at'
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(withdrawals)
    
    csv_content = output.getvalue()
    
    from fastapi.responses import Response
    return Response(
        content=csv_content,
        media_type='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=withdrawals_{datetime.now().strftime("%Y%m%d")}.csv'
        }
    )

@api_router.get("/admin/creator/{creator_id}/financial-details")
async def get_creator_financial_details(creator_id: str, current_user: dict = Depends(get_current_user)):
    """Get user's bank account and UPI details (admin access)"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = await db.users.find_one(
        {"id": creator_id},
        {"_id": 0, "bank_details": 1, "upi_id": 1, "nickname": 1, "email": 1, "balance": 1, "role": 1}
    )
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "nickname": user.get('nickname'),
        "email": user.get('email'),
        "role": user.get('role'),
        "balance": user.get('balance', 0),
        "bank_details": user.get('bank_details', {}),
        "upi_id": user.get('upi_id', None)
    }

app.include_router(categories_router)
app.include_router(applications_router)
app.include_router(gigs_router)
app.include_router(api_router)

from starlette.middleware.base import BaseHTTPMiddleware

class UploadsCORSMiddleware(BaseHTTPMiddleware):
    """Add CORS headers to uploads directory responses"""
    async def dispatch(self, request, call_next):
        if request.url.path.startswith("/uploads"):
            response = await call_next(request)
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
            response.headers["Cache-Control"] = "public, max-age=31536000"
            return response
        return await call_next(request)

app.add_middleware(UploadsCORSMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for uploads
upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))
upload_dir.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(upload_dir)), name="uploads")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_initialization():
    """Initialize default data collections."""
    # Seed payout ranges
    count = await db.payout_ranges.count_documents({})
    if count == 0:
        defaults = [
            {"key": "1k",      "label": "Rs. 1k",         "min_amount": 0,     "max_amount": 1000,  "sort_order": 0},
            {"key": "1k-2.5k", "label": "Rs. 1k - 2.5k",  "min_amount": 1001,  "max_amount": 2500,  "sort_order": 1},
            {"key": "2.5k-5k", "label": "Rs. 2.5k - 5k",  "min_amount": 2501,  "max_amount": 5000,  "sort_order": 2},
            {"key": "5k-10k",  "label": "Rs. 5k - 10k",   "min_amount": 5001,  "max_amount": 10000, "sort_order": 3},
            {"key": "10k-20k", "label": "Rs. 10k - 20k",  "min_amount": 10001, "max_amount": 20000, "sort_order": 4},
        ]
        now = datetime.now(timezone.utc).isoformat()
        docs = [
            {"id": str(uuid.uuid4()), "is_active": True, "created_at": now, "updated_at": now, **d}
            for d in defaults
        ]
        await db.payout_ranges.insert_many(docs)

    # Seed categories
    await seed_categories()

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
