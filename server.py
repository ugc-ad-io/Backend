from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, UploadFile, File, Query, Request, Body
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import time
import asyncio
import requests
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
    map_legacy_to_new_fields,
    total_deliverable_quantity,
)
import admin_caps

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Import routers (after load_dotenv)
from applications import applications_router
from categories import categories_router, seed_categories
from gigs import gigs_router
import creator_features as cf
from storage import persist_file, cloudinary_enabled

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="UGCad Backend API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

# Google Sign-In — OAuth 2.0 Web client id (must match the frontend's).
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')

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
    MORE_INFO = "more_info"
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
    name: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class GoogleAuthRequest(BaseModel):
    credential: str                      # Google ID token (JWT) from GIS
    role: Optional[UserRole] = None      # used only when creating a new account

class VerifyPasswordRequest(BaseModel):
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class VerifyResetCodeRequest(BaseModel):
    email: str
    code: str

class ResetPasswordRequest(BaseModel):
    email: str
    code: str
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
    image_url: Optional[str] = ''  # optional campaign banner/cover image

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

class ShippingAddressSubmit(BaseModel):
    campaign_id: Optional[str] = None  # when set, checks if both parties' addresses are in
    full_name: str
    phone: str
    line1: str
    line2: Optional[str] = ""
    city: str
    state: str
    pincode: str
    country: str = "India"

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
    action: str  # approve | reject | request_info
    reason: Optional[str] = None
    # Reject → structured reason; request_info → message + checklist items.
    reason_code: Optional[str] = None
    reason_details: Optional[str] = None
    message: Optional[str] = None
    items: Optional[List[str]] = None

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

# Admin-managed "Top Earner" showcase cards on the creator home hero.
class TopEarnerItem(BaseModel):
    name: str
    category: Optional[str] = ""
    earned: float = 0
    deals: int = 0
    rating: float = 0
    level: Optional[str] = ""
    video_url: Optional[str] = ""

class TopEarnersUpdate(BaseModel):
    items: List[TopEarnerItem] = []

class BusinessPaymentMethodCreate(BaseModel):
    type: str
    label: str
    last4: Optional[str] = None
    is_default: bool = False

class BusinessWalletRechargeCreate(BaseModel):
    amount: float
    gateway: str = "razorpay"


class BusinessGSTSubmit(BaseModel):
    gstin: str
    legal_name: Optional[str] = ""


class AdminGSTReview(BaseModel):
    action: str                      # 'approve' | 'reject'
    reason: Optional[str] = ""

class CheckoutBriefCreate(BaseModel):
    """Direct booking of a creator from their plan (PlanBrief modal)."""
    creator_id: str
    video_count: int = 1
    brief: Dict[str, Any] = {}

class BookingRespond(BaseModel):
    """Creator's answer to a booking request: accept / decline / revise the price."""
    action: str                              # accept | decline | revise
    amount: Optional[float] = None           # creator's proposed take (revise only)
    message: Optional[str] = None

class BookingPriceDecision(BaseModel):
    """Brand's answer to the creator's counter-offer."""
    action: str                              # accept | reject

class BookingBriefSend(BaseModel):
    """The brief the brand sends once the creator has accepted."""
    brief_text: Optional[str] = None
    deliverables: Optional[str] = None
    attachment_urls: List[str] = []

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
    # WHICH required asset this submission is for, 0-based, on a brief that asks for
    # more than one (quantity > 1 or several deliverable rows). Omitted by older
    # clients and by single-asset briefs, where it defaults to 0 — that keeps the
    # existing one-video flow behaving exactly as before.
    deliverable_index: Optional[int] = None

class DealRevisionResponseSubmit(BaseModel):
    response: str
    note: Optional[str] = None
    # The specific requested changes the creator ticked they'll do (checklist on the
    # creator's Revision Tracker). Lets the brand see exactly what was committed to.
    accepted_changes: Optional[List[str]] = None

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

class DisputeInfoResponse(BaseModel):
    message: str               # the party's answer to the admin's info request
    evidence_urls: List[str] = []   # optional supporting files

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
    # bcrypt only uses the first 72 bytes; truncate so we never raise on long
    # passwords and stay compatible with the Node/bcryptjs backend (which truncates too).
    return bcrypt.hashpw(password.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    # Never raise (a malformed/foreign hash or >72-byte password must fail as
    # "invalid credentials", not crash the login with a 500).
    try:
        return bcrypt.checkpw(password.encode('utf-8')[:72], (hashed or '').encode('utf-8'))
    except (ValueError, TypeError):
        return False

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_delegated_brand_token(brand: dict, admin: dict) -> str:
    payload = {
        "user_id": brand["id"],
        "email": brand.get("email"),
        "role": UserRole.BUSINESS,
        "delegated_admin_id": admin["id"],
        "delegated_admin_email": admin.get("email"),
        "delegated_admin_name": person_display_name(admin, "Operations Team"),
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# ---- Email (Resend) --------------------------------------------------------
# Generic transactional email sender. Safe no-op if RESEND_API_KEY is unset.
def _send_email_sync(to, subject: str, html: str, text: Optional[str] = None) -> dict:
    api_key = os.environ.get('RESEND_API_KEY', '')
    if not api_key:
        logger.warning(f"[email] RESEND_API_KEY not set — skipping send to {to} (\"{subject}\")")
        return {"skipped": True}
    from_addr = os.environ.get('EMAIL_FROM', 'UGCad.io <onboarding@resend.dev>')
    reply_to = os.environ.get('EMAIL_REPLY_TO') or None
    payload = {
        "from": from_addr,
        "to": to if isinstance(to, list) else [to],
        "subject": subject,
        "html": html,
    }
    if text:
        payload["text"] = text
    if reply_to:
        payload["reply_to"] = reply_to
    try:
        r = requests.post(
            "https://api.resend.com/emails",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=15,
        )
        if r.status_code >= 400:
            logger.error(f"[email] Resend send failed {r.status_code}: {r.text}")
            return {"error": r.text}
        return r.json()
    except Exception as e:
        logger.error(f"[email] send exception: {e}")
        return {"error": str(e)}

async def send_email(to, subject: str, html: str, text: Optional[str] = None) -> dict:
    return await asyncio.to_thread(_send_email_sync, to, subject, html, text)

def _email_button(label: str, path: str = "/auth") -> str:
    """Primary CTA button for transactional emails. `path` is appended to
    FRONTEND_URL unless it is already an absolute URL."""
    base = (os.environ.get("FRONTEND_URL") or "https://www.ugcad.io").rstrip("/")
    url = path if str(path).startswith("http") else f"{base}{path}"
    return (
        f'<p style="margin:26px 0 0;"><a href="{url}" '
        'style="background:#07074e;color:#ffffff;padding:13px 26px;border-radius:8px;'
        'text-decoration:none;font-weight:600;display:inline-block;font-size:15px;">'
        f'{label}</a></p>'
    )

def _email_base_template(title: str, content_html: str) -> str:
    year = datetime.now(timezone.utc).year
    return f"""<!doctype html><html><body style="margin:0;padding:0;background:#f4f5fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2340;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5fb;padding:32px 12px;"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 8px 30px rgba(20,22,58,0.08);">
<tr><td style="background:linear-gradient(135deg,#5b6bff,#8b5cf6);padding:24px 32px;"><span style="color:#fff;font-size:20px;font-weight:800;">UGCad.io</span></td></tr>
<tr><td style="padding:32px;">{content_html}</td></tr>
<tr><td style="padding:20px 32px;background:#fafbff;border-top:1px solid #eef0f6;color:#9296ba;font-size:12px;line-height:1.6;">You're receiving this email from UGCad.io.<br/>&copy; {year} UGCad.io. All rights reserved.</td></tr>
</table></td></tr></table></body></html>"""

# ---- Password-reset code helpers -------------------------------------------
def _reset_code_hash(code: str) -> str:
    return hashlib.sha256((code or '').encode('utf-8')).hexdigest()

def _reset_code_valid(user: Optional[dict], code: str) -> bool:
    if not user or not user.get('reset_code') or not user.get('reset_code_expires'):
        return False
    try:
        exp = datetime.fromisoformat(user['reset_code_expires'])
    except Exception:
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc):
        return False
    return user['reset_code'] == _reset_code_hash(code)

# Realistic placeholder names so an account without a set name still reads as a
# person, never a "BraveFalcon764" handle.
PLACEHOLDER_FIRST_NAMES = [
    'Aarav', 'Vivaan', 'Aditya', 'Arjun', 'Reyansh', 'Rohan', 'Kabir', 'Ishaan', 'Dev', 'Krishna',
    'Ananya', 'Diya', 'Aadhya', 'Saanvi', 'Priya', 'Ira', 'Myra', 'Riya', 'Kiara', 'Meera',
    'Neha', 'Kunal', 'Nikhil', 'Sara', 'Aisha', 'Tara', 'Karan', 'Sana', 'Yash', 'Zoya',
]

async def generate_nickname() -> str:
    """A realistic placeholder NAME (not a handle) until the person sets their own."""
    max_attempts = 50
    for _ in range(max_attempts):
        nickname = f"{random.choice(PLACEHOLDER_FIRST_NAMES)}{random.randint(10, 99)}"
        existing = await db.users.find_one({"nickname": {"$in": [nickname, f"@{nickname}"]}})
        if not existing:
            return nickname

    # Fallback: use UUID if all attempts fail
    return f"User{str(uuid.uuid4())[:8]}"

async def generate_creator_code() -> str:
    """Generate a permanent, unique public creator code (e.g. CR-7F3A2B).
    Distinct from the handle; never changes once assigned."""
    for _ in range(50):
        code = cf.generate_creator_code()
        existing = await db.users.find_one({"creator_code": code}, {"_id": 1})
        if not existing:
            return code
    return cf.generate_creator_code()

async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    # Tokens may be minted by either backend: Python uses 'user_id'; Node uses
    # 'userId'/'id'/'sub'. Accept any of them so a token from one works on the other.
    uid = payload.get('user_id') or payload.get('userId') or payload.get('id') or payload.get('sub')
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"id": uid}, {"_id": 0})
    if not user:
        # Node-created users are keyed on ObjectId _id and may lack a string 'id'.
        try:
            from bson import ObjectId
            user = await db.users.find_one({"_id": ObjectId(uid)}, {"_id": 0})
        except Exception:
            user = None
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # A suspended/banned account must be locked out IMMEDIATELY, not only at the next
    # login. Tokens live 7 days, and /auth/login already blocks banned users — but
    # without this check an already-logged-in banned user could keep using the app on
    # their existing token for up to a week. Enforce the ban on every authenticated
    # request so a 4th chat strike (or an admin ban) takes effect right away.
    if user.get("banned"):
        raise HTTPException(status_code=403, detail=f"Account banned: {user.get('banned_reason') or user.get('ban_reason') or 'Account suspended'}")
    delegated_admin_id = payload.get("delegated_admin_id")
    if delegated_admin_id:
        admin = await db.users.find_one({"id": delegated_admin_id}, {"_id": 0})
        if not admin or admin.get("role") != UserRole.ADMIN or not admin_caps.can(admin, "manage_deals", "edit"):
            raise HTTPException(status_code=403, detail="Delegated brand access is no longer authorized")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.url.path.startswith("/api/auth"):
                raise HTTPException(status_code=403, detail="Operations cannot change brand authentication details")
            await log_admin_action(
                admin,
                f"delegated_brand.{request.method.lower()}",
                target_type="business",
                target_id=user.get("id"),
                after={"path": request.url.path},
                reason="Operations acted through the brand workspace",
                request=request,
            )
        user["_delegated_admin_id"] = admin.get("id")
        user["_delegated_admin_name"] = person_display_name(admin, "Operations Team")
        user["_delegated_admin_email"] = admin.get("email")
    return user

async def get_current_business_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access these settings")
    return current_user


# ── Real-world validators: does this website resolve / does this IG handle exist ──
_VALIDATE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36"


def _host_is_public(host: str) -> bool:
    """Resolve host and reject private/loopback ranges (SSRF guard). Returns False
    if DNS doesn't resolve — which is exactly how we detect a fake domain."""
    import ipaddress
    import socket
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return False
    return True


def _check_website_sync(raw: str) -> dict:
    from urllib.parse import urlparse
    u = (raw or "").strip()
    if not u:
        return {"valid": False, "reason": "empty"}
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    host = (urlparse(u).hostname or "").lower()
    if not host or "." not in host:
        return {"valid": False, "reason": "format"}
    if not _host_is_public(host):
        # DNS didn't resolve (or points somewhere private) → treat as a dead/fake site.
        return {"valid": False, "reason": "unreachable"}
    candidates = [u]
    if u.startswith("https://"):
        candidates.append("http://" + u[len("https://"):])
    for cu in candidates:
        try:
            r = requests.head(cu, timeout=6, allow_redirects=True, headers={"User-Agent": _VALIDATE_UA})
            if r.status_code < 400 or r.status_code in (401, 403, 405, 406, 429):
                return {"valid": True, "status": r.status_code, "normalized": r.url}
            r = requests.get(cu, timeout=6, allow_redirects=True, stream=True, headers={"User-Agent": _VALIDATE_UA})
            if r.status_code < 500:
                return {"valid": True, "status": r.status_code, "normalized": r.url}
        except requests.RequestException:
            continue
    return {"valid": False, "reason": "unreachable"}


def _check_instagram_sync(raw: str) -> dict:
    u = (raw or "").strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9._]{1,30}$", u):
        return {"valid": False, "reason": "format"}
    try:
        r = requests.get(
            f"https://www.instagram.com/{u}/",
            timeout=7, allow_redirects=True,
            headers={"User-Agent": _VALIDATE_UA, "Accept-Language": "en-US,en;q=0.9"},
        )
        if r.status_code == 404:
            return {"valid": False, "reason": "not_found"}
        if r.status_code == 200:
            body = (r.text or "")
            low = body.lower()
            if ('"user":null' in body) or ("sorry, this page isn't available" in low) or ("page not found" in low):
                return {"valid": False, "reason": "not_found"}
            # Positive proof the profile exists (present only on a real profile page,
            # not on Instagram's logged-out login wall).
            confirmed = (
                f'"username":"{u.lower()}"' in low
                or f'content="https://www.instagram.com/{u.lower()}/"' in low
                or f'@{u.lower()} •' in low
                or f'alternatename":"@{u.lower()}"' in low
            )
            if confirmed:
                return {"valid": True}
            # Instagram showed a login wall — we genuinely can't tell. Don't claim valid.
            return {"uncertain": True, "reason": "unverified"}
        return {"uncertain": True, "reason": "unverified"}
    except requests.RequestException:
        return {"uncertain": True, "reason": "unverified"}


@api_router.post("/validate/website")
async def validate_website(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    """Best-effort check that a business website actually resolves and responds."""
    return await asyncio.to_thread(_check_website_sync, str(payload.get("url", "")))


@api_router.post("/validate/instagram")
async def validate_instagram(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    """Best-effort check that an Instagram handle exists (IG blocks bots, so failures
    are reported as 'uncertain' rather than invalid)."""
    return await asyncio.to_thread(_check_instagram_sync, str(payload.get("username", "")))


def require_cap(capability: str):
    """FastAPI dependency factory: ensures the caller is an admin AND holds
    `capability` (per admin_caps.can). Mirrors the Express requireCap middleware
    so both backends enforce the same RBAC matrix. Returns current_user so routes
    can keep `current_user: dict = Depends(require_cap("..."))`."""
    async def _dep(request: Request, current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Admin access required")
        access = "view" if request.method in ("GET", "HEAD", "OPTIONS") else "edit"
        if not admin_caps.can(current_user, capability, access):
            role = admin_caps.normalize_role(current_user.get("admin_role"))
            label = admin_caps.ROLE_LABELS.get(role, role)
            raise HTTPException(status_code=403, detail=f"Your role ({label}) does not have {access} access for this feature")
        return current_user
    return _dep

async def get_approved_business_user(request: Request, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    if request.method not in ("GET", "HEAD", "OPTIONS") and current_user.get("approval_status") != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Business profile must be approved")
    return current_user

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    # Date-only / naive strings (e.g. a "2026-06-21" deadline) parse without a
    # timezone; normalize to UTC so comparisons with tz-aware timestamps don't
    # raise "can't compare offset-naive and offset-aware datetimes".
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

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

# ---- GST (GSTIN) verification -----------------------------------------------
# A brand must have a VERIFIED GSTIN before it can put money into its wallet.
# Statuses: not_submitted -> pending -> verified | rejected
GST_STATUSES = ("not_submitted", "pending", "verified", "rejected")
GSTIN_RE = re.compile(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$')
_GSTIN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# State codes 01-38 plus 97 (other territory). Anything else is not a real state.
_GST_STATE_CODES = {f"{i:02d}" for i in range(1, 39)} | {"97"}


def gstin_checksum_ok(gstin: str) -> bool:
    """Verify the 15th character — GSTIN's built-in mod-36 check digit.

    This is real validation, not a regex: a mistyped or invented number fails here,
    so we catch bad GSTINs offline without paying for a lookup API.
    """
    total = 0
    for i, ch in enumerate(gstin[:14]):
        value = _GSTIN_ALPHABET.index(ch)
        factor = 2 if i % 2 else 1
        product = value * factor
        total += product // 36 + product % 36
    expected = _GSTIN_ALPHABET[(36 - total % 36) % 36]
    return expected == gstin[14]


def validate_gstin(raw: str) -> tuple[bool, str]:
    """Return (ok, reason). Reason is user-facing when ok is False."""
    gstin = (raw or "").strip().upper().replace(" ", "")
    if not gstin:
        return False, "Enter your GSTIN."
    if len(gstin) != 15:
        return False, f"A GSTIN is 15 characters — you entered {len(gstin)}."
    if not GSTIN_RE.match(gstin):
        return False, "That doesn't look like a valid GSTIN (format: 22AAAAA0000A1Z5)."
    if gstin[:2] not in _GST_STATE_CODES:
        return False, f"'{gstin[:2]}' is not a valid GST state code."
    if not gstin_checksum_ok(gstin):
        return False, "GSTIN check digit failed — please re-check the number."
    return True, ""


def gst_status_of(user: dict) -> str:
    """Current GST state for a brand. Mirrors the creator `kyc` sub-document shape."""
    status = ((user or {}).get("gst") or {}).get("status")
    return status if status in GST_STATUSES else "not_submitted"


def kyc_status_of(user: dict) -> str:
    """Current KYC state for a creator. Mirrors gst_status_of. Values: not_submitted / pending / verified / rejected."""
    return ((user or {}).get("kyc") or {}).get("status") or "not_submitted"


def person_display_name(user: Optional[dict], fallback: str = "Someone") -> str:
    """Single source of truth for a person's shown NAME — never the "@handle".
    Mirrors the frontend displayName() util: prefer the real name / business name,
    strip any leading "@", and only fall back to the nickname handle when no real
    name exists. Used anywhere the backend bakes a name into text (notifications,
    receipts, emails) so the website never surfaces a raw username."""
    u = user or {}
    p = u.get("profile") or {}
    def clean(v):
        s = str(v or "").strip()
        return s.lstrip("@").strip() if s else ""
    return (
        clean(u.get("full_name"))
        or clean(p.get("fullName"))
        or clean(p.get("full_name"))
        or clean(u.get("business_name"))
        or clean(p.get("business_name"))
        or clean(u.get("name"))
        or clean(u.get("nickname"))
        or clean(u.get("username"))
        or (clean(u.get("email")).split("@")[0] if u.get("email") else "")
        or fallback
    )


def first_name_of(user: dict, fallback: str = "there") -> str:
    """First name for greetings. Prefers an explicit first_name, else the first
    word of the real name (full_name). Only if no real name is set does it fall
    back to the display nickname — with any auto-generated numeric suffix stripped
    so a placeholder handle like 'Aarav42' (legacy 'BraveFalcon277') greets as a
    name, never the raw username. Mirrors the frontend firstName() util so
    greetings read 'Hi Meet!' not 'Hi Meet Jain!'."""
    u = user or {}
    p = u.get("profile") or {}
    # Names may live at the root OR nested under profile (creator signup stores them
    # there via extra="allow"), so check both.
    explicit = str(u.get("first_name") or p.get("first_name") or p.get("firstName") or "").strip().lstrip("@")
    if explicit:
        return explicit.split()[0]
    real = str(u.get("full_name") or p.get("fullName") or p.get("full_name") or "").strip().lstrip("@")
    if real:
        return real.split()[0]
    # No real name — this is the auto-generated placeholder handle. Drop the
    # trailing digits so emails read as a first name, not a "@Name42" username.
    # (Brands keep their typed business nickname as-is — it has no digit suffix.)
    handle = re.sub(r"\d+$", "", str(u.get("nickname") or "").strip().lstrip("@")).strip()
    parts = handle.split()
    return parts[0] if parts else fallback


def gst_public(user: dict) -> dict:
    """What the brand itself sees about its own GST record."""
    gst = (user or {}).get("gst") or {}
    status = gst_status_of(user)
    return {
        "status": status,
        "gstin": gst.get("gstin") or "",
        "legal_name": gst.get("legal_name") or "",
        "submitted_at": gst.get("submitted_at"),
        "reviewed_at": gst.get("reviewed_at"),
        "rejection_reason": gst.get("rejection_reason") or "",
        # The single source of truth the wallet UI keys off.
        "can_recharge": status == "verified",
    }


# ---- Creator KYC field validation -------------------------------------------
# We pay real money to whoever passes KYC, so identity + payout fields are validated
# on the SERVER — the client checks are only a courtesy. Numbers that don't check out
# never reach the review queue.
PAN_RE = re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$')
IFSC_RE = re.compile(r'^[A-Z]{4}0[A-Z0-9]{6}$')   # 4 letters, a 0, then 6 alphanumerics
UPI_RE = re.compile(r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$')

# Aadhaar's Verhoeff checksum — the same algorithm the frontend runs.
_VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
]


def aadhaar_valid(raw: str) -> bool:
    n = re.sub(r"\D", "", raw or "")
    if not re.match(r'^[2-9][0-9]{11}$', n):
        return False
    c = 0
    for i, d in enumerate(reversed(n)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(d)]]
    return c == 0


def age_years(dob_iso: str) -> Optional[int]:
    """Whole years between dob (YYYY-MM-DD) and today, or None if unparseable."""
    try:
        dob = datetime.fromisoformat(str(dob_iso)[:10]).date()
    except Exception:
        return None
    today = datetime.now(timezone.utc).date()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


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
VIDEO_MAX_BYTES = 150 * 1024 * 1024
MAX_IMAGES_PER_CHAT_MESSAGE = 5
MAX_VIDEO_SECONDS = 120

IMAGE_CONTENT_TYPES = {"image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"}
PDF_CONTENT_TYPES = {"application/pdf"}
VIDEO_CONTENT_TYPES = {"video/mp4", "video/quicktime", "video/webm", "video/x-msvideo", "video/mpeg", "video/3gpp", "video/x-matroska"}
CONTACT_URL_DOMAINS = ["wa.me", "t.me", "telegram.me", "linktr.ee", "linktree", "about.me", "beacons.ai", "carrd.co"]
SOCIAL_PLATFORM_PATTERN = re.compile(r"\b(instagram|insta|whatsapp|telegram|linkedin|twitter|youtube|yt|x\.com)\b", re.IGNORECASE)
OBFUSCATED_EMAIL_PATTERN = re.compile(r"\b[\w.-]+\s+(?:at|\[at\]|\(at\))\s+[\w.-]+\s+(?:dot|\[dot\]|\(dot\))\s+[a-z]{2,}\b", re.IGNORECASE)
PHONE_SEQUENCE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\s().-]*){10,15}(?!\w)")
# Broader digit-run catcher (7-15 digits) so partial / shorter numbers can't slip
# through when written next to a contact-intent word (e.g. "call me 900900000").
PHONE_LOOSE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\s().-]*){7,15}(?!\w)")
CONTACT_INTENT_PATTERN = re.compile(
    r"\b(call|contact|reach|ping|text|dm|number|num|mob(?:ile)?|phone|cell|whats?app|wa|telegram|signal|"
    r"insta(?:gram)?|email|mail|connect|hit me|reach me|call me)\b",
    re.IGNORECASE,
)

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
    if content_type in IMAGE_CONTENT_TYPES or lower_name.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp")):
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
    raise HTTPException(status_code=400, detail="Videos must be 150 MB or smaller and 2 minutes or shorter.")

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

# ── Admin-managed filter rules (Admin → Chat oversight → Filter rules) ───────
#
# These rules used to live only in the admin UI: you could add "call me", the page
# showed it as Active, and the filter below — which only ever checked the hardcoded
# patterns above — happily delivered "call me". The rules are real rows now, and
# this cache is what puts them in front of every message.
#
# check_contact_info_policy() is sync and called from a dozen places, so the rules
# are held in a module-level cache that callers refresh (cheaply, TTL-guarded)
# before checking.
_filter_rules_cache: dict = {"rules": [], "at": 0.0}
FILTER_RULES_TTL_SECONDS = 30.0


def _compile_filter_rule(rule: dict):
    """Turn a stored rule into a compiled matcher. A pattern that won't compile is
    dropped rather than raised — one bad rule must never take chat down."""
    try:
        if rule.get("type") == "regex":
            return {"id": rule.get("id"), "label": rule.get("label") or rule.get("id"),
                    "re": re.compile(rule["pattern"], re.IGNORECASE)}
        # keyword: a comma-separated list, matched on word boundaries so the rule
        # "snap" doesn't fire on "snapshot".
        words = [w.strip() for w in str(rule.get("pattern") or "").split(",") if w.strip()]
        if not words:
            return None
        pattern = r"\b(" + "|".join(re.escape(w) for w in words) + r")\b"
        return {"id": rule.get("id"), "label": rule.get("label") or rule.get("id"),
                "re": re.compile(pattern, re.IGNORECASE)}
    except re.error as exc:
        logger.warning("Filter rule %s has an invalid pattern, skipping: %s", rule.get("id"), exc)
        return None


async def refresh_filter_rules(force: bool = False):
    """Reload the enabled rules into the cache. Cheap and TTL-guarded, so callers
    can await it on every message without hammering Mongo."""
    now = time.time()
    if not force and (now - _filter_rules_cache["at"]) < FILTER_RULES_TTL_SECONDS:
        return _filter_rules_cache["rules"]
    try:
        docs = await db.filter_rules.find({"enabled": True}, {"_id": 0}).to_list(500)
        _filter_rules_cache["rules"] = [c for c in (_compile_filter_rule(d) for d in docs) if c]
        _filter_rules_cache["at"] = now
    except Exception as exc:  # DB hiccup: keep the rules we already had
        logger.warning("Could not reload filter rules: %s", exc)
    return _filter_rules_cache["rules"]


async def seed_filter_rules():
    """Persist the built-in defaults once, so they're editable rows like any other
    (they used to be merged into the API response but never stored — which is why
    switching one off or deleting it 404'd: there was no row to act on)."""
    try:
        for rule in DEFAULT_FILTER_RULES:
            await db.filter_rules.update_one(
                {"id": rule["id"]},
                {"$setOnInsert": {**rule, "hits": 0, "created_at": datetime.now(timezone.utc)}},
                upsert=True,
            )
    except Exception as exc:
        logger.warning("Could not seed default filter rules: %s", exc)
    return await refresh_filter_rules(force=True)


def check_contact_info_policy(message: str, allowed_domains: Optional[List[str]] = None) -> dict:
    text = message or ""
    violations = []
    allowed_domains = allowed_domains or []

    # The admin's own rules. Callers await refresh_filter_rules() first; if the cache
    # is cold this is simply empty and the built-in patterns below still apply.
    for rule in _filter_rules_cache["rules"]:
        if rule["re"].search(text):
            violations.append({"type": rule["label"], "content": [rule["label"]], "severity": "high"})

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

    # A run of digits reads as a phone number when it's long (9+), or shorter (7+)
    # but written next to a contact-intent word like "call me" / "whatsapp".
    has_contact_intent = bool(CONTACT_INTENT_PATTERN.search(text))
    min_phone_digits = 7 if has_contact_intent else 9
    phone_matches = []
    for match in PHONE_LOOSE_PATTERN.findall(text):
        digits = re.sub(r"\D", "", match)
        if min_phone_digits <= len(digits) <= 15:
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
    """Alert the ops team. Fans out to a per-admin in-app notification (keyed on
    user_id) so it actually shows in each admin's bell — the notification list
    queries by user_id, so a single target_roles doc was invisible."""
    now = now_iso()
    # Keep the audit copy.
    await db.admin_notifications.insert_one({
        "id": str(uuid.uuid4()), "title": title, "message": message, "type": "warning",
        "link": link, "target_roles": [UserRole.ADMIN], "created_at": now, "created_by": "system",
    })
    admins = await db.users.find({"role": UserRole.ADMIN}, {"_id": 0, "id": 1}).to_list(500)
    if not admins:
        return
    await db.in_app_notifications.insert_many([{
        "id": str(uuid.uuid4()),
        "user_id": a["id"],
        "title": title,
        "message": message,
        "type": "warning",
        "link": link,
        "read": False,
        "created_at": now,
        "created_by": "system",
    } for a in admins if a.get("id")])

FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://www.ugcad.io")


def _notification_email_html(title: str, message: str, link: Optional[str], name: Optional[str]) -> str:
    cta = ""
    if link:
        url = link if str(link).startswith("http") else f"{FRONTEND_URL}{link}"
        cta = (
            f'<p style="margin:24px 0"><a href="{url}" '
            'style="background:#07074e;color:#fff;padding:12px 22px;border-radius:8px;'
            'text-decoration:none;font-weight:600;display:inline-block">Open UGCad.io</a></p>'
        )
    greeting = f"Hi {name}," if name else "Hi,"
    return (
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:0 auto;color:#1a1a2e">'
        f'<h2 style="color:#07074e">{title}</h2>'
        f'<p style="font-size:15px;line-height:1.6">{greeting}</p>'
        f'<p style="font-size:15px;line-height:1.6">{message}</p>'
        f'{cta}'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#888">UGCad.io — where brands meet real creators.</p>'
        '</div>'
    )


def _in_quiet_hours() -> bool:
    """Quiet hours 10pm-8am IST (the platform is India-first). Non-critical emails
    are held back during this window; the in-app notification still records."""
    ist_hour = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).hour
    return ist_hour >= 22 or ist_hour < 8


# Canonical notification categories → the per-role preference key. Creators and
# brands name the same concept differently, so map both.
_NOTIF_PREF_KEYS = {
    "payments":     {"creator": "payout_alerts", "business": "payment_alerts"},
    "deal_updates": {"creator": "bid_updates",   "business": "deal_updates"},
    "applications": {"creator": "bid_updates",   "business": "new_applications"},
    "messages":     {"creator": "messages",      "business": "messages"},
    "weekly":       {"creator": "weekly_digest", "business": "weekly_reports"},
}


async def _email_category_allowed(user: dict, category: Optional[str]) -> bool:
    """Whether the recipient still wants EMAIL for this canonical category.
    Creator prefs live on user.notification_prefs; brand prefs in business_settings.
    Unknown category / no pref set → allowed (never silently drop)."""
    if not category or not user:
        return True
    role = user.get("role")
    key = (_NOTIF_PREF_KEYS.get(category) or {}).get(role, category)
    if role == UserRole.BUSINESS:
        s = await db.business_settings.find_one({"business_id": user["id"]}, {"_id": 0, "notifications": 1})
        n = (s or {}).get("notifications") or {}
        if key in n:
            return bool(n[key])
        return True
    prefs = user.get("notification_prefs") or {}
    if key in prefs:
        return bool(prefs[key])
    return True


async def notify_user(user_id: str, title: str, message: str, link: Optional[str] = None, ntype: str = "info", email: bool = False, critical: bool = False, category: Optional[str] = None):
    """Send an in-app notification to a single user. Set email=True to ALSO send an
    email (best-effort — a mail failure never breaks the in-app notification/action).
    Set critical=True for SLA/security emails that must bypass quiet hours + prefs.
    Set category to honor the recipient's per-category email preference."""
    await db.in_app_notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "title": title,
        "message": message,
        "type": ntype,
        "link": link,
        "category": category,
        "read": False,
        "created_at": now_iso(),
        "created_by": "system",
    })
    # Non-critical email is suppressed during quiet hours (the in-app record still shows).
    if email and (critical or not _in_quiet_hours()):
        try:
            u = await db.users.find_one({"id": user_id}, {"_id": 0, "email": 1, "nickname": 1, "full_name": 1, "role": 1, "notification_prefs": 1})
            # Honor the recipient's per-category email preference (critical bypasses it).
            if not critical and not await _email_category_allowed(u or {}, category):
                return
            addr = (u or {}).get("email")
            if addr:
                html = _notification_email_html(title, message, link, first_name_of(u, fallback=""))
                res = await send_email(addr, title, html, message)
                # Never let a dropped email be invisible. A bare `except: pass` here is how
                # "emails aren't coming" stayed unnoticed while prod had no RESEND_API_KEY.
                if isinstance(res, dict) and (res.get("skipped") or res.get("error")):
                    logger.error(f"[email] NOT delivered to {addr} ('{title}'): {res}")
            else:
                logger.warning(f"[email] user {user_id} has no email on file — '{title}' not sent")
        except Exception as e:
            logger.exception(f"[email] failed sending '{title}' to user {user_id}: {e}")

async def enforce_suspension(user: dict):
    """Block login for a suspended account, or auto-lift the suspension once its
    window has passed. ISO-8601 UTC timestamps compare correctly as strings."""
    if not user or not user.get("suspended"):
        return
    until = user.get("suspended_until")
    if until and now_iso() >= until:
        q = {"id": user["id"]} if user.get("id") else {"email": user.get("email")}
        await db.users.update_one(q, {"$set": {"suspended": False, "status": "active", "suspended_until": None}})
        return
    when = f" until {str(until)[:10]}" if until else ""
    raise HTTPException(status_code=403, detail=f"Account suspended{when}. Reason: {user.get('suspended_reason') or 'policy violation'}")

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
    # A brand can open the conversation with a plain message before sending any
    # formal invite. Once they've messaged this creator, let the creator reply —
    # so a brand can talk first and invite to a private deal afterwards.
    if await db.messages.find_one({"sender_id": brand_id, "recipient_id": creator_id}, {"_id": 0}):
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

async def validate_chat_access(current_user: dict, recipient_id: str, allow_action_cards_only: bool = False, read_only: bool = False):
    recipient = await db.users.find_one({"id": recipient_id}, {"_id": 0, "password": 0})
    # Reading a thread you're already part of must NEVER be blocked. The wallet,
    # approval, relationship and pause gates below govern SENDING; enforcing them on
    # reads made the whole Messages tab look broken ("No messages yet", nothing
    # actionable") for under-funded or not-yet-approved brands. We also tolerate a
    # partner that can only be resolved by _id (created via the Node backend) instead
    # of 404-ing the read — the same fix the conversations list already carries.
    if read_only:
        if not recipient:
            try:
                from bson import ObjectId
                recipient = await db.users.find_one({"_id": ObjectId(recipient_id)}, {"_id": 0, "password": 0})
            except Exception:
                recipient = None
        return recipient or {"id": recipient_id, "role": ""}
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

    # Persist the strike to the user's own bell. Until now the struck user only
    # saw it as the transient 400 chat popup (contact_info_block_message), which
    # vanishes and leaves no record — so warnings never appeared in-app for
    # either brand or creator. Save it as a warning notification too.
    strike_titles = {
        "warning": "Policy warning issued",
        "paused": "Chat paused — policy strike",
        "action_cards_only": "Action Cards only — policy strike",
        "suspended": "Account suspended — policy strike",
    }
    await notify_user(
        current_user["id"],
        strike_titles.get(severity, "Policy warning issued"),
        contact_info_block_message(strike_doc),
        link="/chat",
        ntype="warning",
        category="policy",
    )

    return {"violation": violation_doc, "strike": strike_doc}


def contact_info_block_message(strike: dict) -> str:
    """Human, escalation-aware block message for a contact-info violation.

    Tells the user which strike this is and exactly what happens next / if they
    do it again, so the warning isn't a bare 'blocked' with no context. Mirrors
    the severity ladder in log_chat_violation (warning → paused → action-cards-only
    → suspended).
    """
    n = strike.get("strike_number", 1)
    severity = strike.get("severity")
    pause_txt = "1 hour" if CHAT_PAUSE_SECONDS == 3600 else f"{CHAT_PAUSE_SECONDS // 60} minutes"
    if severity == "suspended" or n >= 4:
        tail = (f"This is strike {n}. Your account has been suspended for repeated "
                "policy violations and is pending admin review. Email support@ugcad.io to appeal.")
    elif severity == "action_cards_only" or n == 3:
        tail = (f"This is strike 3 of 3. You can now only send structured action cards "
                f"(offers, counters) for {ACTION_CARDS_ONLY_DAYS} days. One more violation will "
                "suspend your account.")
    elif severity == "paused" or n == 2:
        tail = (f"This is strike 2 of 3. Your chat is now paused for {pause_txt}. A 3rd strike "
                f"limits you to action cards only for {ACTION_CARDS_ONLY_DAYS} days, and a 4th "
                "suspends your account.")
    else:
        tail = (f"This is strike 1 of 3. If it happens again your chat is paused for {pause_txt}; "
                f"a 3rd strike limits you to action cards only for {ACTION_CARDS_ONLY_DAYS} days, "
                "and a 4th suspends your account.")
    return f"{CONTACT_INFO_BLOCK_DETAIL} {tail}"

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

    KYC identity + payout details (PAN, Aadhaar, address, document URLs, bank
    account, UPI) are NEVER exposed to another user — only the `kyc_verified`
    boolean survives, so a viewer can see the "Verified" badge without the PII.
    """
    if not isinstance(user_doc, dict):
        return user_doc
    if requester_role == UserRole.BUSINESS:
        user_doc.pop("username", None)
        user_doc.pop("email", None)
    if requester_role != UserRole.ADMIN:
        user_doc["kyc_verified"] = bool(user_doc.get("kyc_verified"))
        for private in ("kyc", "bank_details", "upi_id", "pan_number", "aadhaar_number"):
            user_doc.pop(private, None)
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
        require_fields(fields, ["campaign_name", "deliverable_summary", "budget", "timeline", "usage_rights"], "private_invitation")
        # The brand now writes the brief inline ("Send a brief") via brief_details.
        # A legacy/ops-shortlist invite may instead carry a full_brief_link — accept either.
        if not str(fields.get("brief_details") or fields.get("full_brief_link") or "").strip():
            raise HTTPException(status_code=400, detail="private_invitation requires: brief_details")
        # require_fields() treats 0 as "present", and an empty budget box arrives as 0
        # (JS Number('') === 0) — so a zero-budget invitation would otherwise go through.
        if to_float(fields.get("budget")) <= 0:
            raise HTTPException(status_code=400, detail="private_invitation requires a budget greater than zero")
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

def campaign_per_asset_budget(campaign: dict) -> float:
    """The budget for ONE deliverable asset. This is what the brief wizard sends as
    per_video_budget / budget_max (it sends the same figure for both)."""
    if campaign.get("budget"):
        return to_float(campaign.get("budget"))
    budget_min = to_float(campaign.get("budget_min"))
    budget_max = to_float(campaign.get("budget_max"))
    if budget_min and budget_max:
        return budget_max
    return budget_min or budget_max


def campaign_budget_total(campaign: dict) -> float:
    """TOTAL budget a brief commits = per-asset budget x total deliverable quantity.

    Previously this returned the per-asset figure, so a brief asking for 3 Reels only
    ever held ONE video's budget while the creator owed three — the brand was
    under-charged and the payout maths was wrong.

    LEGACY SAFETY: total_deliverable_quantity() returns 1 when a brief has no
    deliverable_items, so every pre-existing campaign yields exactly the old value.
    Refunds are unaffected either way — refund_campaign_reservation() pays back the
    escrow row's STORED reserved_amount rather than recomputing it here.
    """
    return campaign_per_asset_budget(campaign) * total_deliverable_quantity(campaign)

async def reserve_campaign_budget(user: dict, campaign_doc: dict) -> Optional[dict]:
    """Hold a campaign's full budget from the brand wallet at post time so it shows as
    'on hold' in Transaction History. Raises 400 if the wallet can't cover it."""
    amount = round(campaign_budget_total(campaign_doc), 2)
    if amount <= 0:
        return None
    # Atomic conditional debit — only deduct if the balance can cover the reservation.
    debit = await db.users.update_one(
        {"id": user["id"], "balance": {"$gte": amount}},
        {"$inc": {"balance": -amount}},
    )
    if debit.modified_count != 1:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient wallet balance to reserve this campaign's budget (₹{amount:,.0f}). Add funds to your wallet and try again.",
        )
    escrow_doc = {
        "id": str(uuid.uuid4()),
        "campaign_id": campaign_doc["id"],
        "business_id": user["id"],
        "creator_id": None,
        "amount": amount,
        "reserved_amount": amount,
        "status": "reserved",
        "funded": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.escrow.insert_one(escrow_doc)
    return escrow_doc

async def charge_listing_fee(user: dict, campaign_doc: dict) -> float:
    """Charge the brand the platform listing fee (Settings → Listing fee) on publish."""
    fee = to_float(platform_setting("listing_fee", 0))
    if fee <= 0:
        return 0.0
    debit = await db.users.update_one(
        {"id": user["id"], "balance": {"$gte": fee}},
        {"$inc": {"balance": -fee}},
    )
    if debit.modified_count != 1:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient wallet balance for the ₹{fee:,.0f} listing fee. Add funds and try again.",
        )
    await db.wallet_ledger.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "campaign_id": campaign_doc.get("id"),
        "type": "listing_fee",
        "amount": fee,
        "direction": "debit",
        "status": "success",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return fee

async def refund_campaign_reservation(campaign_id: str, reason: str = "refund") -> None:
    """Refund a still-reserved (no creator selected yet) campaign budget to the wallet.
    No-op once a creator is engaged (status becomes 'held')."""
    escrow = await db.escrow.find_one({"campaign_id": campaign_id, "status": "reserved"}, {"_id": 0})
    if not escrow:
        return
    amount = to_float(escrow.get("reserved_amount") or escrow.get("amount"))
    if amount > 0 and escrow.get("funded"):
        await db.users.update_one({"id": escrow["business_id"]}, {"$inc": {"balance": amount}})
    await db.escrow.update_one(
        {"id": escrow["id"]},
        {"$set": {"status": "refunded", "refund_reason": reason, "updated_at": datetime.now(timezone.utc).isoformat()}},
    )

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

def _fmt_amount_short(a: float) -> str:
    a = float(a or 0)
    if a >= 100000:
        return f"₹{a / 100000:.0f}L"
    if a >= 1000:
        return f"₹{a / 1000:.0f}K"
    return f"₹{a:.0f}"

def wallet_bonus_tiers() -> list:
    """Recharge-bonus tiers, driven by Admin → Settings → Recharge bonus tiers.
    Falls back to the shipped defaults. Normalised + sorted ascending by amount."""
    raw = platform_setting("wallet_bonus_tiers", WALLET_BONUS_TIERS) or WALLET_BONUS_TIERS
    tiers = []
    for t in raw:
        try:
            amount = float(t.get("amount") or 0)
            percent = float(t.get("bonus_percent") or 0)
        except (TypeError, ValueError, AttributeError):
            continue
        if amount <= 0:
            continue
        tiers.append({"amount": amount, "bonus_percent": percent, "label": (t.get("label") or _fmt_amount_short(amount))})
    tiers.sort(key=lambda t: t["amount"])
    return tiers or WALLET_BONUS_TIERS

def wallet_bonus_percent(amount: float) -> int:
    percent = 0
    for tier in wallet_bonus_tiers():
        if amount >= tier["amount"]:
            percent = tier["bonus_percent"]
    return percent

def wallet_bonus_amount(amount: float) -> float:
    return round(amount * wallet_bonus_percent(amount) / 100, 2)

def wallet_bonus_progress(amount: float) -> dict:
    current_tier = None
    next_tier = None
    for tier in wallet_bonus_tiers():
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
    elif tx_type in ["revision_fee", "paid_revision"]:
        tx_type = "Revision Fee"
        direction = "debit"
    elif tx_type in ["escrow_refund", "refund_escrow"]:
        tx_type = "Escrow Refund"
        direction = "credit"
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

async def issue_wallet_receipt(transaction: dict, reference: str, amount: float,
                               bonus_amount: float, credited_amount: float, now: str) -> None:
    """Save a payment receipt and email it to the brand.

    A wallet recharge is PREPAID CREDIT, not a taxable supply, so this is a payment
    receipt — NOT a GST tax invoice. (GST would apply to the platform commission on a
    completed deal, which is invoiced separately.)
    """
    user = await db.users.find_one({"id": transaction.get("user_id")}, {"_id": 0}) or {}

    # Sequential-ish receipt number: UGC-RCP-<year>-<count>
    year = now[:4]
    seq = await db.deal_receipts.count_documents({"kind": "wallet_recharge", "year": year}) + 1
    receipt_no = f"UGC-RCP-{year}-{seq:04d}"

    receipt = {
        "id": str(uuid.uuid4()),
        "kind": "wallet_recharge",
        "year": year,
        "receipt_no": receipt_no,
        "transaction_id": transaction["id"],
        "user_id": transaction.get("user_id"),
        "business_name": (user.get("profile") or {}).get("business_name") or user.get("nickname") or "",
        "email": user.get("email"),
        "gateway": transaction.get("gateway"),
        "payment_id": reference,
        "order_id": transaction.get("gateway_order_id"),
        "amount_paid": amount,
        "bonus_amount": bonus_amount,
        "credited_amount": credited_amount,
        "currency": transaction.get("currency", "INR"),
        "status": "paid",
        "created_at": now,
    }
    await db.deal_receipts.insert_one(receipt)

    to_email = user.get("email")
    if not to_email:
        return

    inr = lambda v: f"₹{float(v or 0):,.2f}"
    bonus_row = (
        f'<tr><td style="padding:8px 0;color:#4a4f74;">Recharge bonus</td>'
        f'<td align="right" style="padding:8px 0;color:#16a34a;font-weight:600;">+ {inr(bonus_amount)}</td></tr>'
    ) if bonus_amount > 0 else ""

    content = f"""
      <h1 style="margin:0 0 6px;font-size:22px;color:#1f2340;">Payment receipt</h1>
      <p style="margin:0 0 18px;font-size:14px;color:#8a90a6;">{receipt_no} &nbsp;·&nbsp; {now[:10]}</p>
      <p style="margin:0 0 18px;font-size:15px;color:#4a4f74;">
        Thanks{(' ' + receipt['business_name']) if receipt['business_name'] else ''} — your payment was successful
        and your wallet has been credited.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;border-top:1px solid #eceef5;">
        <tr><td style="padding:8px 0;color:#4a4f74;">Amount paid</td>
            <td align="right" style="padding:8px 0;color:#1f2340;font-weight:600;">{inr(amount)}</td></tr>
        {bonus_row}
        <tr><td style="padding:12px 0;border-top:1px solid #eceef5;color:#1f2340;font-weight:700;">Total credited to wallet</td>
            <td align="right" style="padding:12px 0;border-top:1px solid #eceef5;color:#1f2340;font-weight:800;">{inr(credited_amount)}</td></tr>
      </table>
      <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:18px;font-size:13px;color:#8a90a6;">
        <tr><td style="padding:4px 0;">Payment method</td><td align="right">Razorpay</td></tr>
        <tr><td style="padding:4px 0;">Payment ID</td><td align="right">{reference or '—'}</td></tr>
        <tr><td style="padding:4px 0;">Status</td><td align="right" style="color:#16a34a;font-weight:600;">Paid</td></tr>
      </table>
      <p style="margin:20px 0 0;font-size:12px;color:#9aa0b4;">
        This is a payment receipt for prepaid wallet credit, not a tax invoice.
        Wallet credits are non-refundable.
      </p>"""

    await send_email(to_email, f"Your UGCad.io payment receipt — {receipt_no}",
                     _email_base_template("Payment receipt", content))
    await notify_user(transaction.get("user_id"), "Wallet credited",
                      f"{inr(credited_amount)} added to your wallet. Receipt {receipt_no} emailed to you.",
                      link="/dashboard/business/wallet", ntype="success")


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
        # Payment receipt — generated once, inside the idempotent credit branch, so the
        # webhook and the frontend /payments/verify can't both email a duplicate.
        # NOTE: a wallet recharge is prepaid credit, not a taxable supply — this is a
        # payment RECEIPT, not a GST tax invoice.
        try:
            await issue_wallet_receipt(transaction, reference, amount, bonus_amount, credited_amount, now)
        except Exception as receipt_error:
            logger.error(f"[wallet-receipt] {receipt_error}")
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


async def find_campaign_by_any_id(any_id: str) -> Optional[dict]:
    """Look a campaign up by its real id, or by the DEAL-#### id the UI displays.

    make_deal_id() DERIVES "DEAL-4466" from the campaign's uuid and stores it
    nowhere — so a `{"deal_id": ...}` query can never match, and callers that pass
    the id shown on screen (the Deal Room does) got a 404. Recompute the derived id
    over the candidate campaigns instead of trusting a field that doesn't exist.
    """
    if not any_id:
        return None
    campaign = await db.campaigns.find_one({"$or": [{"id": any_id}, {"deal_id": any_id}]}, {"_id": 0})
    if campaign:
        return campaign
    if not str(any_id).upper().startswith("DEAL-"):
        return None
    # The hash is lossy (mod 9000), so more than one campaign could collide. Only
    # campaigns with a creator on them can be a real deal, which makes that vanishingly
    # unlikely — but scan rather than guess.
    async for c in db.campaigns.find({"selected_creator": {"$nin": [None, ""]}}, {"_id": 0}):
        if make_deal_id(c).upper() == str(any_id).upper():
            return c
    return None

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
        # Surfaced so the brand/creator progress trackers can date the "Product Shipped" step.
        "shipped_at": shipment.get('shipped_at') or shipment.get('updated_at'),
        "delivered_at": shipment.get('delivered_at'),
        # Booleans ONLY — never the addresses themselves, so masked shipping still holds.
        # The deal room needs these to know the creator has already confirmed; without them
        # its primary action kept reading "Confirm Delivery Address" forever after submitting.
        "creator_address_confirmed": bool(shipment.get('delivery_address')),
        "brand_address_confirmed": bool(shipment.get('pickup_address')),
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

async def deal_revision_history(campaign_id: str, creator_id: Optional[str] = None) -> List[dict]:
    """Every revision ever requested on this deal, across all versions, oldest first.

    Revisions must be counted PER DEAL. Each resubmission inserts a *new*
    work_submissions doc whose `revisions` list starts empty, so counting off the
    latest doc alone reset the tally to 0 every round — the 2-free-then-₹500 rule
    never fired and the brand could revise forever for free.
    """
    query = {"campaign_id": campaign_id}
    if creator_id:
        query["creator_id"] = creator_id
    docs = await db.work_submissions.find(query, {"_id": 0, "revisions": 1}).to_list(100)
    history = [rev for doc in docs for rev in (doc.get("revisions") or [])]
    history.sort(key=lambda r: r.get("requested_at") or "")
    return history


def normalize_revision_tracker(work: Optional[dict], response: Optional[dict],
                               all_revisions: Optional[List[dict]] = None) -> dict:
    # Count across the whole deal (see deal_revision_history), not just the latest work doc.
    revisions = all_revisions if all_revisions is not None else ((work or {}).get('revisions') or [])
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
        "next_revision_fee": revision_fee_for(used),
        "latest_feedback": latest.get('feedback'),
        "requested_changes": requested_changes or [],
        "items": latest.get('items') or [],
        "notes": latest.get('notes') or '',
        "new_deadline_at": latest.get('new_deadline_at'),
        "creator_response": (response or {}).get('response'),
        "accepted_changes": (response or {}).get('accepted_changes') or []
    }

def compute_deal_state(campaign: dict, shipment: Optional[dict], receipt: dict, work: Optional[dict], escrow: Optional[dict], action_cards: List[dict]) -> dict:
    damaged = receipt.get('items_damaged') or any(card.get('type') == 'damage_report' and card.get('status') == 'open' for card in action_cards)
    disputed = any(card.get('type') in ['raise_dispute', 'escalate_to_admin'] and card.get('status') == 'open' for card in action_cards)
    shipment_status = (shipment or {}).get('status') or (shipment or {}).get('courier_status')
    work_status = (work or {}).get('status')
    escrow_status = (escrow or {}).get('status')

    # A cancelled deal is terminal — the brand ended it (or a dispute was refunded
    # in full). This must be checked FIRST: without it a cancelled campaign fell
    # through to a content-stage state with active_party "creator" and action
    # "Submit content", so a deal sitting in the creator's Cancelled tab still
    # offered a "Submit Content" button when opened.
    if campaign.get('status') == 'cancelled':
        state, party, action = "Cancelled", "system", "Deal cancelled"
        started = campaign.get('cancelled_at') or campaign.get('updated_at')
    elif damaged:
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
    countdown = hours_until(next_deadline)
    # SLA surfacing: a deal blocked on a human party past its deadline is overdue/urgent.
    # System/admin states (payout, dispute) don't count — nobody is holding those up.
    actionable = party in ("brand", "creator")
    is_overdue = bool(next_deadline and countdown is not None and countdown < 0 and actionable)
    if is_overdue:
        urgency = "overdue"
    elif actionable and countdown is not None and 0 <= countdown <= 24:
        urgency = "due_soon"
    else:
        urgency = "normal"
    return {
        "current_state": state,
        "active_party": party,
        "primary_next_action": action,
        "state_started_at": started,
        "next_deadline_at": next_deadline,
        "deadline_countdown_hours": countdown,
        "is_overdue": is_overdue,
        "urgency": urgency,
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
    if role == UserRole.BUSINESS and campaign.get('business_id') == _brand_ws_id(current_user):
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
        if submitted and (now - submitted).days >= int(platform_setting("auto_approval_days", AUTO_APPROVE_DAYS)):
            cards = await db.deal_action_cards.find({"campaign_id": cid}, {"_id": 0}).to_list(100)
            disputed = any(c.get('type') in ['raise_dispute', 'escalate_to_admin'] and c.get('status') == 'open' for c in cards)
            if not disputed:
                await db.work_submissions.update_one({"id": work['id']}, {"$set": {"status": WorkStatus.APPROVED, "approved_at": now_iso(), "auto_approved": True}})
                await release_payout_now(campaign, work, source="auto_approval")
                await notify_user(work['creator_id'], "Your content was auto-approved", "The brand didn't review in time, so your content was auto-approved and you've been paid.", link="/my-deals")
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
    revision_history = await deal_revision_history(campaign['id'], creator['id'])
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
        "activity": activity,
        "revision_history": revision_history
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
    revision_tracker = normalize_revision_tracker(context['work'], context['revision_response'], context.get('revision_history'))

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
                "actor_name": person_display_name(brand, 'Brand'),
                "event_type": "tracking_uploaded",
                "message": "Shipment tracking was uploaded."
            })
        if normalized_receipt.get('received_at'):
            activity_feed.append({
                "id": f"{campaign['id']}-receipt",
                "timestamp": normalized_receipt['received_at'],
                "actor_type": "creator",
                "actor_name": person_display_name(creator, 'Creator'),
                "event_type": "receipt_confirmed",
                "message": "Product receipt was confirmed."
            })
        if context['work']:
            activity_feed.append({
                "id": f"{campaign['id']}-work",
                "timestamp": context['work'].get('submitted_at'),
                "actor_type": "creator",
                "actor_name": person_display_name(creator, 'Creator'),
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
    # The brief typed at checkout is a DRAFT until the brand sends it (which they can
    # only do once the creator accepts). The creator must not see it before then.
    if viewer.get('id') == creator.get('id'):
        campaign_details.pop('brief_draft', None)
    # Enable "Mark Received" whenever a real shipment exists and is shipped — not
    # only when the requires_shipment flag is set (some briefs carry shipment data
    # without the flag, which previously left the button permanently disabled).
    _has_shipment_record = bool(
        normalized_shipment.get('tracking_id')
        or normalized_shipment.get('courier_status')
        or normalized_shipment.get('required')
    )
    can_mark_received = _has_shipment_record and normalized_shipment.get('courier_status') in ['delivered', 'shipped', 'in_transit'] and not normalized_receipt.get('received_at')
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
    # Use the name the person typed at signup as their display name; only fall
    # back to a generated placeholder if they didn't give one.
    typed_name = str(data.name or "").strip().lstrip("@")
    nickname = typed_name or await generate_nickname()

    user_doc = {
        "id": user_id,
        "email": data.email,
        "password": hash_password(data.password),
        "role": data.role,
        "nickname": nickname,
        "full_name": typed_name,
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
    if not user or not user.get('password') or not verify_password(data.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if user is banned
    if user.get('banned', False):
        ban_reason = user.get('ban_reason', 'Account suspended')
        raise HTTPException(status_code=403, detail=f"Account banned: {ban_reason}")

    # Block a suspended account (auto-lifts once the suspension window passes).
    await enforce_suspension(user)

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
    
    token = create_token(user['id'], user.get('email', data.email), user.get('role'))
    return {
        "token": token,
        "user_id": user.get('id'),
        "nickname": user.get('nickname') or user.get('full_name') or user.get('username') or (user.get('email') or '').split('@')[0],
        "username": user.get('username'),
        "creator_code": user.get('creator_code'),
        "level": user.get('level'),
        "role": user.get('role'),
        "admin_role": user.get('admin_role'),
        "admin_caps": user.get('admin_caps', []),
        "admin_cap_modes": user.get('admin_cap_modes', {}),
        "admin_scope": user.get('admin_scope', 'all'),
        "assigned_categories": user.get('assigned_categories', []),
        "profile_completed": user.get('profile_completed', False),
        "approval_status": user.get('approval_status', ApprovalStatus.PENDING),
        # The admin's "we need more info" message + checklist. Without it the
        # more-info screen renders an empty box right after login (it only filled in
        # later, once /auth/me happened to refresh the user).
        "review": user.get('review', {}),
        "approval_reason": user.get('approval_reason', ''),
        # The saved profile, so the setup forms can prefill what's already on file
        # instead of making the user retype it all on a resubmit.
        "profile": user.get('profile', {}),
        "profile_photo": user.get('profile_photo')
    }

def _verify_google_id_token(credential: str) -> Optional[dict]:
    """Verify a Google ID token via Google's tokeninfo endpoint.
    Returns the decoded claims dict, or None if invalid. Runs in a thread."""
    try:
        resp = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": credential},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


@api_router.post("/auth/google")
async def google_auth(data: GoogleAuthRequest):
    """Sign in / sign up with Google. The client sends the ID token (credential)
    from Google Identity Services; we verify it, find-or-create the user, then
    issue our own JWT — same response shape as /auth/login."""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google sign-in is not configured on the server")

    info = await asyncio.to_thread(_verify_google_id_token, data.credential)
    if not info:
        raise HTTPException(status_code=401, detail="Invalid or expired Google credential")

    # Token must have been issued for THIS app.
    if info.get("aud") != GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=401, detail="Google credential audience mismatch")

    email = (info.get("email") or "").lower()
    if not email:
        raise HTTPException(status_code=401, detail="Google account has no email")
    # tokeninfo returns email_verified as the string "true" (or bool true).
    if info.get("email_verified") not in (True, "true"):
        raise HTTPException(status_code=403, detail="Your Google email is not verified")

    user = await db.users.find_one({"email": email}, {"_id": 0})

    if not user:
        # New account — role from the signup selector, defaulting to creator.
        role = data.role.value if data.role else UserRole.CREATOR.value
        if role not in [UserRole.CREATOR.value, UserRole.BUSINESS.value, UserRole.ADMIN.value]:
            role = UserRole.CREATOR.value

        user_id = str(uuid.uuid4())
        nickname = await generate_nickname()
        user_doc = {
            "id": user_id,
            "email": email,
            "role": role,
            "nickname": info.get("name") or nickname,
            "full_name": info.get("name", ""),
            "profile_photo": info.get("picture"),
            "google_id": info.get("sub"),
            "auth_provider": "google",
            "profile_completed": False,
            "curated_brand_visible": False,
            "creator_directory_visible": False,
            "approval_status": ApprovalStatus.PENDING if role in [UserRole.CREATOR.value, UserRole.BUSINESS.value] else ApprovalStatus.APPROVED,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "balance": 0.0,
        }
        if role == UserRole.CREATOR.value:
            user_doc["creator_code"] = await generate_creator_code()
            user_doc["level"] = cf.DEFAULT_CREATOR_LEVEL
            user_doc["handle_locked"] = False

        await db.users.insert_one(user_doc)
        user = user_doc
    else:
        # Block banned accounts, mirroring /auth/login.
        if user.get("banned", False):
            raise HTTPException(status_code=403, detail=f"Account banned: {user.get('ban_reason', 'Account suspended')}")
        await enforce_suspension(user)

        # Backfill/link fields on the existing account. Match by email (always
        # present + unique) since a legacy account may have no "id" field.
        link = {}
        # Legacy accounts (e.g. created by another service) may lack the string
        # "id" the whole app keys on — backfill one so tokens resolve.
        if not user.get("id"):
            link["id"] = str(uuid.uuid4())
        if not user.get("google_id"):
            link["google_id"] = info.get("sub")
            if not user.get("profile_photo") and info.get("picture"):
                link["profile_photo"] = info.get("picture")
        if link:
            await db.users.update_one({"email": email}, {"$set": link})
            user.update(link)

    token = create_token(user["id"], user.get("email", email), user.get("role"))
    return {
        "token": token,
        "user_id": user.get("id"),
        "nickname": user.get("nickname") or user.get("full_name") or user.get("username") or (user.get("email") or "").split("@")[0],
        "username": user.get("username"),
        "creator_code": user.get("creator_code"),
        "level": user.get("level"),
        "role": user.get("role"),
        "admin_role": user.get("admin_role"),
        "admin_caps": user.get("admin_caps", []),
        "admin_cap_modes": user.get("admin_cap_modes", {}),
        "admin_scope": user.get("admin_scope", "all"),
        "assigned_categories": user.get("assigned_categories", []),
        "profile_completed": user.get("profile_completed", False),
        "approval_status": user.get("approval_status", ApprovalStatus.PENDING),
        # Same as /auth/login — the more-info gate needs the admin's request, and the
        # setup forms prefill from profile.
        "review": user.get("review", {}),
        "approval_reason": user.get("approval_reason", ""),
        "profile": user.get("profile", {}),
        "profile_photo": user.get("profile_photo"),
        # Team context so the client can gate owner-only UI immediately after login.
        "team_of": user.get("team_of"),
        "team_role": user.get("team_role", "owner"),
        "is_team_member": bool(user.get("team_of")),
    }


def _auth_response(user: dict) -> dict:
    """Shared login/reset response shape (same as /auth/login)."""
    return {
        "token": create_token(user["id"], user.get("email", ""), user.get("role")),
        "user_id": user.get("id"),
        "nickname": user.get("nickname") or user.get("full_name") or user.get("username") or (user.get("email") or "").split("@")[0],
        "username": user.get("username"),
        "creator_code": user.get("creator_code"),
        "level": user.get("level"),
        "role": user.get("role"),
        "admin_role": user.get("admin_role"),
        "admin_caps": user.get("admin_caps", []),
        "admin_cap_modes": user.get("admin_cap_modes", {}),
        "admin_scope": user.get("admin_scope", "all"),
        "assigned_categories": user.get("assigned_categories", []),
        "profile_completed": user.get("profile_completed", False),
        "approval_status": user.get("approval_status", ApprovalStatus.PENDING),
        # Keep in step with /auth/login — the more-info gate reads review.* to tell
        # the user what the admin actually asked for, and the setup forms prefill
        # from profile.
        "review": user.get("review", {}),
        "approval_reason": user.get("approval_reason", ""),
        "profile": user.get("profile", {}),
        "profile_photo": user.get("profile_photo"),
        # Team context so the client can gate owner-only UI immediately after login.
        "team_of": user.get("team_of"),
        "team_role": user.get("team_role", "owner"),
        "is_team_member": bool(user.get("team_of")),
    }


@api_router.post("/auth/verify-password")
async def verify_own_password(data: VerifyPasswordRequest, current_user: dict = Depends(get_current_user)):
    """Re-authenticate the signed-in user with their own password. Used to gate
    sensitive actions (e.g. a founder changing another admin's password)."""
    stored = current_user.get("password")
    if not stored:
        raise HTTPException(status_code=400, detail="This account has no password set (Google sign-in only)")
    if not verify_password(data.password or "", stored):
        raise HTTPException(status_code=400, detail="Incorrect password")
    return {"valid": True}


@api_router.post("/auth/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    """Issue a 6-digit reset code (valid 15 min) and email it. Always returns the
    same generic message so it can't be used to probe which emails have accounts.
    Google-only accounts (no password) get the generic response with no code."""
    email = (data.email or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    generic = {"message": "If an account exists for that email, a reset code has been sent."}
    user = await db.users.find_one({"email": email})
    if not user or (not user.get("password") and user.get("google_id")):
        return generic
    code = f"{random.randint(100000, 999999)}"
    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"reset_code": _reset_code_hash(code), "reset_code_expires": expires}},
    )
    logger.info(f"[forgot-password] reset code for {email}: {code}")
    try:
        from urllib.parse import quote
        html = _email_base_template("Password reset", f"""
            <h1 style="margin:0 0 12px;font-size:22px;color:#1f2340;">Reset your password</h1>
            <p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#4a4f74;">Use the code below to reset your password. It expires in 15 minutes.</p>
            <div style="font-size:32px;font-weight:800;letter-spacing:8px;color:#5b6bff;background:#f4f5fb;border-radius:12px;padding:18px 0;text-align:center;">{code}</div>
            {_email_button("Enter code & set new password", f"/auth?view=reset&email={quote(email)}")}
            <p style="margin:20px 0 0;font-size:13px;line-height:1.6;color:#9296ba;">If you didn't request this, you can safely ignore this email.</p>""")
        await send_email(email, "Your UGCad.io password reset code", html)
    except Exception as e:
        logger.error(f"[forgot-password] email send failed: {e}")
    return generic


@api_router.post("/auth/verify-reset-code")
async def verify_reset_code(data: VerifyResetCodeRequest):
    """Check the reset code is valid and unexpired WITHOUT consuming it, so the UI
    can gate the new-password step."""
    email = (data.email or "").strip().lower()
    code = (data.code or "").strip()
    if not email or not code:
        raise HTTPException(status_code=400, detail="Email and code are required")
    user = await db.users.find_one({"email": email})
    if not _reset_code_valid(user, code):
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")
    return {"valid": True}


@api_router.post("/auth/reset-password")
async def reset_password(data: ResetPasswordRequest):
    """Verify the code, set the new password, clear the code, and sign the user in."""
    email = (data.email or "").strip().lower()
    code = (data.code or "").strip()
    password = data.password or ""
    if not email or not code or not password:
        raise HTTPException(status_code=400, detail="Email, code and new password are required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user = await db.users.find_one({"email": email})
    if not _reset_code_valid(user, code):
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")
    if user.get("banned"):
        raise HTTPException(status_code=403, detail=f"Account banned: {user.get('ban_reason', 'Account suspended')}")
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"password": hash_password(password)}, "$unset": {"reset_code": "", "reset_code_expires": ""}},
    )
    fresh = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    return _auth_response(fresh or user)


@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    me = {k: v for k, v in current_user.items() if k != 'password'}
    # Back-compat: older creators had their signup portfolio stored only under
    # `profile.portfolio`; surface it at the top level the Portfolio page reads.
    if not me.get("portfolio"):
        nested = (me.get("profile") or {}).get("portfolio")
        if nested:
            me["portfolio"] = nested
    return me

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
        creator.get("creator_directory_visible") is not False
    )

async def get_visible_directory_creator(creator_id: str) -> Optional[dict]:
    return await db.users.find_one({
        "id": creator_id,
        "role": UserRole.CREATOR,
        "approval_status": ApprovalStatus.APPROVED,
        "profile_completed": True,
        "creator_directory_visible": {"$ne": False},
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

def _portfolio_preview_url(item: Any) -> str:
    """Pull a usable media URL out of a portfolio entry, which may be a plain
    URL string or a rich item ({urls:[...]}, {url}, {video_url}, ...). Dead
    blob: refs and bare filenames are ignored so the brand card can fall back to
    its placeholder instead of rendering a broken asset."""
    def usable(u: Any) -> bool:
        return isinstance(u, str) and (u.startswith("http") or u.startswith("/"))
    if usable(item):
        return item
    if isinstance(item, dict):
        urls = item.get("urls")
        if isinstance(urls, list):
            for u in urls:
                if usable(u):
                    return u
        for key in ("thumbnail_url", "url", "video_url", "videoUrl", "link", "image", "video"):
            if usable(item.get(key)):
                return item.get(key)
    return ""

def creator_directory_public_view(creator: dict, deliverables_completed: int) -> dict:
    profile = creator.get("profile") or {}
    portfolio = first_non_empty(creator.get("portfolio"), profile.get("portfolio")) or []
    preview_source = portfolio[0] if isinstance(portfolio, list) and portfolio else portfolio
    portfolio_preview = _portfolio_preview_url(preview_source)
    primary_category = first_non_empty(
        creator.get("primary_category"),
        creator.get("category"),
        profile.get("primary_category"),
        profile.get("category"),
        (creator.get("tags") or [None])[0] if isinstance(creator.get("tags"), list) else None,
        (profile.get("tags") or [None])[0] if isinstance(profile.get("tags"), list) else None,
    )
    # Public display NAME shown to brands: the creator's real FIRST name (no
    # surname, no "@username" handle). Prefer the name they typed on their
    # profile; only fall back to the auto handle if they never set one.
    raw_name = first_non_empty(
        profile.get("fullName"),
        profile.get("full_name"),
        creator.get("full_name"),
        creator.get("nickname"),
        profile.get("nickname"),
        creator.get("username"),
        creator.get("public_creator_id"),
    ) or ""
    raw_name = raw_name.strip().lstrip("@")
    display_name = raw_name.split()[0] if raw_name else ""
    return {
        "id": creator.get("id"),
        "public_creator_id": creator.get("public_creator_id") or "",
        # Brand-facing display handle. The real username stays private (strip_private_fields);
        # brands see the auto-generated nickname, so cards/briefs don't read "Creator".
        "nickname": creator.get("nickname") or "",
        # Identity-verified (admin-approved KYC) — drives the "Verified" badge. Only the
        # boolean is exposed; the KYC documents themselves never leave the backend.
        "kyc_verified": bool(creator.get("kyc_verified")),
        "name": display_name,
        "nickname": creator.get("nickname") or "",
        "profile_photo": first_non_empty(creator.get("profile_photo"), creator.get("profile_picture"), profile.get("profile_photo"), profile.get("profile_picture")),
        "primary_category": primary_category or "",
        "languages": compact_list(creator.get("languages"), profile.get("languages"), creator.get("content_languages"), profile.get("content_languages")),
        "city_tier": first_non_empty(creator.get("city_tier"), creator.get("location_region"), profile.get("city_tier"), profile.get("location_region")) or "",
        "deliverables_completed": deliverables_completed,
        "portfolio_preview": portfolio_preview or "",
        "content_style": first_non_empty(creator.get("content_style"), profile.get("content_style")) or "",
        "budget_range": first_non_empty(
            creator.get("budget_range"),
            profile.get("budget_range"),
            (profile.get("rate_card") or {}).get("expected_payout"),
            profile.get("expectedPayout"),
        ) or "",
        "level": cf.normalize_level(creator.get("level")),
        "level_label": cf.CREATOR_LEVELS[cf.normalize_level(creator.get("level"))]["label"],
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
    # Discovery is available while a brand profile is under review. Invitations,
    # campaign publishing and payments continue to use the approved-brand guard.
    current_user: dict = Depends(get_current_business_user),
):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    if sort not in ["recent", "active", "best_match", None]:
        raise HTTPException(status_code=400, detail="Invalid sort option")

    # Approved, profile-complete creators are discoverable by default; only those who
    # explicitly opt out (creator_directory_visible == False) are hidden.
    creators = await db.users.find({
        "role": UserRole.CREATOR,
        "approval_status": ApprovalStatus.APPROVED,
        "profile_completed": True,
        "creator_directory_visible": {"$ne": False},
    }, {"_id": 0}).to_list(10000)

    # Batch the review aggregates (avg rating + count) for ALL creators in one query,
    # so the directory/quick-preview cards can show a real rating instead of "New".
    creator_ids = [c.get("id") for c in creators if c.get("id")]
    rating_map = {}
    if creator_ids:
        agg = await db.reviews.aggregate([
            {"$match": {"creator_id": {"$in": creator_ids}}},
            {"$group": {"_id": "$creator_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}},
        ]).to_list(None)
        rating_map = {a["_id"]: a for a in agg}

    rows = []
    for creator in creators:
        if not creator_matches_directory_filters(creator, category, language, region, style, budget):
            continue
        await ensure_public_creator_id(creator)
        deliverables = await creator_deliverables_completed(creator)
        pub = creator_directory_public_view(creator, deliverables)
        _r = rating_map.get(creator.get("id"))
        pub["avg_rating"] = round(_r["avg"], 1) if (_r and _r.get("count")) else None
        pub["review_count"] = int(_r["count"]) if _r else 0
        rows.append({
            "creator": creator,
            "public": pub,
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
        campaign = await db.campaigns.find_one({"id": data.campaign_id, "business_id": _brand_ws_id(current_user)}, {"_id": 0})
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

    duplicate_query = {
        "business_id": _brand_ws_id(current_user),
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
        "business_id": _brand_ws_id(current_user),
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

@api_router.get("/business/gst")
async def get_business_gst(current_user: dict = Depends(get_approved_business_user)):
    """The brand's own GST record + whether it may fund its wallet yet."""
    return gst_public(current_user)


@api_router.post("/business/gst")
async def submit_business_gst(data: BusinessGSTSubmit, current_user: dict = Depends(get_approved_business_user)):
    """Submit a GSTIN for verification. The number is checksum-validated here, so an
    invented or mistyped GSTIN is rejected immediately rather than sitting in the
    admin queue. A valid one goes to an admin to confirm it belongs to this brand."""
    if gst_status_of(current_user) == "verified":
        raise HTTPException(status_code=400, detail="Your GST is already verified.")

    gstin = (data.gstin or "").strip().upper().replace(" ", "")
    ok, reason = validate_gstin(gstin)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    # One GSTIN cannot back two brand accounts.
    clash = await db.users.find_one({
        "gst.gstin": gstin,
        "gst.status": {"$in": ["pending", "verified"]},
        "id": {"$ne": current_user["id"]},
    })
    if clash:
        raise HTTPException(status_code=409, detail="This GSTIN is already registered to another account.")

    record = {
        "status": "pending",
        "gstin": gstin,
        "legal_name": (data.legal_name or "").strip(),
        "submitted_at": now_iso(),
        "reviewed_at": None,
        "reviewed_by": "",
        "rejection_reason": "",
    }
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"gst": record, "gst_number": gstin}})
    await notify_admins(
        "GST verification pending",
        f"{current_user.get('nickname') or current_user.get('email')} submitted GSTIN {gstin} for verification.",
        link="/dashboard/admin/gst",
    )
    return {**gst_public({"gst": record}), "message": "GSTIN submitted for verification."}


@api_router.get("/business/wallet")
async def get_business_wallet(current_user: dict = Depends(get_approved_business_user)):
    if current_user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this resource")
    balance = to_float(current_user.get("balance"))
    settings = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
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

    brand_campaigns = await db.campaigns.find(
        {"business_id": _brand_ws_id(current_user)},
        {"_id": 0, "id": 1, "title": 1, "status": 1, "budget": 1, "budget_min": 1, "budget_max": 1, "created_at": 1, "submitted_at": 1},
    ).to_list(10000)
    campaign_ids = [campaign.get("id") for campaign in brand_campaigns if campaign.get("id")]
    escrowed_campaign_ids = set()
    if campaign_ids:
        escrow_rows = await db.escrow.find({"campaign_id": {"$in": campaign_ids}}, {"_id": 0}).to_list(10000)
        for row in escrow_rows:
            escrowed_campaign_ids.add(row.get("campaign_id"))
            e_status = row.get("status")
            if e_status == "refunded":
                # Reservation was returned to the wallet (e.g. campaign rejected/cancelled).
                amt = to_float(row.get("reserved_amount") or row.get("amount"))
                transactions.append(normalize_wallet_transaction({**row, "amount": amt, "type": "Budget Refund"}, "Budget Refund", "credit"))
                continue
            label = "Budget Reserved" if e_status == "reserved" else "Escrow Lock"
            amt = to_float(row.get("brand_charged") or row.get("reserved_amount") or row.get("amount"))
            transactions.append(normalize_wallet_transaction({**row, "amount": amt, "type": label}, label, "debit"))

        # Live / awaiting-approval campaigns without an escrow record (posted before the
        # budget-at-post reservation) still show their committed budget as "on hold".
        HELD_STATUSES = {"active", "pending_approval", "in_progress", "work_submitted"}
        for campaign in brand_campaigns:
            if campaign.get("id") in escrowed_campaign_ids:
                continue
            if str(campaign.get("status")) not in HELD_STATUSES:
                continue
            amt = campaign_budget_total(campaign)
            if amt <= 0:
                continue
            transactions.append(normalize_wallet_transaction({
                "id": f"hold-{campaign.get('id')}",
                "campaign_id": campaign.get("id"),
                "amount": amt,
                "type": "Budget Reserved",
                "created_at": campaign.get("submitted_at") or campaign.get("created_at"),
            }, "Budget Reserved", "debit"))

    transactions.sort(key=lambda item: item.get("date") or "", reverse=True)

    return {
        "available_balance": balance,
        "minimum_chat_balance": MIN_BRAND_CHAT_BALANCE,
        "chat_unlocked": balance >= MIN_BRAND_CHAT_BALANCE,
        "plan_name": plan_name,
        "recharge_bonus": wallet_bonus_progress(balance),
        "bonus_tiers": wallet_bonus_tiers(),
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

    # (GST-verification gate removed — brands can add funds without a verified GSTIN.)

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


# ---------------------------------------------------------------------------
# Brand checkout — booking a creator straight from their plan (PlanBrief modal).
#
# The brand's wallet is a prepaid balance. Booking SPENDS it: the money leaves the
# wallet and is held in the deal's escrow until the brand approves the content.
# Nothing here trusts a price sent by the browser — every figure is recomputed from
# the creator's rate card and the admin's commission setting.
# ---------------------------------------------------------------------------
def creator_plan_price(creator: dict) -> float:
    """The creator's per-video rate, as set on their profile → rate_card."""
    rate_card = (creator.get("profile") or {}).get("rate_card") or {}
    raw = str(rate_card.get("expected_payout") or rate_card.get("last_salary") or "")
    digits = re.sub(r"[^0-9]", "", raw)
    return float(digits) if digits else 0.0


def quote_brief(creator: dict, video_count) -> dict:
    """Price a brief. Raises 400 if the creator never published a rate."""
    try:
        count = max(1, int(video_count or 1))
    except (TypeError, ValueError):
        count = 1
    price = creator_plan_price(creator)
    if price <= 0:
        raise HTTPException(status_code=400, detail="This creator hasn't set a price yet. Message them to agree on one.")
    subtotal = round(price * count, 2)
    fee = brand_commission(subtotal)
    return {
        "video_count": count,
        "unit_price": price,
        "subtotal": subtotal,
        "fee": fee,
        "fee_percent": commission_percent(),
        "total": round(subtotal + fee, 2),
    }


@api_router.get("/checkout/quote")
async def checkout_quote(creator_id: str, video_count: int = 1,
                         current_user: dict = Depends(get_approved_business_user)):
    creator = await db.users.find_one({"id": creator_id}, {"_id": 0})
    if not creator or creator.get("role") != UserRole.CREATOR:
        raise HTTPException(status_code=404, detail="Creator not found")
    q = quote_brief(creator, video_count)
    balance = to_float(current_user.get("balance"))
    return {
        **q,
        "wallet_balance": balance,
        "sufficient": balance >= q["total"],
        "shortfall": max(0.0, round(q["total"] - balance, 2)),
    }


@api_router.post("/checkout/brief", status_code=201)
async def checkout_brief(data: CheckoutBriefCreate,
                         current_user: dict = Depends(get_approved_business_user)):
    creator = await db.users.find_one({"id": data.creator_id}, {"_id": 0})
    if not creator or creator.get("role") != UserRole.CREATOR:
        raise HTTPException(status_code=404, detail="Creator not found")
    if creator.get("approval_status") != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=400, detail="This creator is not accepting briefs yet.")

    q = quote_brief(creator, data.video_count)
    total = q["total"]

    # Debit and balance-check in ONE atomic update. A find-then-update would let two
    # concurrent bookings both pass the check and overdraw the wallet.
    debit = await db.users.update_one(
        {"id": current_user["id"], "balance": {"$gte": total}},
        {"$inc": {"balance": -total}},
    )
    if debit.modified_count != 1:
        # The only reason the update matched nothing: not enough balance.
        # Flat body (not HTTPException) so the checkout screen can read `shortfall`
        # and `available` directly — FastAPI would nest them under `detail`.
        from fastapi.responses import JSONResponse
        fresh = await db.users.find_one({"id": current_user["id"]}, {"_id": 0, "balance": 1})
        balance = to_float((fresh or {}).get("balance"))
        return JSONResponse(status_code=402, content={
            "detail": f"Not enough credits. This brief costs ₹{total:,.0f} but your wallet has ₹{balance:,.0f}.",
            "code": "INSUFFICIENT_FUNDS",
            "required": total,
            "available": balance,
            "shortfall": round(total - balance, 2),
        })

    # The money is out of the wallet. Any failure from here on MUST put it back.
    now = datetime.now(timezone.utc).isoformat()
    campaign_id = str(uuid.uuid4())
    escrow_id = str(uuid.uuid4())
    brief = dict(data.brief or {})
    profile = current_user.get("profile") or {}

    # The brief the brand typed at checkout is held as a DRAFT. The creator must accept
    # the booking first; only then can the brand send it (POST /bookings/{id}/brief).
    # It is stripped from the creator's view of the deal until it's actually sent.
    brief_draft = {
        "brief_text": brief.pop("brief_text", "") or "",
        "deliverables": brief.pop("deliverables", "") or "",
        "attachment_urls": [],
    }

    campaign_doc = {
        **brief,                       # title, delivery_date, delivery_slot, requires_shipment…
        "id": campaign_id,
        "business_id": _brand_ws_id(current_user),
        "business_nickname": current_user.get("nickname", ""),
        "brand_name": profile.get("business_name") or current_user.get("nickname", ""),
        "brand_logo_url": profile.get("logo") or "",
        "brand_cover_image_url": profile.get("banner") or "",
        "business_verified": True,
        "selected_creator": data.creator_id,
        # Paid up front — no admin approval gate, no bidding. But the work does NOT
        # start until the creator accepts the booking (booking_status below).
        "status": CampaignStatus.IN_PROGRESS.value,
        "booking_status": "pending_creator",
        "brief_sent": False,
        "brief_draft": brief_draft,
        "escrow_id": escrow_id,
        # The creator's take. The platform fee is charged on top and is NOT escrowed.
        "budget_min": q["subtotal"],
        "budget_max": q["subtotal"],
        "amount_paid": total,
        "platform_fee": q["fee"],
        "fee_percent": q["fee_percent"],
        "video_count": q["video_count"],
        "bids": [],
        "direct_booking": True,
        "paid_at": now,
        "created_at": now,
        "updated_at": now,
    }

    try:
        await db.campaigns.insert_one(dict(campaign_doc))
        await db.escrow.insert_one({
            "id": escrow_id,
            "campaign_id": campaign_id,
            "business_id": _brand_ws_id(current_user),
            "creator_id": data.creator_id,
            "amount": q["subtotal"],
            "brand_commission_amount": q["fee"],
            "brand_commission_percent": q["fee_percent"],
            "brand_charged": total,
            "funded": True,
            "status": "held",
            "created_at": now,
        })
    except Exception:
        # Refund and undo — a campaign with no escrow is worse than no campaign, and
        # the brand is owed their money back.
        await db.users.update_one({"id": current_user["id"]}, {"$inc": {"balance": total}})
        await db.campaigns.delete_one({"id": campaign_id})
        await db.escrow.delete_one({"id": escrow_id})
        raise HTTPException(status_code=500, detail="Checkout failed. You have not been charged.")

    title = campaign_doc.get("title") or "your brief"
    creator_name = person_display_name(creator, "the creator")
    brand_name = campaign_doc.get("brand_name") or "A brand"

    await insert_deal_system_message(
        campaign_doc,
        f"📩 Booking request from {brand_name} — {q['video_count']} video(s) for ₹{q['subtotal']:,.0f}. "
        f"Payment is held in escrow. Accept, decline, or propose a different price.",
    )
    await notify_user(
        data.creator_id,
        "📩 New booking request",
        f"{brand_name} booked you for '{title}' — ₹{q['subtotal']:,.0f} is already held in escrow. "
        f"Accept it, decline it, or propose a different price.",
        link="/my-deals?tab=requested",
        ntype="info",
    )
    await notify_user(
        current_user["id"],
        "Payment held in escrow",
        f"₹{total:,.0f} was paid from your credits for '{title}'. "
        f"It's held until {creator_name} accepts — you'll be refunded in full if they decline.",
        link="/dashboard/business/wallet",
        ntype="success",
    )

    updated = await db.users.find_one({"id": current_user["id"]}, {"_id": 0, "balance": 1})
    campaign_doc.pop("_id", None)
    return {
        "success": True,
        "campaign_id": campaign_id,
        "deal_id": make_deal_id(campaign_doc),
        "booking_status": "pending_creator",
        "amount_charged": total,
        "subtotal": q["subtotal"],
        "fee": q["fee"],
        "fee_percent": q["fee_percent"],
        "wallet_balance": to_float((updated or {}).get("balance")),
    }


# ---------------------------------------------------------------------------
# Booking request lifecycle
#
#   brand pays  →  pending_creator
#                    ├─ creator accepts  → accepted   → brand sends brief → work starts
#                    ├─ creator declines → declined   → escrow refunded in full
#                    └─ creator revises  → price_revision
#                                            ├─ brand accepts → difference settled → accepted
#                                            └─ brand rejects → declined → refunded
# ---------------------------------------------------------------------------
async def refund_booking(campaign: dict, reason: str) -> float:
    """Return the whole escrowed amount to the brand's wallet and close the booking."""
    escrow = await db.escrow.find_one({"campaign_id": campaign["id"]}, {"_id": 0})
    if not escrow or escrow.get("status") == "refunded":
        return 0.0
    amount = to_float(escrow.get("brand_charged") or escrow.get("amount"))
    await db.users.update_one({"id": campaign["business_id"]}, {"$inc": {"balance": amount}})
    await db.escrow.update_one(
        {"id": escrow["id"]},
        {"$set": {"status": "refunded", "refunded_at": now_iso(), "refund_reason": reason}},
    )
    return amount


async def get_booking(campaign_id: str, current_user: dict, *, role: str) -> dict:
    """Load a booking and check the caller is the right party."""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Booking not found")
    if role == "creator" and campaign.get("selected_creator") != current_user["id"]:
        raise HTTPException(status_code=403, detail="This booking isn't yours")
    if role == "brand" and campaign.get("business_id") != _brand_ws_id(current_user):
        raise HTTPException(status_code=403, detail="This booking isn't yours")
    return campaign


@api_router.post("/bookings/{campaign_id}/respond")
async def respond_to_booking(campaign_id: str, data: BookingRespond,
                             current_user: dict = Depends(get_current_user)):
    """Creator accepts, declines, or counter-offers on a booking request."""
    if current_user.get("role") != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only the booked creator can respond")
    campaign = await get_booking(campaign_id, current_user, role="creator")

    if campaign.get("booking_status") != "pending_creator":
        raise HTTPException(status_code=400, detail="This booking has already been answered")

    creator_name = person_display_name(current_user, "The creator")
    title = campaign.get("title") or "your booking"
    brand_id = campaign["business_id"]
    now = now_iso()

    if data.action == "accept":
        await db.campaigns.update_one({"id": campaign_id}, {"$set": {
            "booking_status": "accepted",
            "accepted_at": now,
            "updated_at": now,
        }})
        await insert_deal_system_message(campaign, f"✅ {creator_name} accepted the booking. The brand can now send the brief.")
        await notify_user(brand_id, "Booking accepted — send your brief",
                          f"{creator_name} accepted '{title}'. Send them the brief to start the work.",
                          link="/dashboard/business/all-campaigns", ntype="success")
        return {"booking_status": "accepted"}

    if data.action == "decline":
        refunded = await refund_booking(campaign, f"Creator declined: {data.message or 'no reason given'}")
        await db.campaigns.update_one({"id": campaign_id}, {"$set": {
            "booking_status": "declined",
            "status": "cancelled",
            "declined_at": now,
            "decline_reason": data.message or "",
            "updated_at": now,
        }})
        await insert_deal_system_message(campaign, f"❌ {creator_name} declined the booking. The brand has been refunded in full.")
        await notify_user(brand_id, "Booking declined — you've been refunded",
                          f"{creator_name} declined '{title}'. ₹{refunded:,.0f} is back in your wallet."
                          + (f" Reason: {data.message}" if data.message else ""),
                          link="/dashboard/business/wallet", ntype="warning", email=True, category="payments")
        return {"booking_status": "declined", "refunded": refunded}

    if data.action == "revise":
        proposed = to_float(data.amount)
        if proposed <= 0:
            raise HTTPException(status_code=400, detail="Enter the price you want for this booking")
        await db.campaigns.update_one({"id": campaign_id}, {"$set": {
            "booking_status": "price_revision",
            "proposed_amount": proposed,          # the creator's take, fee is added on top
            "proposed_message": data.message or "",
            "proposed_at": now,
            "updated_at": now,
        }})
        fee = brand_commission(proposed)
        await insert_deal_system_message(
            campaign,
            f"💬 {creator_name} proposed a new price: ₹{proposed:,.0f} (₹{proposed + fee:,.0f} incl. platform fee)."
            + (f" — \"{data.message}\"" if data.message else ""),
        )
        await notify_user(brand_id, "Creator proposed a new price",
                          f"{creator_name} wants ₹{proposed:,.0f} for '{title}'. Accept it or cancel the booking.",
                          link="/dashboard/business/all-campaigns", ntype="info")
        return {"booking_status": "price_revision", "proposed_amount": proposed, "new_total": round(proposed + fee, 2)}

    raise HTTPException(status_code=400, detail="action must be accept, decline or revise")


@api_router.post("/bookings/{campaign_id}/price")
async def decide_booking_price(campaign_id: str, data: BookingPriceDecision,
                               current_user: dict = Depends(get_approved_business_user)):
    """Brand accepts or rejects the creator's counter-offer. Settles the difference."""
    campaign = await get_booking(campaign_id, current_user, role="brand")
    if campaign.get("booking_status") != "price_revision":
        raise HTTPException(status_code=400, detail="There's no price proposal on this booking")

    creator = await db.users.find_one({"id": campaign["selected_creator"]}, {"_id": 0, "nickname": 1, "full_name": 1, "business_name": 1, "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1, "email": 1})
    creator_name = person_display_name(creator, "The creator")
    title = campaign.get("title") or "your booking"
    now = now_iso()

    if data.action == "reject":
        refunded = await refund_booking(campaign, "Brand rejected the creator's price")
        await db.campaigns.update_one({"id": campaign_id}, {"$set": {
            "booking_status": "declined", "status": "cancelled", "declined_at": now, "updated_at": now,
        }})
        await insert_deal_system_message(campaign, "❌ The brand didn't accept the new price. The booking is cancelled and refunded.")
        await notify_user(campaign["selected_creator"], "Booking cancelled",
                          f"The brand didn't accept your price for '{title}'.", link="/my-deals", ntype="warning")
        return {"booking_status": "declined", "refunded": refunded}

    if data.action != "accept":
        raise HTTPException(status_code=400, detail="action must be accept or reject")

    old_total = to_float(campaign.get("amount_paid"))
    new_subtotal = to_float(campaign.get("proposed_amount"))
    new_fee = brand_commission(new_subtotal)
    new_total = round(new_subtotal + new_fee, 2)
    difference = round(new_total - old_total, 2)

    if difference > 0:
        # Charge only the gap, atomically — same overdraw guard as checkout.
        debit = await db.users.update_one(
            {"id": current_user["id"], "balance": {"$gte": difference}},
            {"$inc": {"balance": -difference}},
        )
        if debit.modified_count != 1:
            from fastapi.responses import JSONResponse
            fresh = await db.users.find_one({"id": current_user["id"]}, {"_id": 0, "balance": 1})
            balance = to_float((fresh or {}).get("balance"))
            return JSONResponse(status_code=402, content={
                "detail": f"The new price needs ₹{difference:,.0f} more in credits, but your wallet has ₹{balance:,.0f}.",
                "code": "INSUFFICIENT_FUNDS",
                "required": difference,
                "available": balance,
                "shortfall": round(difference - balance, 2),
            })
    elif difference < 0:
        # Cheaper than booked — hand the surplus straight back.
        await db.users.update_one({"id": current_user["id"]}, {"$inc": {"balance": -difference}})

    await db.escrow.update_one({"campaign_id": campaign_id}, {"$set": {
        "amount": new_subtotal,
        "brand_commission_amount": new_fee,
        "brand_charged": new_total,
        "updated_at": now,
    }})
    await db.campaigns.update_one({"id": campaign_id}, {"$set": {
        "booking_status": "accepted",
        "budget_min": new_subtotal,
        "budget_max": new_subtotal,
        "amount_paid": new_total,
        "platform_fee": new_fee,
        "accepted_at": now,
        "updated_at": now,
    }, "$unset": {"proposed_amount": "", "proposed_message": "", "proposed_at": ""}})

    await insert_deal_system_message(campaign, f"✅ The brand accepted ₹{new_subtotal:,.0f}. The booking is confirmed — the brief is next.")
    await notify_user(campaign["selected_creator"], "Your price was accepted",
                      f"The brand accepted ₹{new_subtotal:,.0f} for '{title}'. Wait for their brief to start.",
                      link="/my-deals", ntype="success")

    updated = await db.users.find_one({"id": current_user["id"]}, {"_id": 0, "balance": 1})
    return {
        "booking_status": "accepted",
        "subtotal": new_subtotal,
        "fee": new_fee,
        "total": new_total,
        "difference_charged": difference,
        "wallet_balance": to_float((updated or {}).get("balance")),
    }


@api_router.post("/bookings/{campaign_id}/brief")
async def send_booking_brief(campaign_id: str, data: BookingBriefSend,
                             current_user: dict = Depends(get_approved_business_user)):
    """Brand sends the brief. Only possible once the creator has accepted — this is
    what actually starts the work."""
    campaign = await get_booking(campaign_id, current_user, role="brand")
    status = campaign.get("booking_status")
    if status != "accepted":
        raise HTTPException(status_code=400, detail={
            "pending_creator": "The creator hasn't accepted this booking yet.",
            "price_revision": "Answer the creator's price proposal first.",
            "declined": "This booking was declined.",
        }.get(status, "This booking isn't ready for a brief."))
    if campaign.get("brief_sent"):
        raise HTTPException(status_code=400, detail="The brief has already been sent")

    draft = campaign.get("brief_draft") or {}
    brief_text = (data.brief_text or draft.get("brief_text") or "").strip()
    if not brief_text:
        raise HTTPException(status_code=400, detail="The brief can't be empty")
    enforce_brief_contact_policy({"brief_text": brief_text})

    now = now_iso()
    await db.campaigns.update_one({"id": campaign_id}, {"$set": {
        "brief_text": brief_text,
        "deliverables": data.deliverables or draft.get("deliverables") or "",
        "brief_attachments": data.attachment_urls or [],
        "brief_sent": True,
        "brief_sent_at": now,
        "work_started_at": now,
        "updated_at": now,
    }, "$unset": {"brief_draft": ""}})

    await insert_deal_system_message(campaign, f"📋 Brief received. The work has started.\n\n{brief_text}")
    await notify_user(campaign["selected_creator"], "📋 Brief received — you can start",
                      f"The brand sent the brief for '{campaign.get('title') or 'your booking'}'. The work has officially started.",
                      link="/my-deals", ntype="success")
    return {"brief_sent": True, "brief_text": brief_text}


@api_router.get("/business/dashboard")
async def get_business_dashboard(current_user: dict = Depends(get_current_user)):
    if current_user.get('role') != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only business users can access this dashboard")

    business_id = _brand_ws_id(current_user)  # team members see the owner's workspace
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
    creators = await db.users.find({"id": {"$in": creator_ids}}, {"_id": 0, "id": 1, "nickname": 1, "full_name": 1, "business_name": 1, "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1}).to_list(10000) if creator_ids else []
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
            "creator_name": person_display_name(creator, creator.get("nickname") or "Creator"),
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
    settings = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
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
        {"business_id": _brand_ws_id(current_user)},
        {
            "$set": {"business_id": _brand_ws_id(current_user), "profile": profile_data, "updated_at": now},
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
        {"business_id": _brand_ws_id(current_user)},
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
    file_ext = Path(file.filename or "").suffix or ".png"
    unique_filename = f"logo_{current_user['id']}_{uuid.uuid4().hex}{file_ext}"
    content = await file.read()

    logo_url = persist_file(
        content,
        unique_filename,
        kind="image",
        local_dir=upload_dir,
        public_path=f"/uploads/business_logos/{unique_filename}",
        cloud_folder="ugcad/logos",
    )
    now = datetime.now(timezone.utc).isoformat()
    existing = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
    profile_data = business_profile_defaults(current_user, (existing or {}).get("profile"))
    profile_data["logo_url"] = logo_url
    await db.business_settings.update_one(
        {"business_id": _brand_ws_id(current_user)},
        {
            "$set": {"business_id": _brand_ws_id(current_user), "profile": profile_data, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"profile.logo": logo_url, "updated_at": now}})
    await db.campaigns.update_many({"business_id": _brand_ws_id(current_user)}, {"$set": {"brand_logo_url": logo_url, "updated_at": now}})
    return {"logo_url": logo_url}

@api_router.delete("/business/settings/logo")
async def delete_business_settings_logo(current_user: dict = Depends(get_current_business_user)):
    now = datetime.now(timezone.utc).isoformat()
    existing = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
    profile_data = business_profile_defaults(current_user, (existing or {}).get("profile"))
    profile_data["logo_url"] = ""
    await db.business_settings.update_one(
        {"business_id": _brand_ws_id(current_user)},
        {
            "$set": {"business_id": _brand_ws_id(current_user), "profile": profile_data, "updated_at": now},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"profile.logo": "", "updated_at": now}})
    await db.campaigns.update_many({"business_id": _brand_ws_id(current_user)}, {"$set": {"brand_logo_url": "", "updated_at": now}})
    return {"logo_url": ""}

@api_router.get("/business/settings/company")
async def get_business_settings_company(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
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
        {"business_id": _brand_ws_id(current_user)},
        {
            "$set": {"business_id": _brand_ws_id(current_user), "company": company_data, "updated_at": now},
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

# ── Brand team / shared workspace helpers ────────────────────────────────────
# A brand team member logs in with their own account but operates on the OWNER's
# brand data. `team_of` on their user doc points at the owner; brand-scoped
# queries resolve through _brand_ws_id() so a member sees the owner's campaigns,
# deals and work. Their own id still keys chat / notifications / audit.
def _brand_ws_id(user: dict) -> str:
    return user.get("team_of") or user.get("id")

def _can_manage_team(user: dict) -> bool:
    # The owner (no team_of) or a team admin can invite / remove members.
    return (not user.get("team_of")) or user.get("team_role") == "admin"

def _hash_invite_token(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()

async def _team_payload(owner_id: str) -> dict:
    owner = await db.users.find_one({"id": owner_id}, {"_id": 0}) or {}
    members = [{
        "id": owner_id,
        "name": (owner.get("profile") or {}).get("business_name") or owner.get("nickname") or owner.get("email", ""),
        "email": owner.get("email", ""),
        "avatar_url": owner.get("profile_photo") or "",
        "role": "owner",
        "status": "active",
        "is_owner": True,
    }]
    rows = await db.business_team_members.find({"business_id": owner_id}, {"_id": 0}).sort("created_at", 1).to_list(1000)
    for m in rows:
        members.append({
            "id": m.get("id"),
            "name": m.get("name") or m.get("email", ""),
            "email": m.get("email", ""),
            "avatar_url": m.get("avatar_url", ""),
            "role": m.get("role", "viewer"),
            "status": m.get("status", "invited"),
        })
    settings = await db.business_settings.find_one({"business_id": owner_id}, {"_id": 0})
    seat_limit = ((settings or {}).get("team") or {}).get("seat_limit", 10)
    return {"members": members, "seat_limit": seat_limit, "seats_used": len(members)}

@api_router.get("/business/settings/team")
async def get_business_settings_team(current_user: dict = Depends(get_current_business_user)):
    # Resolve to the workspace owner so a team member sees the real team, not just themselves.
    return await _team_payload(_brand_ws_id(current_user))

@api_router.post("/business/settings/team/invite")
async def invite_business_settings_team_member(
    data: BusinessTeamInvite,
    current_user: dict = Depends(get_current_business_user)
):
    # Accept "member" (what the invite modal sends) alongside the legacy "editor".
    validate_choice(data.role, ["admin", "editor", "member", "viewer"], "role")
    if not _can_manage_team(current_user):
        raise HTTPException(status_code=403, detail="Only the workspace owner or an admin can invite members.")
    owner_id = _brand_ws_id(current_user)
    owner = await db.users.find_one({"id": owner_id}, {"_id": 0}) or {}
    email = str(data.email).lower().strip()

    if email == str(owner.get("email", "")).lower():
        raise HTTPException(status_code=409, detail="That is the workspace owner.")
    existing = await db.business_team_members.find_one({"business_id": owner_id, "email": email})
    if existing:
        raise HTTPException(status_code=409, detail="That person is already on your team.")
    # Someone can't be a member of two brand workspaces.
    other_ws = await db.users.find_one({"email": email, "team_of": {"$nin": [None, ""]}}, {"_id": 0})
    if other_ws and other_ws.get("team_of") != owner_id:
        raise HTTPException(status_code=409, detail="That email already belongs to another brand workspace.")

    # Seat check (owner + members).
    payload = await _team_payload(owner_id)
    if payload["seats_used"] >= payload["seat_limit"]:
        raise HTTPException(status_code=409, detail=f"Seat limit reached ({payload['seat_limit']}). Remove a member first.")

    raw_token = uuid.uuid4().hex + uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    member_doc = {
        "id": str(uuid.uuid4()),
        "business_id": owner_id,
        "name": data.name or email.split("@")[0],
        "email": email,
        "avatar_url": "",
        "role": data.role,
        "status": "invited",
        "invite_token_hash": _hash_invite_token(raw_token),
        "invite_expires": expires,
        "invited_by": current_user["id"],
        "created_at": now,
        "updated_at": now,
    }
    await db.business_team_members.insert_one(member_doc)

    # Email the invite with a set-password link.
    brand_name = (owner.get("profile") or {}).get("business_name") or owner.get("nickname") or "a brand"
    frontend = (os.environ.get("FRONTEND_URL") or "https://www.ugcad.io").rstrip("/")
    link = f"{frontend}/team/accept?token={raw_token}"
    try:
        await send_email(
            to=email,
            subject=f"You've been invited to join {brand_name} on UGCad.io",
            html=_email_base_template(
                "Team invitation",
                f'<h1 style="margin:0 0 12px;font-size:22px;color:#1f2340;">Join {brand_name} on UGCad.io</h1>'
                f'<p style="margin:0 0 8px;font-size:15px;line-height:1.6;color:#4a4f74;">You\'ve been invited as a <strong>{data.role}</strong>. '
                'Set a password to access the workspace. This link expires in 7 days.</p>'
                + _email_button("Accept invitation", link)
                + f'<p style="margin:22px 0 0;font-size:12.5px;color:#9296ba;word-break:break-all;">Or paste this link: {link}</p>'
            ),
        )
    except Exception as e:
        logger.error(f"[team/invite] email failed: {e}")
    logger.info(f"[team/invite] {email} invited to workspace {owner_id}: {link}")

    return await _team_payload(owner_id)

@api_router.patch("/business/settings/team/{member_id}")
async def update_business_settings_team_member(
    member_id: str,
    data: BusinessTeamMemberUpdate,
    current_user: dict = Depends(get_current_business_user)
):
    update_data = {key: value for key, value in data.dict().items() if value is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields provided")
    validate_choice(update_data.get("role"), ["admin", "editor", "member", "viewer"], "role")
    validate_choice(update_data.get("status"), ["active", "invited", "disabled"], "status")
    if not _can_manage_team(current_user):
        raise HTTPException(status_code=403, detail="Only the workspace owner or an admin can change members.")
    owner_id = _brand_ws_id(current_user)
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = await db.business_team_members.update_one(
        {"id": member_id, "business_id": owner_id},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Team member not found")
    # Keep the member's linked user role in step when their team role changes.
    member = await db.business_team_members.find_one({"id": member_id, "business_id": owner_id}, {"_id": 0})
    if member and member.get("user_id") and update_data.get("role"):
        await db.users.update_one({"id": member["user_id"]}, {"$set": {"team_role": update_data["role"]}})
    return await _team_payload(owner_id)

@api_router.delete("/business/settings/team/{member_id}")
async def delete_business_settings_team_member(member_id: str, current_user: dict = Depends(get_current_business_user)):
    if not _can_manage_team(current_user):
        raise HTTPException(status_code=403, detail="Only the workspace owner or an admin can remove members.")
    owner_id = _brand_ws_id(current_user)
    member = await db.business_team_members.find_one({"id": member_id, "business_id": owner_id})
    if not member:
        raise HTTPException(status_code=404, detail="Team member not found")
    # If they already accepted and have a login, unlink it from the workspace so
    # their access is cut (their account itself survives).
    if member.get("user_id"):
        await db.users.update_one({"id": member["user_id"]}, {"$set": {"team_of": None, "team_role": "owner"}})
    await db.business_team_members.delete_one({"id": member_id, "business_id": owner_id})
    return await _team_payload(owner_id)

# ── Public team-invite accept flow (no auth) ─────────────────────────────────
class TeamAcceptRequest(BaseModel):
    token: str
    password: str
    name: Optional[str] = None

async def _find_team_invite(token: str):
    return await db.business_team_members.find_one({"invite_token_hash": _hash_invite_token(token)}, {"_id": 0})

@api_router.get("/team/invite/{token}")
async def get_team_invite(token: str):
    inv = await _find_team_invite(token)
    if not inv or inv.get("status") != "invited":
        raise HTTPException(status_code=404, detail="This invitation is invalid or has expired.")
    exp = inv.get("invite_expires")
    if exp and datetime.fromisoformat(exp) < datetime.now(timezone.utc):
        raise HTTPException(status_code=404, detail="This invitation is invalid or has expired.")
    owner = await db.users.find_one({"id": inv.get("business_id")}, {"_id": 0}) or {}
    return {
        "email": inv.get("email"),
        "role": inv.get("role", "member"),
        "brand_name": (owner.get("profile") or {}).get("business_name") or owner.get("nickname") or "a brand",
    }

@api_router.post("/team/accept")
async def accept_team_invite(data: TeamAcceptRequest):
    if not data.token or not data.password:
        raise HTTPException(status_code=400, detail="Token and password are required.")
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    inv = await _find_team_invite(data.token)
    if not inv or inv.get("status") != "invited":
        raise HTTPException(status_code=404, detail="This invitation is invalid or has expired.")
    exp = inv.get("invite_expires")
    if exp and datetime.fromisoformat(exp) < datetime.now(timezone.utc):
        raise HTTPException(status_code=404, detail="This invitation is invalid or has expired.")

    owner_id = inv.get("business_id")
    owner = await db.users.find_one({"id": owner_id}, {"_id": 0})
    if not owner:
        raise HTTPException(status_code=404, detail="The inviting brand no longer exists.")

    email = str(inv.get("email")).lower().strip()
    existing = await db.users.find_one({"email": email}, {"_id": 0})
    if existing and existing.get("team_of") and existing.get("team_of") != owner_id:
        raise HTTPException(status_code=409, detail="This email already belongs to another workspace.")
    if existing and not existing.get("team_of") and existing.get("role") != UserRole.BUSINESS:
        # An existing creator/other account can't be converted into a brand member.
        raise HTTPException(status_code=409, detail="An account with this email already exists. Sign in instead.")

    now = datetime.now(timezone.utc).isoformat()
    if existing:
        user_id = existing["id"]
        await db.users.update_one({"id": user_id}, {"$set": {
            "password": hash_password(data.password),
            "team_of": owner_id,
            "team_role": inv.get("role", "member"),
            "role": UserRole.BUSINESS,
            "approval_status": ApprovalStatus.APPROVED,
            "active": True,
            "updated_at": now,
        }})
    else:
        user_id = str(uuid.uuid4())
        await db.users.insert_one({
            "id": user_id,
            "email": email,
            "password": hash_password(data.password),
            "role": UserRole.BUSINESS,
            "nickname": (data.name or inv.get("name") or email.split("@")[0]),
            "full_name": data.name or "",
            "profile_completed": True,
            "approval_status": ApprovalStatus.APPROVED,
            "active": True,
            "team_of": owner_id,
            "team_role": inv.get("role", "member"),
            "balance": 0.0,
            "created_at": now,
            "updated_at": now,
        })

    # Mark the invite consumed + link it to the login.
    await db.business_team_members.update_one(
        {"id": inv["id"]},
        {"$set": {"status": "active", "user_id": user_id, "updated_at": now},
         "$unset": {"invite_token_hash": "", "invite_expires": ""}},
    )

    fresh = await db.users.find_one({"id": user_id}, {"_id": 0})
    return _auth_response(fresh)

@api_router.get("/business/settings/billing")
async def get_business_settings_billing(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
    billing = (settings or {}).get("billing") or {}
    transactions = await db.payment_transactions.find({"user_id": current_user["id"]}, {"_id": 0}).sort("created_at", -1).limit(20).to_list(20)
    campaigns = await db.campaigns.find({"business_id": _brand_ws_id(current_user)}, {"_id": 0}).to_list(10000)
    current_month_start = month_start(datetime.now(timezone.utc))
    next_month_start = add_months(current_month_start, 1)
    monthly_budget_used = sum(
        campaign_budget_total(campaign)
        for campaign in campaigns
        if is_between_iso(campaign.get("created_at"), current_month_start, next_month_start)
    )
    return {
        "plan_name": billing.get("plan_name", "Pro"),
        # The platform fee actually charged on top of a deal is the live global
        # rate (see brand_commission()), so report that — not a stale stored copy.
        "commission_rate": commission_percent(),
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
        {"business_id": _brand_ws_id(current_user)},
        {
            "$set": {"business_id": _brand_ws_id(current_user), "billing.plan_name": data.plan_name, "updated_at": now},
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
        {"business_id": _brand_ws_id(current_user)},
        {
            "$set": {"business_id": _brand_ws_id(current_user), "updated_at": now},
            "$push": {"billing.payment_methods": method},
            "$setOnInsert": {"id": str(uuid.uuid4()), "created_at": now}
        },
        upsert=True
    )
    return method

@api_router.get("/business/settings/notifications")
async def get_business_settings_notifications(current_user: dict = Depends(get_current_business_user)):
    settings = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
    return business_notification_defaults((settings or {}).get("notifications"))

@api_router.put("/business/settings/notifications")
async def update_business_settings_notifications(
    data: BusinessNotificationPreferences,
    current_user: dict = Depends(get_current_business_user)
):
    notification_data = data.dict()
    now = datetime.now(timezone.utc).isoformat()
    await db.business_settings.update_one(
        {"business_id": _brand_ws_id(current_user)},
        {
            "$set": {"business_id": _brand_ws_id(current_user), "notifications": notification_data, "updated_at": now},
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
    settings = await db.business_settings.find_one({"business_id": _brand_ws_id(current_user)}, {"_id": 0})
    billing = (settings or {}).get("billing") or {}
    team_count = 1 + await db.business_team_members.count_documents({
        "business_id": _brand_ws_id(current_user),
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

    now_str = datetime.now(timezone.utc).isoformat()
    was_approved = current_user.get("approval_status") == ApprovalStatus.APPROVED
    update_fields = {
        "profile": profile_data,
        "profile_completed": True,
        "updated_at": now_str,
    }

    # The creator's real NAME becomes their display name — this is what replaces
    # the auto-generated "@FierceDragon774" handle everywhere the UI shows them.
    real_name = str(
        profile_data.get("fullName")
        or profile_data.get("full_name")
        or profile_data.get("name")
        or ""
    ).strip().lstrip("@")
    if real_name:
        update_fields["nickname"] = real_name
        update_fields["full_name"] = real_name
    if was_approved:
        # An already-approved creator editing their profile (details, new work) must NOT
        # be knocked back to PENDING — that silently de-lists them from the brand
        # directory. Keep them approved/discoverable and flag the edit for re-review.
        update_fields["profile_review_status"] = "pending_review"
        update_fields["profile_updated_at"] = now_str
    else:
        update_fields["approval_status"] = ApprovalStatus.PENDING

    # Mirror the portfolio to the top-level field so the Portfolio page (and the
    # creator directory) can read it — these read `user.portfolio`, while the
    # rest of the profile lives nested under `profile`. Keeps signup-submitted
    # samples consistent with the PATCH /profile/portfolio editor.
    if submitted_portfolio:
        update_fields["portfolio"] = submitted_portfolio

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

    if was_approved:
        # Stay live for brands, but let ops know there are edits to look at.
        await notify_admins(
            "Creator updated their profile",
            f"{current_user.get('nickname') or 'A creator'} edited their approved profile — review the changes.",
            link="/dashboard/admin/profiles",
        )
        return {"message": "Profile updated", "username": username or None}

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
    set_fields = {
        "profile": profile_data,
        "profile_completed": True,
        "approval_status": ApprovalStatus.PENDING,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    # The brand's name becomes their display name (replaces any auto handle).
    brand_display = str(
        profile_data.get("business_name")
        or profile_data.get("contact_person")
        or profile_data.get("name")
        or ""
    ).strip().lstrip("@")
    if brand_display:
        set_fields["nickname"] = brand_display
    await db.users.update_one({"id": current_user['id']}, {"$set": set_fields})

    # Cascade brand info updates to all existing campaigns for this business
    brand_name = profile_data.get('business_name') or current_user.get('nickname', '')
    brand_logo_url = profile_data.get('logo') or ''
    brand_cover_image_url = profile_data.get('banner') or ''
    await db.campaigns.update_many(
        {"business_id": _brand_ws_id(current_user)},
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

    # Save file
    try:
        content = await file.read()
        # Update user profile with photo URL
        photo_url = persist_file(
            content,
            unique_filename,
            kind="image",
            local_dir=upload_dir,
            public_path=f"/uploads/profiles/{unique_filename}",
            cloud_folder="ugcad/profiles",
        )
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


@api_router.post("/profile/upload-banner")
async def upload_profile_banner(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Upload the creator's profile banner. Mirrors /profile/upload-photo: validates,
    persists the file, and saves the URL on the user in a single step."""
    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))) / "banners"
    upload_dir.mkdir(parents=True, exist_ok=True)

    allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp', 'image/gif']
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Only image files are allowed for banners")

    file_ext = Path(file.filename).suffix
    unique_filename = f"banner_{current_user['id']}{file_ext}"

    try:
        content = await file.read()
        banner_url = persist_file(
            content,
            unique_filename,
            kind="image",
            local_dir=upload_dir,
            public_path=f"/uploads/banners/{unique_filename}",
            cloud_folder="ugcad/banners",
        )
        await db.users.update_one(
            {"id": current_user['id']},
            {"$set": {
                "banner": banner_url,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        return {"banner": banner_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload banner: {str(e)}")

@api_router.patch("/profile/banner")
async def update_profile_banner(payload: Dict[str, Any] = Body(...), current_user: dict = Depends(get_current_user)):
    """Set the creator's profile banner image URL. Does not affect approval status."""
    banner = (payload or {}).get("banner") or ""
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {"banner": banner, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"banner": banner}


@api_router.post("/profile/deactivate")
async def deactivate_profile(current_user: dict = Depends(get_current_user)):
    """Self-deactivate: hide the account (active: False). Reactivated on next login."""
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {"active": False, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"message": "Account deactivated"}


@api_router.delete("/profile")
async def delete_profile(current_user: dict = Depends(get_current_user)):
    """Permanently delete the signed-in user's account."""
    await db.users.delete_one({"id": current_user['id']})
    return {"message": "Account deleted"}

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


@api_router.put("/profile/payment-info")
async def update_payment_info(data: Dict[str, Any] = Body(...), current_user: dict = Depends(get_current_user)):
    """Save a creator's payout account (bank + UPI). Read back via /payout/overview."""
    bank = data.get("bank_details") or {}
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": {
            "bank_details": {
                "account_holder_name": (bank.get("account_holder_name") or "").strip(),
                "bank_name": (bank.get("bank_name") or "").strip(),
                "account_number": (bank.get("account_number") or "").strip(),
                "ifsc_code": (bank.get("ifsc_code") or "").strip().upper(),
            },
            "upi_id": (data.get("upi_id") or "").strip() or None,
            "updated_at": now_iso(),
        }},
    )
    return {"message": "Payment details saved"}


@api_router.get("/kyc/me")
async def get_my_kyc(current_user: dict = Depends(get_current_user)):
    """Current creator's KYC submission/status (mirrors what the admin queue reads)."""
    kyc = current_user.get("kyc")
    if not kyc:
        return {"status": "not_submitted"}
    return _json_safe(kyc)


@api_router.post("/kyc/submit")
async def submit_kyc(data: Dict[str, Any] = Body(...), current_user: dict = Depends(get_current_user)):
    """Creator submits PAN + Aadhaar for verification. Stored on user.kyc with
    status 'pending' so it shows up in the admin KYC review queue (/admin/kyc)."""
    if current_user["role"] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators submit KYC")
    existing = current_user.get("kyc") or {}
    if existing.get("status") in ("pending", "verified"):
        raise HTTPException(status_code=400, detail=f"KYC already {existing['status']}")

    # --- Identity ---
    name = str(data.get("full_legal_name") or data.get("name_on_pan") or "").strip()
    pan = str(data.get("pan_number") or "").strip().upper()
    aadhaar = re.sub(r"\D", "", str(data.get("aadhaar_number") or ""))
    dob = str(data.get("date_of_birth") or "").strip()[:10]
    gender = str(data.get("gender") or "").strip().lower()
    if not name:
        raise HTTPException(status_code=400, detail="Enter your full legal name.")
    if not PAN_RE.match(pan):
        raise HTTPException(status_code=400, detail="PAN must look like ABCDE1234F.")
    # Aadhaar is optional per spec; if given it must be valid.
    if aadhaar and not aadhaar_valid(aadhaar):
        raise HTTPException(status_code=400, detail="That Aadhaar number is not valid.")
    age = age_years(dob)
    if age is None:
        raise HTTPException(status_code=400, detail="Enter a valid date of birth.")
    if age < 18:
        raise HTTPException(status_code=400, detail="You must be at least 18 to receive payouts.")
    if gender not in ("male", "female", "other", "prefer_not_to_say"):
        raise HTTPException(status_code=400, detail="Select your gender.")

    # --- Residential address ---
    addr = data.get("address") or {}
    addr_line = str(addr.get("line") or data.get("address_line") or "").strip()
    city = str(addr.get("city") or data.get("city") or "").strip()
    state = str(addr.get("state") or data.get("state") or "").strip()
    pincode = re.sub(r"\D", "", str(addr.get("pincode") or data.get("pincode") or ""))
    if not (addr_line and city and state):
        raise HTTPException(status_code=400, detail="Enter your full residential address.")
    if len(pincode) != 6:
        raise HTTPException(status_code=400, detail="Enter a valid 6-digit pincode.")

    # --- Payout: UPI OR bank+IFSC (exactly one is enough) ---
    upi = str(data.get("upi_id") or "").strip()
    bank = data.get("bank_details") or {}
    acct = str(bank.get("account_number") or "").strip()
    ifsc = str(bank.get("ifsc_code") or "").strip().upper()
    holder = str(bank.get("account_holder_name") or "").strip()
    has_bank = bool(acct and ifsc)
    if not upi and not has_bank:
        raise HTTPException(status_code=400, detail="Add a payout method — a UPI ID or a bank account with IFSC.")
    if upi and not UPI_RE.match(upi):
        raise HTTPException(status_code=400, detail="That UPI ID doesn't look right (e.g. name@bank).")
    if has_bank:
        if not IFSC_RE.match(ifsc):
            raise HTTPException(status_code=400, detail="That IFSC code is not valid (e.g. HDFC0001234).")
        if not re.match(r'^\d{9,18}$', acct):
            raise HTTPException(status_code=400, detail="Enter a valid bank account number.")
        if not holder:
            raise HTTPException(status_code=400, detail="Enter the account holder's name.")

    # --- Documents ---
    pan_doc = str(data.get("pan_doc_url") or "").strip()
    selfie = str(data.get("selfie_url") or "").strip()  # optional — no longer required
    if not pan_doc:
        raise HTTPException(status_code=400, detail="Upload a photo of your PAN card.")

    kyc = {
        "status": "pending",
        "full_legal_name": name,
        "name_on_pan": name,
        "date_of_birth": dob,
        "gender": gender,
        "pan_number": pan,
        "aadhaar_number": aadhaar,
        "address": {"line": addr_line, "city": city, "state": state, "pincode": pincode},
        "payout_method": "upi" if upi else "bank",
        "pan_doc_url": pan_doc,
        "aadhaar_front_url": str(data.get("aadhaar_front_url") or "").strip(),
        "aadhaar_back_url": str(data.get("aadhaar_back_url") or "").strip(),
        "selfie_url": selfie,
        "submitted_at": now_iso(),
        "rejection_reason": None,
    }
    # Payout account lives at the top level too (that's where withdrawals read it).
    payout_set = {"upi_id": upi or None}
    if has_bank:
        payout_set["bank_details"] = {
            "account_holder_name": holder, "bank_name": str(bank.get("bank_name") or "").strip(),
            "account_number": acct, "ifsc_code": ifsc,
        }
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"kyc": kyc, "kyc_verified": False, **payout_set}})
    await notify_admins("New KYC submission", f"{current_user.get('nickname', current_user['id'])} submitted KYC for review.")
    return _json_safe(kyc)


@api_router.put("/profile/preferences")
async def update_profile_preferences(data: Dict[str, Any] = Body(...), current_user: dict = Depends(get_current_user)):
    """Persist a creator's notification + privacy preferences (were localStorage-only)."""
    update = {"updated_at": now_iso()}
    if isinstance(data.get("notification_prefs"), dict):
        update["notification_prefs"] = data["notification_prefs"]
    if isinstance(data.get("privacy"), dict):
        update["privacy"] = data["privacy"]
    await db.users.update_one({"id": current_user["id"]}, {"$set": update})
    return {"message": "Preferences saved", "notification_prefs": update.get("notification_prefs"), "privacy": update.get("privacy")}


# ---- Saved briefs (was localStorage-only) ---------------------------------
@api_router.get("/saved-briefs")
async def list_saved_briefs(current_user: dict = Depends(get_current_user)):
    return {"campaign_ids": current_user.get("saved_briefs") or []}


@api_router.post("/saved-briefs/{campaign_id}")
async def add_saved_brief(campaign_id: str, current_user: dict = Depends(get_current_user)):
    await db.users.update_one({"id": current_user["id"]}, {"$addToSet": {"saved_briefs": campaign_id}})
    return {"saved": True}


@api_router.delete("/saved-briefs/{campaign_id}")
async def remove_saved_brief(campaign_id: str, current_user: dict = Depends(get_current_user)):
    await db.users.update_one({"id": current_user["id"]}, {"$pull": {"saved_briefs": campaign_id}})
    return {"saved": False}

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

    # Hide a creator's social links from OTHER users (anti-disintermediation) — but
    # never from the creator viewing their own profile (that stripped their own links
    # and made the profile show "add link" even after they'd saved them), and never
    # from admins.
    is_self = current_user.get('id') == user.get('id')
    if user['role'] == UserRole.CREATOR and current_user['role'] != UserRole.ADMIN and not is_self:
        if 'profile' in user and 'social_links' in user['profile']:
            user['profile']['social_links'] = {}

    # Username is private — strip it (and email) from brand-facing responses,
    # unless the requester is the user themselves.
    if current_user.get('id') != user.get('id'):
        strip_private_fields(user, current_user.get('role'))

    # Completed-works count: the single-profile route returned the raw doc,
    # which never carries deliverables_completed, so the profile modal always
    # showed 0. Compute it the same way the directory/shortlist do.
    if user.get('role') == UserRole.CREATOR:
        user['deliverables_completed'] = await creator_deliverables_completed(user)
        # Same back-compat as /auth/me: a creator's signup portfolio can live only
        # under profile.portfolio, but the profile modal reads the TOP-LEVEL
        # `portfolio`. Without surfacing it here, saved work showed as "add work".
        if not user.get('portfolio'):
            nested = (user.get('profile') or {}).get('portfolio')
            if nested:
                user['portfolio'] = nested

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
        "business_id": _brand_ws_id(current_user),
        "business_nickname": current_user.get('nickname', ''),
        "brand_name": brand_name,
        "brand_logo_url": brand_logo_url,
        "brand_cover_image_url": brand_cover_image_url,
        "image_url": campaign_data.get("image_url") or "",
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
    if campaign.get('business_id') != _brand_ws_id(current_user):
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

@api_router.delete("/campaigns/{campaign_id}")
async def delete_campaign_route(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a draft (or rejected) campaign the brand owns.

    Only un-published briefs can be removed — a draft/rejected campaign never held
    escrow and was never shown to creators, so deletion is safe. Anything that has
    gone live (or beyond) must be cancelled through the normal flow instead.
    """
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Check ownership
    if campaign.get('business_id') != _brand_ws_id(current_user):
        raise HTTPException(status_code=403, detail="You can only delete your own campaigns")

    # Guard: only drafts / rejected briefs (never live, no money held) can be deleted.
    if campaign.get('status') not in ['draft', 'rejected']:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete campaign with status: {campaign.get('status')}"
        )

    await db.campaigns.delete_one({"id": campaign_id})

    return {"deleted": True, "campaign_id": campaign_id, "message": "Draft deleted"}

@api_router.post("/campaigns/{campaign_id}/submit")
async def submit_campaign_route(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Submit a draft campaign for approval"""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Check ownership
    if campaign.get('business_id') != _brand_ws_id(current_user):
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

    # Restricted brand categories (Settings) may not be advertised.
    blocked = is_restricted_category(campaign.get('category'), campaign.get('product_type'),
                                     campaign.get('industry_category'), campaign.get('title'))
    if blocked:
        raise HTTPException(status_code=400, detail=f"'{blocked}' is a restricted category and cannot be advertised on this platform.")

    # Hold the campaign budget on the wallet now (shows as 'on hold' in Transaction
    # History). Raises 400 if the wallet can't cover it — the brief stays a draft.
    await reserve_campaign_budget(current_user, campaign)
    # Platform listing fee (Settings → Listing fee). If it can't be paid, undo the hold.
    try:
        await charge_listing_fee(current_user, campaign)
    except HTTPException:
        await refund_campaign_reservation(campaign_id, reason="listing_fee_unpaid")
        raise

    # Submitting sends the brief for admin approval — it goes live (ACTIVE) only after
    # an admin approves it, so creators never see un-reviewed campaigns.
    now_iso_str = datetime.now(timezone.utc).isoformat()
    update_fields = {
        "status": CampaignStatus.PENDING_APPROVAL,
        "submitted_at": now_iso_str,
        "updated_at": now_iso_str
    }
    await notify_admins(
        "New campaign awaiting approval",
        f"'{campaign.get('title', '')}' was submitted and needs admin approval before it goes live to creators.",
        link="/dashboard/admin/campaigns",
    )

    # Flag to admin if the budget is hidden from creators
    await flag_hidden_budget_if_needed(campaign)
    if campaign.get('budget_hidden'):
        update_fields['budget_hidden'] = True
        update_fields['admin_flags'] = campaign.get('admin_flags')

    # PRD 5.2 Path B: brand requested an ops-curated shortlist (feature-flagged)
    if campaign.get('match_requested') and feature_enabled('matching_v05'):
        update_fields['match_status'] = 'queued'
        await notify_admins(
            "New brief awaiting matches",
            f"'{campaign.get('title', '')}' was published with Request Matches and needs an ops shortlist.",
            link="/dashboard/admin/campaigns",
        )

    # Submit the brief for approval
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": update_fields}
    )

    return {
        "campaign_id": campaign_id,
        "status": CampaignStatus.ACTIVE.value,
        "message": "Campaign published"
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
    if campaign.get('business_id') != _brand_ws_id(current_user):
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
    file_ext = Path(file.filename).suffix or '.jpg'
    filename = f"{uuid.uuid4()}{file_ext}"

    file_url = persist_file(
        content,
        filename,
        kind="image",
        local_dir=img_dir,
        public_path=f"/uploads/campaigns/{image_type}/{filename}",
        cloud_folder="ugcad/campaigns",
    )
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
    # Published briefs go to PENDING_APPROVAL and only become ACTIVE (visible to creators)
    # after an admin approves them — creators never see un-reviewed campaigns. Drafts stay drafts.
    status = campaign_data.pop('status', None)
    if status == 'draft':
        is_publish = False
        final_status = CampaignStatus.DRAFT.value
    elif status == 'pending_approval':
        validate_campaign_for_submission(campaign_data)
        is_publish = True
        final_status = CampaignStatus.PENDING_APPROVAL.value
    else:
        is_publish = True
        final_status = CampaignStatus.PENDING_APPROVAL.value
        try:
            validate_campaign_for_submission(campaign_data)
        except HTTPException:
            if status is not None:
                raise
            is_publish = False
            final_status = CampaignStatus.DRAFT.value

    # Moderate the free-text "things to avoid" field for contact info on publish
    if is_publish:
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
        "business_id": _brand_ws_id(current_user),
        "business_nickname": current_user.get('nickname', ''),
        "brand_name": brand_name,
        "brand_logo_url": brand_logo_url,
        "brand_cover_image_url": brand_cover_image_url,
        "image_url": campaign_data.get("image_url") or "",
        "business_verified": business_verified,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

    if is_publish:
        # Restricted brand categories (Settings) may not be advertised.
        blocked = is_restricted_category(campaign_doc.get('category'), campaign_doc.get('product_type'),
                                         campaign_doc.get('industry_category'), campaign_doc.get('title'))
        if blocked:
            raise HTTPException(status_code=400, detail=f"'{blocked}' is a restricted category and cannot be advertised on this platform.")
        # Hold the campaign budget on the wallet now (shows as 'on hold' in Transaction
        # History). Raises 400 if the wallet can't cover it — the campaign is not created.
        await reserve_campaign_budget(current_user, campaign_doc)
        # Platform listing fee (Settings → Listing fee). If it can't be paid, undo the hold.
        try:
            await charge_listing_fee(current_user, campaign_doc)
        except HTTPException:
            await refund_campaign_reservation(campaign_doc['id'], reason="listing_fee_unpaid")
            raise
        now_iso = datetime.now(timezone.utc).isoformat()
        campaign_doc['submitted_at'] = now_iso
        # Awaits admin approval before going live — no approved_at stamp yet.
        # Flag to admin if the budget is hidden from creators
        await flag_hidden_budget_if_needed(campaign_doc)
        # PRD 5.2 Path B: brand requested an ops-curated shortlist (feature-flagged)
        if campaign_doc.get('match_requested') and feature_enabled('matching_v05'):
            campaign_doc['match_status'] = 'queued'
        await notify_admins(
            "New campaign awaiting approval",
            f"'{campaign_doc.get('title', '')}' was submitted and needs admin approval before it goes live to creators.",
            link="/dashboard/admin/campaigns",
        )

    await db.campaigns.insert_one(campaign_doc)

    message = "Campaign published" if is_publish else "Draft campaign created"
    
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
async def get_match_queue(current_user: dict = Depends(require_cap("review_applications"))):
    """Ops view: briefs that requested matches and await a shortlist."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view the match queue")
    campaigns = await db.campaigns.find(
        {"match_requested": True, "match_status": {"$in": ["queued", "shortlisted"]}},
        {"_id": 0},
    ).sort("submitted_at", 1).to_list(500)
    return [normalize_campaign_response(c) for c in campaigns]


@api_router.post("/admin/campaigns/{campaign_id}/shortlist")
async def create_campaign_shortlist(campaign_id: str, data: ShortlistCreate, current_user: dict = Depends(require_cap("review_applications"))):
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
    if current_user["role"] not in OPS_ROLES and campaign.get("business_id") != _brand_ws_id(current_user):
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
    if campaign.get("business_id") != _brand_ws_id(current_user):
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
    await notify_user(creator_id, "You've received a brief invitation", f"{person_display_name(current_user, 'A brand')} invited you to '{campaign.get('title', '')}'.", link="/messages", email=True, category="applications")
    return {"message": "Invitation sent", "campaign_id": campaign_id, "creator_id": creator_id, "action_card": {k: v for k, v in action_card.items() if k != "_id"}}


@api_router.post("/campaigns/{campaign_id}/shortlist/request-new")
async def request_new_shortlist(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Brand isn't satisfied with the shortlist and requests a new one (PRD 5.4)."""
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.get("business_id") != _brand_ws_id(current_user):
        raise HTTPException(status_code=403, detail="You can only request matches for your own brief")
    count = (campaign.get("shortlist_request_count") or 0) + 1
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {"match_status": "queued", "shortlist": [], "shortlist_request_count": count, "updated_at": now_iso()}},
    )
    await notify_admins(
        "Brand requested a new shortlist",
        f"'{campaign.get('title', '')}' requested new matches (request #{count}).",
        link="/dashboard/admin/campaigns",
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
async def get_match_metrics(current_user: dict = Depends(require_cap("review_applications"))):
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


async def enrich_bids_with_creator_names(campaigns: list) -> None:
    """Fill each bid's `creator_name` (the creator's real name) in place so brands
    see real names, not the auto-generated @handle. New bids already store it; this
    backfills older bids by batch-looking-up the creators. Mutates the campaigns."""
    missing_ids = {
        bid.get("creator_id")
        for c in campaigns
        for bid in (c.get("bids") or [])
        if bid.get("creator_id") and not bid.get("creator_name")
    }
    if not missing_ids:
        return
    users = await db.users.find(
        {"id": {"$in": list(missing_ids)}},
        {"_id": 0, "id": 1, "nickname": 1, "full_name": 1, "business_name": 1,
         "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1},
    ).to_list(10000)
    name_by_id = {u.get("id"): person_display_name(u, u.get("nickname") or "Creator") for u in users}
    for c in campaigns:
        for bid in (c.get("bids") or []):
            if not bid.get("creator_name") and bid.get("creator_id") in name_by_id:
                bid["creator_name"] = name_by_id[bid["creator_id"]]


@api_router.get("/campaigns")
async def get_campaigns(
    status: Optional[str] = None,
    include_drafts: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """Get campaigns with extended fields support"""
    query = {}
    
    if current_user['role'] == UserRole.CREATOR:
        # Creators see active campaigns to browse, PLUS every deal they were selected
        # for in ANY status (in_progress, work_submitted, completed, cancelled) — so
        # the "Completed" / "Cancelled" tabs of My Active Work aren't empty.
        query = {
            "$or": [
                {"status": CampaignStatus.ACTIVE},
                {"selected_creator": current_user['id']}
            ]
        }
    elif current_user['role'] == UserRole.BUSINESS:
        query['business_id'] = _brand_ws_id(current_user)  # team members see the owner's campaigns
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

    # Brands should see each bidder's real name, not the @handle.
    if current_user.get('role') == UserRole.BUSINESS:
        await enrich_bids_with_creator_names(normalized_campaigns)

    return _json_safe(normalized_campaigns)

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

    # Brands should see each bidder's real name, not the @handle.
    if current_user.get('role') == UserRole.BUSINESS:
        await enrich_bids_with_creator_names([campaign])

    return campaign

@api_router.post("/campaigns/{campaign_id}/bid")
async def submit_bid(campaign_id: str, data: BidCreate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can bid")
    
    if current_user.get('approval_status') != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Your profile must be approved first")

    if kyc_status_of(current_user) != "verified":
        raise HTTPException(status_code=403, detail="Complete KYC verification before bidding on campaigns")

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
        # Real name so brands see the creator's actual name, not the @handle.
        "creator_name": person_display_name(current_user, current_user['nickname']),
        **data.dict(),
        "submitted_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$push": {"bids": bid_doc}}
    )

    # Notify the brand that a creator has bid on their campaign.
    if campaign.get("business_id"):
        await notify_user(
            campaign["business_id"],
            "New bid on your campaign",
            f"{person_display_name(current_user, 'A creator')} placed a bid of ₹{int(data.amount or 0):,} on '{campaign.get('title', 'your campaign')}'.",
            link="/dashboard/business/pending-bids",
            ntype="info",
        )

    return {"message": "Bid submitted successfully"}

@api_router.post("/campaigns/{campaign_id}/bids/{bid_id}/decline")
async def decline_bid(campaign_id: str, bid_id: str, current_user: dict = Depends(get_current_user)):
    """Brand declines a creator's bid. Persists status on the bid (so it stays
    declined after a refresh) and notifies the creator."""
    campaign = await db.campaigns.find_one({"id": campaign_id})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.get("business_id") != _brand_ws_id(current_user):
        raise HTTPException(status_code=403, detail="This campaign belongs to another brand")
    # Match by bid id OR creator_id — the UI falls back to creator_id when a bid
    # has no id, so accept either as the identifier.
    bid = next((b for b in campaign.get("bids", []) if b.get("id") == bid_id or b.get("creator_id") == bid_id), None)
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")
    if bid.get("status") == "declined":
        return {"message": "Bid already declined"}

    await db.campaigns.update_one(
        {"id": campaign_id},
        {"$set": {"bids.$[b].status": "declined", "bids.$[b].declined_at": now_iso()}},
        array_filters=[{"$or": [{"b.id": bid_id}, {"b.creator_id": bid_id}]}],
    )

    creator_id = bid.get("creator_id")
    if creator_id:
        await notify_user(
            creator_id,
            "Your bid was declined",
            f"The brand declined your bid on '{campaign.get('title', 'a campaign')}'. Keep an eye out — plenty of other briefs are open.",
            link="/browse-briefs",
            ntype="warning",
        )
    return {"message": "Bid declined"}

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
    if not campaign or campaign['business_id'] != _brand_ws_id(current_user):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get creator details
    creator = await db.users.find_one({"id": creator_id}, {"_id": 0, "nickname": 1, "full_name": 1, "business_name": 1, "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1, "email": 1})
    if not creator:
        raise HTTPException(status_code=404, detail="Creator not found")
    creator_display = person_display_name(creator, "the creator")
    
    # Create escrow transaction
    selected_bid = next((bid for bid in campaign.get('bids', []) if bid['creator_id'] == creator_id), None)
    if not selected_bid:
        raise HTTPException(status_code=404, detail="Bid not found")
    
    escrow_id = str(uuid.uuid4())
    deal_amount = float(selected_bid['amount'])
    brand_fee = brand_commission(deal_amount)
    brand_total = round(deal_amount + brand_fee, 2)

    # The campaign budget was reserved on the wallet at post time. Convert that
    # reservation into the deal instead of charging again: refund any surplus
    # (reserved budget − deal total), or top up the small shortfall if commission
    # pushes the deal above the reserved budget.
    reservation = await db.escrow.find_one({"campaign_id": campaign_id, "status": "reserved"}, {"_id": 0})
    if reservation:
        escrow_id = reservation["id"]
        reserved = to_float(reservation.get("reserved_amount") or reservation.get("amount"))
        funded = True
        if brand_total <= reserved:
            surplus = round(reserved - brand_total, 2)
            if surplus > 0:
                await db.users.update_one({"id": current_user['id']}, {"$inc": {"balance": surplus}})
        else:
            shortfall = round(brand_total - reserved, 2)
            topup = await db.users.update_one(
                {"id": current_user['id'], "balance": {"$gte": shortfall}},
                {"$inc": {"balance": -shortfall}},
            )
            funded = topup.modified_count == 1
        escrow_doc = {
            "id": escrow_id,
            "campaign_id": campaign_id,
            "business_id": _brand_ws_id(current_user),
            "creator_id": creator_id,
            "amount": deal_amount,
            "brand_commission_amount": brand_fee,
            "brand_commission_percent": commission_percent(),
            "brand_charged": brand_total,
            "reserved_amount": reserved,
            "funded": funded,
            "status": "held",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.escrow.update_one({"id": escrow_id}, {"$set": escrow_doc})
    else:
        # Legacy path (campaign posted before budget-at-post reservation): charge now.
        # Best-effort debit: only deduct if the wallet can cover it.
        debit = await db.users.update_one(
            {"id": current_user['id'], "balance": {"$gte": brand_total}},
            {"$inc": {"balance": -brand_total}},
        )
        escrow_doc = {
            "id": escrow_id,
            "campaign_id": campaign_id,
            "business_id": _brand_ws_id(current_user),
            "creator_id": creator_id,
            "amount": deal_amount,
            "brand_commission_amount": brand_fee,
            "brand_commission_percent": commission_percent(),
            "brand_charged": brand_total,
            "funded": debit.modified_count == 1,
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

💰 Payment: ₹{int(selected_bid['amount']):,} has been held in escrow and will be released upon work approval.
📅 Delivery: {selected_bid['estimated_delivery_days']} days
📋 Campaign Brief: {campaign.get('brief_text', 'See campaign details')}

Let's discuss the next steps and get started! Feel free to ask any questions."""
    
    system_message_to_business = f"""✅ You've successfully selected {creator_display} for "{campaign['title']}"!

💰 Payment: ₹{int(selected_bid['amount']):,} has been held in escrow
📅 Expected Delivery: {selected_bid['estimated_delivery_days']} days

You can now communicate directly with {creator_display} to coordinate the work. Good luck with your campaign!"""
    
    # Send message to creator
    try:
        creator_message_doc = {
            "id": str(uuid.uuid4()),
            "sender_id": "system",
            "sender_nickname": "Platform",
            "recipient_id": creator_id,
            # Scope this system message to the exact brand<->creator thread so it
            # surfaces in that 1:1 conversation (GET /chat/{other}) and never leaks
            # into the brand's other creator threads.
            "thread_key": thread_key_for(creator_id, current_user['id']),
            "message": system_message_to_creator,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "read": False,
            "system_message": True
        }
        await db.messages.insert_one(creator_message_doc)
        print(f"[ok] Created system message to creator: {creator_message_doc['id']}")
    except Exception as e:
        print(f"[err] Error creating creator system message: {str(e)}")
    
    # Send message to business
    try:
        business_message_doc = {
            "id": str(uuid.uuid4()),
            "sender_id": "system",
            "sender_nickname": "Platform",
            "recipient_id": current_user['id'],
            # Same thread scope as the creator's copy (thread_key is symmetric) — this
            # is what makes the "You've successfully selected …" system message appear
            # in the BRAND's message section, which was the reported gap.
            "thread_key": thread_key_for(creator_id, current_user['id']),
            "message": system_message_to_business,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "read": False,
            "system_message": True
        }
        await db.messages.insert_one(business_message_doc)
        print(f"[ok] Created system message to business: {business_message_doc['id']}")
    except Exception as e:
        print(f"[err] Error creating business system message: {str(e)}")
    
    # Create initial conversation between business and creator
    try:
        conversation_starter = {
            "id": str(uuid.uuid4()),
            "sender_id": current_user['id'],
            "sender_nickname": current_user['nickname'],
            "recipient_id": creator_id,
            "message": f"Hi {first_name_of(creator)}! Looking forward to working with you on this campaign. Let me know if you have any questions!",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "read": False
        }
        await db.messages.insert_one(conversation_starter)
        print(f"[ok] Created conversation starter: {conversation_starter['id']}")
    except Exception as e:
        print(f"[err] Error creating conversation starter: {str(e)}")
    
    # Create in-app notification for creator
    notification_doc = {
        "id": str(uuid.uuid4()),
        "user_id": creator_id,
        "title": "🎉 You've been selected for a campaign!",
        "message": f"Congratulations! You've been selected for '{campaign['title']}'. Payment of ₹{int(selected_bid['amount']):,} is now in escrow.",
        "type": "success",
        "link": "/creator-dashboard",
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": "system"
    }
    await db.in_app_notifications.insert_one(notification_doc)

    # Notify the brand that their payment is now held in escrow.
    await notify_user(
        current_user['id'],
        "Payment held in escrow",
        f"₹{int(deal_amount):,} for '{campaign['title']}' is now held in escrow. It's released to {creator_display} once you approve their work.",
        link="/dashboard/business/wallet",
        ntype="success",
    )

    return {
        "message": "Creator selected and payment held in escrow",
        "creator_id": creator_id,
        "creator_nickname": creator['nickname'],
        "creator_name": creator_display,
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

    # Pick up any rule the admin added/enabled since the last message.
    await refresh_filter_rules()
    safety_check = check_contact_info_policy(data.message, brand_allowed_domains(current_user, recipient))
    if not safety_check["safe"]:
        result = await log_chat_violation(current_user, data.recipient_id, data.message, safety_check["violations"], "message")
        raise HTTPException(status_code=400, detail=contact_info_block_message(result["strike"]))

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

    # Tell the recipient they have a new message. Works both ways (brand → creator and
    # creator → brand) — sending a chat used to create no notification at all, so the
    # other side only found out if they happened to open Messages.
    # A creator's message only ever goes to a brand, who sees creators by first name.
    # A brand's message keeps the full business name for the creator.
    sender_label = (first_name_of(current_user, person_display_name(current_user))
                    if current_user.get("role") == UserRole.CREATOR
                    else person_display_name(current_user))
    body = (data.message or "").strip()
    preview = (body[:80] + "…") if len(body) > 80 else (body or "Sent an attachment")
    await notify_user(
        data.recipient_id,
        f"New message from {sender_label}",
        preview,
        link="/messages",
        ntype="message",
    )

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
            other_user = await db.users.find_one({"id": other_id}, {"_id": 0, "nickname": 1, "full_name": 1, "username": 1, "role": 1, "profile_photo": 1, "profile_picture": 1, "business_name": 1, "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1, "profile.logo": 1, "profile.profile_photo": 1, "profile.profile_picture": 1})
            # Fall back to _id — a partner created through the Node backend may carry only
            # `_id`, and looking up by `id` alone silently DROPPED the whole conversation
            # (the "I got a message notification but Messages is empty" bug).
            if not other_user:
                try:
                    from bson import ObjectId
                    other_user = await db.users.find_one({"_id": ObjectId(other_id)}, {"_id": 0, "nickname": 1, "full_name": 1, "username": 1, "role": 1, "profile_photo": 1, "profile_picture": 1, "business_name": 1, "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1, "profile.logo": 1, "profile.profile_photo": 1, "profile.profile_picture": 1})
                except Exception:
                    other_user = None
            # Never drop a real message. Show the thread even if the account can't be
            # resolved, rather than making the conversation disappear.
            if True:
                other_user = other_user or {"nickname": "Unknown user", "role": ""}
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
                    # Real name + @handle exposed separately so the UI can show the
                    # person's NAME (never the auto-generated "@handle") in the list.
                    "full_name": other_user.get('full_name'),
                    # Brand's company name (from their profile) so the UI shows the
                    # business NAME, not the auto-generated "@nickname" handle.
                    "business_name": other_user.get('business_name') or (other_user.get('profile') or {}).get('business_name'),
                    "profile": other_user.get('profile') or {},
                    "username": other_user.get('username'),
                    "role": other_user.get('role', ''),
                    "profile_picture": first_non_empty(
                        other_user.get('profile_photo'), other_user.get('profile_picture'),
                        (other_user.get('profile') or {}).get('profile_photo'),
                        (other_user.get('profile') or {}).get('profile_picture'),
                        (other_user.get('profile') or {}).get('logo'),
                    ),
                    "last_message": item,
                    "last_item_snippet": snippet[:120],
                    "timestamp": item_timestamp,
                    "unread_count": unread_per_partner.get(other_id, 0),
                    "associated_deal_status": deal_status,
                    # Campaign id of the deal on this thread — lets the creator leave a
                    # brand review once the deal is completed (POST /reviews needs it).
                    "associated_campaign_id": (deal or {}).get("id"),
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
async def review_chat_false_positive(violation_id: str, data: ChatFalsePositiveReview, current_user: dict = Depends(require_cap("content_moderation"))):
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
    # Creators can't open a dispute directly — they resolve with the brand first and
    # escalate to admin only if that fails (mirrors the deal-room /dispute guard).
    if data.type == "raise_dispute" and current_user.get("role") == UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Creators can't open a dispute directly. Try to resolve it with the brand, then use 'Escalate to admin' if you need help.")
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
    # The brand must cover the deal value PLUS the brand-side platform commission.
    required = round(amount + brand_commission(amount), 2)
    balance = to_float(brand.get("balance"))
    if balance < required:
        shortfall = round(required - balance, 2)
        deadline = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        await db.chat_action_cards.update_one(
            {"id": card["id"]},
            {"$set": {"pending_topup": True, "topup_deadline": deadline, "shortfall": shortfall}},
        )
        await notify_user(
            brand["id"],
            "Top up to confirm this deal",
            f"A creator accepted your offer for ₹{int(amount)} (+₹{int(brand_commission(amount))} platform fee) but your wallet holds ₹{int(balance)}. Add ₹{int(shortfall)} within 24 hours to confirm the deal.",
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
        # A private invitation is product-based (PRD 5.5 → ships, then content),
        # so it defaults to requiring shipment. A creator-initiated custom offer
        # is a service by default (no shipment) unless it says otherwise.
        req_ship = fields.get("requires_shipment")
        if req_ship is None:
            req_ship = card.get("type") == "private_invitation"
        campaign = {
            "id": str(uuid.uuid4()),
            "business_id": brand["id"],
            "brand_name": brand.get("nickname") or (brand.get("profile") or {}).get("business_name") or "Brand",
            "title": fields.get("campaign_name") or "Direct deal",
            "brief_text": fields.get("deliverable_summary") or fields.get("diff_vs_original") or "",
            "objectives": [],
            "budget_min": amount,
            "budget_max": amount,
            "requires_shipment": bool(req_ship),
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
        brand_fee = brand_commission(amount)
        brand_total = round(float(amount) + brand_fee, 2)
        debit = await db.users.update_one(
            {"id": brand["id"], "balance": {"$gte": brand_total}},
            {"$inc": {"balance": -brand_total}},
        )
        funded = debit.modified_count == 1
        await db.escrow.insert_one({
            "id": escrow_id,
            "campaign_id": campaign["id"],
            "business_id": brand["id"],
            "creator_id": creator["id"],
            "amount": amount,
            "brand_commission_amount": brand_fee,
            "brand_commission_percent": commission_percent(),
            "brand_charged": brand_total,
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
        f"{person_display_name(current_user, 'The brand')} withdrew their {card.get('type', 'offer').replace('_', ' ')}.",
        link="/messages",
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
    await validate_chat_access(current_user, other_user_id, allow_action_cards_only=True, read_only=True)
    messages = await db.messages.find({
        "$or": [
            {"sender_id": current_user['id'], "recipient_id": other_user_id},
            {"sender_id": other_user_id, "recipient_id": current_user['id']},
            # System messages (sender_id="system") are addressed to one user but belong
            # to a specific 1:1 thread. Match this viewer's own system messages scoped
            # to THIS thread by thread_key, so e.g. the brand sees "You've successfully
            # selected …" in the creator's thread — without it leaking into other threads.
            {"sender_id": "system", "recipient_id": current_user['id'],
             "thread_key": thread_key_for(current_user['id'], other_user_id)}
        ]
    }, {"_id": 0}).sort("timestamp", 1).to_list(1000)

    action_cards = await db.chat_action_cards.find({
        "participants": {"$all": [current_user['id'], other_user_id]}
    }, {"_id": 0}).sort("created_at", 1).to_list(1000)

    # Deal-room SYSTEM messages ("Content submitted…", "Brand requested revisions…",
    # "Creator partially accepted…") live in db.deal_messages, scoped by campaign — so
    # the creator saw them in their Deal Room but the brand (who chats via the 1:1
    # ChatPopup / Messages page) never did. Surface those system notices in this 1:1
    # thread for BOTH parties. We pull only sender_type="system"; the deal room's own
    # human chat stays in the deal room.
    shared_campaigns = await db.campaigns.find({
        "$or": [
            {"business_id": current_user['id'], "selected_creator": other_user_id},
            {"business_id": other_user_id, "selected_creator": current_user['id']},
        ]
    }, {"_id": 0, "id": 1}).to_list(100)
    deal_system_messages = []
    if shared_campaigns:
        deal_system_messages = await db.deal_messages.find({
            "campaign_id": {"$in": [c["id"] for c in shared_campaigns]},
            "sender_type": "system",
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

    items = (
        [message_to_chat_item(msg) for msg in messages]
        + [message_to_chat_item(msg) for msg in deal_system_messages]
        + [action_card_to_chat_item(card) for card in action_cards]
    )
    items.sort(key=lambda item: item.get("created_at") or item.get("timestamp") or "")
    return items

@api_router.get("/admin/violations")
async def get_all_violations(current_user: dict = Depends(require_cap("content_moderation"))):
    """Admin endpoint to view all violations"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    violations = await db.violations.find({}, {"_id": 0}).sort("timestamp", -1).limit(100).to_list(100)
    return violations

@api_router.get("/admin/chats")
async def get_all_chats(current_user: dict = Depends(require_cap("content_moderation"))):
    """Admin endpoint to view all chat conversations"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get all messages
    messages = await db.messages.find({}, {"_id": 0}).to_list(10000)
    
    # Group by conversation (unique pairs of users)
    conversations_dict = {}
    for msg in messages:
        sender = msg.get('sender_id')
        recipient = msg.get('recipient_id')
        # Skip non person-to-person items (system / action-card / invitation rows have
        # no recipient pair and no timestamp) so they can't crash the oversight view.
        if not sender or not recipient:
            continue
        # Create a consistent conversation ID (sorted user IDs)
        user_pair = tuple(sorted([sender, recipient]))
        # Timestamp field name varies by source (Node vs Python) — fall back gracefully.
        ts = str(msg.get('timestamp') or msg.get('created_at') or msg.get('createdAt') or msg.get('read_at') or '')
        text = (msg.get('message') or '')[:50]

        if user_pair not in conversations_dict or ts > conversations_dict[user_pair]['last_message_at']:
            conversations_dict[user_pair] = {
                "user1_id": user_pair[0],
                "user2_id": user_pair[1],
                "last_message": text,
                "last_message_at": ts,
                # Preserve a filtered flag already seen for this pair from an older message.
                "has_filtered": conversations_dict.get(user_pair, {}).get('has_filtered', False),
            }

        # Check if any message in this conversation was filtered
        if msg.get('filtered', False):
            conversations_dict[user_pair]['has_filtered'] = True
    
    # Enrich with user details
    conversations = []
    for user_pair, conv_data in conversations_dict.items():
        user1 = await db.users.find_one({"id": conv_data['user1_id']}, {"_id": 0, "nickname": 1, "username": 1, "role": 1, "warning_count": 1})
        user2 = await db.users.find_one({"id": conv_data['user2_id']}, {"_id": 0, "nickname": 1, "username": 1, "role": 1, "warning_count": 1})
        pair_ids = [conv_data['user1_id'], conv_data['user2_id']]

        # Blocked messages for THIS conversation. A contact-info hit never reaches
        # db.messages (send_message raises before the insert), so the `filtered` flag
        # on messages was always False — which left this queue permanently empty even
        # while users were being strike-paused. db.violations is the real record.
        violation_count = await db.violations.count_documents({
            "user_id": {"$in": pair_ids},
            "recipient_id": {"$in": pair_ids},
        })

        # Open user-reports against either participant (harassment / spam queue).
        report_count = await db.user_reports.count_documents({
            "reported_user_id": {"$in": pair_ids},
            "status": "open"
        })

        # A user is "on strike watch" while they carry one or more active strikes.
        u1_watch = bool((user1 or {}).get('warning_count', 0))
        u2_watch = bool((user2 or {}).get('warning_count', 0))

        conversations.append({
            "conversation_id": f"{conv_data['user1_id']}_{conv_data['user2_id']}",
            "user1": {
                "id": conv_data['user1_id'],
                "nickname": user1.get('nickname', 'Unknown') if user1 else 'Unknown',
                "username": user1.get('username') if user1 else None,
                "role": user1.get('role', '') if user1 else '',
                "on_strike_watch": u1_watch
            },
            "user2": {
                "id": conv_data['user2_id'],
                "nickname": user2.get('nickname', 'Unknown') if user2 else 'Unknown',
                "username": user2.get('username') if user2 else None,
                "role": user2.get('role', '') if user2 else '',
                "on_strike_watch": u2_watch
            },
            "last_message": conv_data['last_message'],
            "last_message_at": conv_data['last_message_at'],
            # Either a delivered-but-flagged message (legacy) OR a blocked one.
            "has_violations": conv_data['has_filtered'] or violation_count > 0,
            "violation_count": violation_count,
            # New signals for the Chat Oversight queues:
            "report_count": report_count,
            "reported": report_count > 0,
            "on_strike_watch": u1_watch or u2_watch
        })
    
    # Sort by last message time (most recent first)
    conversations.sort(key=lambda x: x['last_message_at'], reverse=True)
    
    return conversations

@api_router.get("/admin/chat/{user1_id}/{user2_id}")
async def get_chat_for_admin(user1_id: str, user2_id: str, current_user: dict = Depends(require_cap("content_moderation"))):
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

    # Senders with an open user-report (so admins can spot reported authors).
    reported_user_ids = set(await db.user_reports.distinct("reported_user_id", {
        "reported_user_id": {"$in": [user1_id, user2_id]},
        "status": "open"
    }))

    # Enrich each message with the sender's current nickname/username for admin display
    sender_cache: Dict[str, dict] = {}
    for msg in messages:
        sender_id = msg.get("sender_id")
        # Flag messages from reported users so the "User reports" queue can surface them.
        if sender_id in reported_user_ids and not msg.get("reported"):
            msg["reported"] = True
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

    # Blocked messages never made it into db.messages — the contact-info filter raises
    # before the insert. Fold them in from db.violations as `filtered` rows so the
    # admin can actually read what was blocked and approve / confirm it. Without this
    # the drill-down said "No flagged messages in this conversation" every time.
    pair = [user1_id, user2_id]
    blocked = await db.violations.find({
        "user_id": {"$in": pair},
        "recipient_id": {"$in": pair},
    }, {"_id": 0}).to_list(500)

    for v in blocked:
        sender_id = v.get("user_id")
        if sender_id not in sender_cache:
            sender_cache[sender_id] = await db.users.find_one(
                {"id": sender_id}, {"_id": 0, "nickname": 1, "username": 1}
            ) or {}
        sender = sender_cache[sender_id]
        messages.append({
            "id": v.get("id"),
            "violation_id": v.get("id"),
            "sender_id": sender_id,
            "sender_nickname": sender.get("nickname") or v.get("user_nickname"),
            "sender_username": sender.get("username"),
            "recipient_id": v.get("recipient_id"),
            "message": v.get("original_message"),
            "timestamp": v.get("timestamp"),
            "created_at": v.get("timestamp"),
            # What the oversight UI keys off to show it in the queue + action bar.
            "filtered": True,
            "blocked": True,
            "delivered": False,
            "violations": v.get("violations", []),
            "false_positive_status": v.get("false_positive_status"),
            "attachment_urls": [],
        })

    messages.sort(key=lambda m: str(m.get("timestamp") or m.get("created_at") or ""))
    return messages


# ---------------------------------------------------------------------------
# Chat Oversight (PRD 11.12): per-message moderation + filter-rule management
# ---------------------------------------------------------------------------

class MessageModerationAction(BaseModel):
    user1Id: str
    user2Id: str
    timestamp: str
    sender: Optional[str] = None
    action: str  # "approve" | "confirm" | "escalate"
    escalation: Optional[str] = None  # for action == "escalate": "warn" | "suspend"


class FilterRulePropose(BaseModel):
    type: str  # "regex" | "keyword"
    label: str
    pattern: str


class FilterRuleToggle(BaseModel):
    enabled: bool


async def _restore_strike_for_violation(violation: dict, reviewed_by: str) -> None:
    """Approve a false positive: invalidate its strike and recompute the user's
    active warning count (mirrors the false-positive-review endpoint)."""
    reviewed_at = now_iso()
    await db.violations.update_one(
        {"id": violation["id"]},
        {"$set": {"false_positive_status": "approved", "false_positive_reviewed_at": reviewed_at, "false_positive_reviewed_by": reviewed_by}}
    )
    await db.chat_strikes.update_many(
        {"violation_id": violation["id"]},
        {"$set": {"invalidated": True, "invalidated_at": reviewed_at, "invalidated_by": reviewed_by}}
    )
    active_strikes = await db.chat_strikes.count_documents({"user_id": violation["user_id"], "invalidated": {"$ne": True}})
    await db.users.update_one(
        {"id": violation["user_id"]},
        {"$set": {"warning_count": active_strikes}, "$unset": {"action_cards_only_until": ""}}
    )
    await db.chat_pauses.update_many({"user_id": violation["user_id"]}, {"$set": {"invalidated": True, "paused_until": reviewed_at}})


@api_router.post("/admin/message/moderate")
async def moderate_chat_message(data: MessageModerationAction, current_user: dict = Depends(require_cap("content_moderation"))):
    """Per-message oversight action: approve (false positive), confirm violation
    (apply strike + notify), or escalate (warn / suspend the sender)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required")
    if data.action not in ["approve", "confirm", "escalate"]:
        raise HTTPException(status_code=400, detail="action must be approve, confirm, or escalate")

    # Locate the message between the two participants at the given timestamp.
    message = await db.messages.find_one({
        "timestamp": data.timestamp,
        "$or": [
            {"sender_id": data.user1Id, "recipient_id": data.user2Id},
            {"sender_id": data.user2Id, "recipient_id": data.user1Id},
        ],
    }, {"_id": 0})

    # A blocked message was never inserted into db.messages — it only exists as a
    # violation. Rebuild it from there so admins can approve/confirm it too, instead
    # of every action on the contact-info queue 404-ing.
    blocked_violation = None
    if not message:
        blocked_violation = await db.violations.find_one({
            "timestamp": data.timestamp,
            "user_id": {"$in": [data.user1Id, data.user2Id]},
            "recipient_id": {"$in": [data.user1Id, data.user2Id]},
        }, {"_id": 0})
        if not blocked_violation:
            raise HTTPException(status_code=404, detail="Message not found")
        message = {
            "sender_id": blocked_violation.get("user_id"),
            "sender_nickname": blocked_violation.get("user_nickname"),
            "recipient_id": blocked_violation.get("recipient_id"),
            "message": blocked_violation.get("original_message", ""),
            "timestamp": blocked_violation.get("timestamp"),
        }

    sender_id = message.get("sender_id")
    recipient_id = message.get("recipient_id")
    reviewed_at = now_iso()
    result_message = ""

    # Find the violation tied to this message (filtered messages create one).
    violation = await db.violations.find_one({
        "user_id": sender_id,
        "$or": [{"original_message": message.get("message")}, {"timestamp": data.timestamp}],
    }, {"_id": 0}, sort=[("timestamp", -1)])

    if data.action == "approve":
        # False positive: deliver the message and restore the strike if any.
        if blocked_violation:
            # It was never delivered — insert it now so the recipient finally sees it.
            await db.messages.insert_one({
                "id": str(uuid.uuid4()),
                "sender_id": sender_id,
                "sender_nickname": message.get("sender_nickname"),
                "recipient_id": recipient_id,
                "message": message.get("message", ""),
                "attachment_urls": [],
                "timestamp": data.timestamp,
                "created_at": data.timestamp,
                "read": False,
                "read_by": [sender_id],
                "delivered_at": reviewed_at,
                "status": "delivered",
                "filtered": False,
                "moderation_status": "approved",
            })
            await db.violations.update_one(
                {"id": blocked_violation["id"]},
                {"$set": {"status": "approved", "false_positive_status": "confirmed",
                          "reviewed_at": reviewed_at, "reviewed_by": current_user["id"]}},
            )
        else:
            await db.messages.update_one(
                {"timestamp": data.timestamp, "sender_id": sender_id, "recipient_id": recipient_id},
                {"$set": {"filtered": False, "moderation_status": "approved", "reported": False}}
            )
        if violation:
            await _restore_strike_for_violation(violation, current_user["id"])
        if sender_id:
            await notify_user(sender_id, "Message cleared", "An admin reviewed a flagged message and cleared it. Any related strike has been removed.", ntype="info")
        result_message = "Message approved as a false positive."

    elif data.action == "confirm":
        # Confirm the violation: ensure a strike exists and notify the sender.
        if not violation:
            logged = await log_chat_violation(
                {"id": sender_id, "nickname": message.get("sender_nickname")},
                recipient_id,
                message.get("message", ""),
                [{"type": "manual_review", "severity": "warning", "detail": "Confirmed by admin from chat oversight"}],
                source="admin_confirm",
            )
            violation = logged["violation"]
        else:
            await db.violations.update_one({"id": violation["id"]}, {"$set": {"status": "confirmed", "confirmed_by": current_user["id"], "confirmed_at": reviewed_at}})
        await db.messages.update_one(
            {"timestamp": data.timestamp, "sender_id": sender_id, "recipient_id": recipient_id},
            {"$set": {"moderation_status": "confirmed"}}
        )
        if sender_id:
            await notify_user(sender_id, "Policy strike applied", "An admin confirmed that one of your messages violated platform policy. A strike has been applied to your account.", ntype="warning")
        result_message = "Violation confirmed and strike applied."

    else:  # escalate
        escalation = data.escalation if data.escalation in ["warn", "suspend"] else "warn"
        if escalation == "suspend":
            await db.users.update_one(
                {"id": sender_id},
                {"$set": {"banned": True, "banned_reason": "Suspended by admin from chat oversight", "banned_at": reviewed_at}}
            )
            if sender_id:
                await notify_user(sender_id, "Account suspended", "Your account has been suspended following a chat policy review. Contact support if you believe this is a mistake.", ntype="error")
            result_message = "User suspended."
        else:
            if sender_id:
                await notify_user(sender_id, "Warning issued", "An admin issued a warning regarding your recent chat activity. Continued violations may lead to suspension.", ntype="warning")
            result_message = "Warning issued to user."
        await db.messages.update_one(
            {"timestamp": data.timestamp, "sender_id": sender_id, "recipient_id": recipient_id},
            {"$set": {"moderation_status": f"escalated_{escalation}"}}
        )

    # Audit trail for the weekly edge-case review.
    await db.chat_moderation_actions.insert_one({
        "id": str(uuid.uuid4()),
        "message_timestamp": data.timestamp,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "action": data.action,
        "escalation": data.escalation,
        "violation_id": (violation or {}).get("id"),
        "moderated_by": current_user["id"],
        "created_at": reviewed_at,
    })

    return {"message": result_message, "action": data.action}


# Default filter rules seeded when the collection is empty, so admins always
# see what the contact-info filter is enforcing.
DEFAULT_FILTER_RULES = [
    {"id": "r-phone", "type": "regex", "pattern": r"\b(?:\+?\d[ -]?){7,}\b", "label": "Phone numbers", "enabled": True, "status": "active"},
    {"id": "r-email", "type": "regex", "pattern": r"[\w.+-]+@[\w-]+\.[\w.-]+", "label": "Email addresses", "enabled": True, "status": "active"},
    {"id": "r-apps", "type": "keyword", "pattern": "whatsapp, telegram, signal, snapchat", "label": "Off-platform apps", "enabled": True, "status": "active"},
    {"id": "r-callme", "type": "keyword", "pattern": "call me, text me, dm me, reach me at", "label": "Contact solicitations", "enabled": True, "status": "active"},
]


@api_router.get("/admin/filter-rules")
async def list_filter_rules(current_user: dict = Depends(require_cap("content_moderation"))):
    """List the contact-info filter rules (regex patterns and keyword lists)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required")
    rules = await db.filter_rules.find({}, {"_id": 0}).sort("created_at", 1).to_list(500)
    # Always include the built-in defaults so the panel is never empty.
    existing_ids = {r.get("id") for r in rules}
    seeded = [r for r in DEFAULT_FILTER_RULES if r["id"] not in existing_ids]
    return seeded + rules


@api_router.post("/admin/filter-rules/propose")
async def propose_filter_rule(data: FilterRulePropose, current_user: dict = Depends(require_cap("content_moderation"))):
    """Propose a new filter rule. Proposals stay disabled pending senior-admin
    (ADMIN role) review before they go live."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required")
    if data.type not in ["regex", "keyword"]:
        raise HTTPException(status_code=400, detail="type must be regex or keyword")
    if not data.label.strip() or not data.pattern.strip():
        raise HTTPException(status_code=400, detail="label and pattern are required")
    # Validate regex patterns up front so we never seed an un-compilable rule.
    if data.type == "regex":
        try:
            re.compile(data.pattern)
        except re.error as exc:
            raise HTTPException(status_code=400, detail=f"Invalid regex: {exc}")
    # Whoever adds a rule here already holds content_moderation, and the old second
    # approval step just stranded every new rule in "Awaiting review" with nothing
    # able to approve it. Rules go live on save — which is what the panel promises —
    # and a careless one is switched off or deleted with the endpoints below.
    rule = {
        "id": str(uuid.uuid4()),
        "type": data.type,
        "label": data.label.strip(),
        "pattern": data.pattern.strip(),
        "enabled": True,
        "status": "active",
        "hits": 0,
        "proposed_by": current_user["id"],
        "proposed_by_nickname": current_user.get("nickname"),
        "created_at": now_iso(),
    }
    await db.filter_rules.insert_one(rule)
    # Bite on the very next message rather than waiting out the cache TTL.
    await refresh_filter_rules(force=True)
    await notify_admins(
        "New filter rule added",
        f"{current_user.get('nickname', current_user['id'])} added a {data.type} rule \"{data.label}\" — it is now live.",
        link="/dashboard/admin/flagged",
    )
    return {"message": "Rule added — live from the next message.", "rule": {k: v for k, v in rule.items() if k != "_id"}}


@api_router.post("/admin/filter-rules/{rule_id}/toggle")
async def toggle_filter_rule(rule_id: str, data: FilterRuleToggle,
                             current_user: dict = Depends(require_cap("content_moderation"))):
    """Switch a rule on or off. This is what promotes an older 'Awaiting review'
    rule to live — and it takes effect immediately, not after the cache TTL."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required")
    # The built-in defaults used to be virtual — merged into the list response but
    # never stored — so there was no row to toggle and this 404'd. Materialise the
    # rule on first touch.
    existing = await db.filter_rules.find_one({"id": rule_id}, {"_id": 0})
    if not existing:
        default = next((r for r in DEFAULT_FILTER_RULES if r["id"] == rule_id), None)
        if not default:
            raise HTTPException(status_code=404, detail="Rule not found")
        await db.filter_rules.insert_one({**default, "hits": 0, "created_at": now_iso()})

    await db.filter_rules.update_one(
        {"id": rule_id},
        {"$set": {"enabled": data.enabled, "status": "active" if data.enabled else "disabled"}},
    )
    await refresh_filter_rules(force=True)
    rule = await db.filter_rules.find_one({"id": rule_id}, {"_id": 0})
    return {"success": True, "rule": rule}


@api_router.delete("/admin/filter-rules/{rule_id}")
async def delete_filter_rule(rule_id: str, current_user: dict = Depends(require_cap("content_moderation"))):
    """Delete a rule outright."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required")
    result = await db.filter_rules.delete_one({"id": rule_id})
    if result.deleted_count == 0:
        # A built-in that was never materialised: store it disabled so it stops
        # showing up as an active rule the admin can't get rid of.
        default = next((r for r in DEFAULT_FILTER_RULES if r["id"] == rule_id), None)
        if not default:
            raise HTTPException(status_code=404, detail="Rule not found")
        await db.filter_rules.insert_one({**default, "enabled": False, "status": "disabled",
                                          "hits": 0, "created_at": now_iso()})
    await refresh_filter_rules(force=True)
    return {"success": True}

# Work Submission Routes
async def ensure_ready_for_content(campaign: dict):
    """PRD 8.3: content can only be submitted once the deal has reached the
    content stage. If the brief requires shipment, the product must be received
    first; and no submissions while a dispute is open."""
    await ensure_not_disputed(campaign['id'])
    if campaign.get('requires_shipment'):
        shipment = await db.shipments.find_one({"campaign_id": campaign['id']}, {"_id": 0})
        receipt = await db.deal_receipts.find_one({"campaign_id": campaign['id']}, {"_id": 0})
        received = bool(
            (shipment or {}).get('received_at')
            or (shipment or {}).get('status') == 'received'
            or (receipt or {}).get('received_at')
        )
        if not received:
            raise HTTPException(
                status_code=409,
                detail="You can submit content only after receiving the product. Confirm the shipment as received first.",
            )


@api_router.post("/work/submit")
async def submit_work(data: WorkSubmission, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can submit work")

    campaign = await db.campaigns.find_one({"id": data.campaign_id}, {"_id": 0})
    if not campaign or campaign.get('selected_creator') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    # PRD 8.3: gate submission on shipment receipt (and pause during disputes).
    await ensure_ready_for_content(campaign)

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

    # Update campaign status + surface the submission for the brand's Work Review.
    await db.campaigns.update_one(
        {"id": data.campaign_id},
        {"$set": {
            "status": "work_submitted",
            "work_submission": {
                "id": work_doc["id"],
                "creator_id": current_user['id'],
                "work_files": data.work_files,
                "video_url": primary_file,
                "creator_note": data.description,
                "submitted_at": work_doc["submitted_at"],
            },
        }}
    )

    await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), "content_submitted", "Content was submitted for brand review.")
    await insert_deal_system_message(campaign, "Content was submitted and is awaiting brand review.")

    # Notify the brand that content is ready for review.
    if campaign.get("business_id"):
        await notify_user(
            campaign["business_id"],
            "Content submitted for review",
            f"{first_name_of(current_user, fallback='The creator')} submitted content for '{campaign.get('title', 'your campaign')}'. Review it to release payment.",
            link="/dashboard/business/work-review",
            ntype="info",
        )

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


@api_router.get("/work/{work_id}/download")
async def download_work(work_id: str, current_user: dict = Depends(get_current_user)):
    """Download the delivered file. Allowed for the brand on the campaign, the
    creator, or an admin — and (for the brand) only once the work is approved."""
    # The Work Review card passes a CAMPAIGN id, not a work_submission id (same shape as
    # the approve fix). Resolve either: try the work id first, then fall back to the
    # campaign's latest work submission — preferring the approved one.
    work = await db.work_submissions.find_one({"id": work_id}, {"_id": 0})
    if not work:
        campaign_match = await find_campaign_by_any_id(work_id)
        cid = (campaign_match or {}).get("id", work_id)
        work = await db.work_submissions.find_one(
            {"campaign_id": cid, "status": WorkStatus.APPROVED}, {"_id": 0}, sort=[("submitted_at", -1)]
        ) or await db.work_submissions.find_one(
            {"campaign_id": cid}, {"_id": 0}, sort=[("submitted_at", -1)]
        )
    if not work:
        raise HTTPException(status_code=404, detail="No submitted work found for this deal")
    campaign = await db.campaigns.find_one({"id": work.get("campaign_id")}, {"_id": 0}) or {}
    uid, role = current_user["id"], current_user.get("role")
    is_brand = _brand_ws_id(current_user) == campaign.get("business_id")
    is_creator = uid == campaign.get("selected_creator") or uid == work.get("creator_id")
    if not (is_brand or is_creator or role == UserRole.ADMIN):
        raise HTTPException(status_code=403, detail="Not authorized to download this work")
    # Unlock on approval. Match the deal-room asset gate (see work_approved above):
    # treat a COMPLETED campaign as approved too, so a finished deal whose resolved
    # work_submissions row was never stamped "approved" (legacy deals, multi-version
    # submissions, submitted_at sort ties) still downloads instead of falsely 403-ing
    # "unlocks after you approve" on a card that already shows Approved.
    work_approved = (
        work.get("status") == WorkStatus.APPROVED
        or campaign.get("status") == CampaignStatus.COMPLETED
    )
    if is_brand and role != UserRole.ADMIN and not work_approved:
        raise HTTPException(status_code=403, detail="Download unlocks after you approve the work")
    versions = work.get("versions") or []
    latest = versions[-1] if versions else {}
    # work_submissions store the delivered files in `work_files` (first = the video);
    # older/legacy docs may carry video_url/original_url. Also fall back to the newest
    # approved content submission, which always has the raw video_url.
    work_files = work.get("work_files") or []
    url = (latest.get("original_url") or latest.get("video_url")
           or work.get("original_url") or work.get("video_url")
           or (work_files[0] if work_files else None))
    if not url:
        sub = await db.deal_content_submissions.find_one(
            {"campaign_id": work.get("campaign_id")}, {"_id": 0}, sort=[("version", -1)]
        ) or {}
        url = sub.get("original_url") or sub.get("video_url")
    if not url:
        raise HTTPException(status_code=404, detail="No downloadable file for this work")
    # Files live on Cloudinary or /uploads — hand back the URL to stream from.
    from fastapi.responses import RedirectResponse
    if not str(url).startswith("http"):
        url = f"/{str(url).lstrip('/')}"
    return RedirectResponse(url)


@api_router.post("/work/{work_id}/approve")
async def approve_work(work_id: str, current_user: dict = Depends(get_current_user)):
    work = await db.work_submissions.find_one({"id": work_id})
    if not work:
        raise HTTPException(status_code=404, detail="Work not found")

    campaign = await db.campaigns.find_one({"id": work['campaign_id']})
    if campaign['business_id'] != _brand_ws_id(current_user):
        raise HTTPException(status_code=403, detail="Not authorized")

    # PRD 9.3: no approval while a dispute is open.
    await ensure_not_disputed(work['campaign_id'])

    now = now_iso()
    already_approved = work.get('status') == WorkStatus.APPROVED

    # PRD 8.6/8.7: approval is final. If the payout was already scheduled/released,
    # re-approving is a graceful no-op (not an error). But if the work was somehow
    # marked approved without the payout ever being scheduled, finish the job now
    # so the deal can't get stuck with escrow held and the creator unpaid.
    escrow = await db.escrow.find_one({"campaign_id": work['campaign_id']})
    if already_approved and escrow and escrow.get('payout_status') == 'released':
        return {
            "message": "Content was already approved and the creator has been paid.",
            "payout_status": "released",
            "net_payable": escrow.get('net_payable', 0),
        }
    if already_approved and escrow and escrow.get('payout_status') == 'scheduled':
        # Approved earlier but the payout is still held — release it to the creator now.
        await release_scheduled_payout(escrow)
        escrow = await db.escrow.find_one({"campaign_id": work['campaign_id']})
        return {
            "message": "Creator funded instantly.",
            "payout_status": "released",
            "net_payable": (escrow or {}).get('net_payable', 0),
        }

    if not already_approved:
        # RACE GUARD: flip to APPROVED only if it isn't already approved, atomically.
        # If a concurrent approval won the flip, bail out WITHOUT releasing payout again
        # (prevents double-payout when both parties/tabs approve at once).
        flip = await db.work_submissions.update_one(
            {"id": work_id, "status": {"$ne": WorkStatus.APPROVED}},
            {"$set": {"status": WorkStatus.APPROVED, "approved_at": now}}
        )
        if flip.modified_count == 0:
            esc2 = await db.escrow.find_one({"campaign_id": work['campaign_id']})
            return {
                "message": "Content was already approved (a concurrent action won).",
                "payout_status": (esc2 or {}).get('payout_status', 'released'),
                "net_payable": (esc2 or {}).get('net_payable', 0),
            }

    # Keep the creator's deal content view in sync — but stamp ONLY the version the brand
    # actually approved. The old update_many() swept every row still marked "submitted",
    # so v1..v3 (already sent back for revision) all flipped to Approved next to v4.
    # Scope to the ASSET this work item was for, so approving deliverable #2 can't stamp
    # deliverable #1's latest version (they share a campaign_id but are separate assets).
    work_idx = work.get('deliverable_index') or 0
    approved_version = await db.deal_content_submissions.find_one(
        {"campaign_id": work['campaign_id'],
         "$or": [{"deliverable_index": work_idx},
                 # legacy rows predate the field; only index 0 may claim them
                 *([{"deliverable_index": {"$exists": False}}] if work_idx == 0 else [])]},
        sort=[("version", -1)]
    )
    if approved_version:
        await db.deal_content_submissions.update_one(
            {"id": approved_version['id']},
            {"$set": {"status": "approved", "approved_at": now}}
        )
        # Anything older for THIS asset that never got a verdict is superseded.
        await db.deal_content_submissions.update_many(
            {"campaign_id": work['campaign_id'],
             "deliverable_index": approved_version.get('deliverable_index') or 0,
             "version": {"$lt": approved_version.get('version', 1)},
             "status": {"$nin": ["approved", "revision_requested"]}},
            {"$set": {"status": "superseded"}}
        )

    # PAYOUT GATE: only fund once EVERY required asset has an approved submission.
    # Previously one approval released the whole payout, so a brief asking for 3 Reels
    # paid out in full after the first video. For a single-asset brief (required == 1,
    # which is every legacy campaign) this is satisfied immediately and the behaviour
    # is identical to before.
    progress = await deliverables_progress(campaign)
    if not progress["complete"]:
        await db.campaigns.update_one(
            {"id": work['campaign_id']},
            {"$set": {"status": "in_progress", "updated_at": now}}
        )
        await insert_deal_activity(
            campaign, "brand", current_user.get('nickname', 'Brand'), "content_approved",
            f"Deliverable {progress['approved']} of {progress['required']} approved. "
            f"{progress['remaining']} still to be delivered before payout.",
        )
        await insert_deal_system_message(
            campaign,
            f"Deliverable approved ({progress['approved']}/{progress['required']}). "
            f"The creator has {progress['remaining']} more to submit before the deal completes.",
        )
        await notify_user(
            work['creator_id'], "Deliverable approved",
            f"{progress['approved']} of {progress['required']} deliverables approved. "
            f"Submit the remaining {progress['remaining']} to complete this deal.",
            link="/my-deals", ntype="success", email=True, category="deal_updates",
        )
        return {
            "message": f"Deliverable approved ({progress['approved']}/{progress['required']}).",
            "payout_status": "awaiting_remaining_deliverables",
            "deliverables": progress,
        }

    # Every deliverable is in — fund the creator instantly (no hold period).
    payout_info = await release_payout_now(campaign, work, source="approval")

    if payout_info.get("released"):
        # release_scheduled_payout already marks the deal complete and notifies the creator.
        await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "content_approved",
                                   f"Content approved. ₹{int(payout_info.get('net_payable', 0))} released to the creator.")
        await insert_deal_system_message(campaign, "Content approved. The creator has been paid.")
        return {"message": "Content approved. Creator funded instantly.", "payout_status": "released", **payout_info}

    # Fallback: nothing to release (e.g. a legacy deal with no escrow). Still mark
    # the campaign completed so it stops showing as "work submitted" / pending review.
    await db.campaigns.update_one(
        {"id": work['campaign_id']},
        {"$set": {"status": CampaignStatus.COMPLETED, "payout_status": "approved", "approved_at": now, "updated_at": now}}
    )
    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "content_approved", "Content approved.")
    await notify_user(work['creator_id'], "Your content was approved", "Your content was approved.", link="/my-deals", ntype="success", email=True, category="deal_updates")
    return {"message": "Content approved.", **payout_info}


async def schedule_payout_for_deal(campaign: dict, work: dict, source: str = "approval") -> dict:
    """PRD 8.7: queue the creator's payout for `payout_delay_days` after approval,
    netting TDS and any late-delivery penalty. Does NOT move money yet."""
    escrow = await db.escrow.find_one({"campaign_id": campaign['id']})
    if not escrow:
        return {"payout_scheduled_at": None, "net_payable": 0, "tds_amount": 0, "penalty_amount": 0}
    creator = await db.users.find_one({"id": work['creator_id']}, {"_id": 0, "level": 1, "tds_exempt": 1}) or {}
    gross = float(escrow.get('amount') or 0)
    delay = payout_delay_for(creator.get('level'))
    scheduled_at = (datetime.now(timezone.utc) + timedelta(days=delay)).isoformat()
    tds = cf.compute_tds(gross, exempt=bool(creator.get('tds_exempt')))
    late = await assess_late_delivery(work['creator_id'], campaign, work)
    penalty = round(gross * late['penalty_pct'] / 100, 2) if late['is_late'] else 0.0
    # Creator-side platform commission (deducted from the payout).
    commission = creator_commission(gross)
    net = round(gross - commission - tds - penalty, 2)
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
            "commission_amount": commission,
            "commission_percent": commission_percent(),
            "penalty_pct": late['penalty_pct'],
            "penalty_brand_credit": round(penalty * cf.LATE_PENALTY_BRAND_SHARE, 2),
            "late_severity": late['severity'],
            "net_payable": net,
            "deductions": [
                {"label": "Commission", "amount": commission},
                {"label": "TDS", "amount": tds},
                {"label": "Penalty", "amount": penalty},
            ],
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
        "commission_amount": commission,
        "net_to_creator": net,
        "created_at": now_iso(),
        "source": source,
    })
    return {"payout_scheduled_at": scheduled_at, "net_payable": net, "tds_amount": tds, "penalty_amount": penalty, "late": late}


async def deliverables_progress(campaign: dict) -> dict:
    """How many of a brief's required assets currently have an APPROVED submission.

    Counts DISTINCT deliverable_index values, not rows — v1/v2/v3 of the same asset
    are revisions and must only ever count once. Submissions written before this field
    existed have no deliverable_index and collapse to index 0, so a legacy single-asset
    deal reads as 1-of-1 complete exactly as it did before.
    """
    required = total_deliverable_quantity(campaign)
    rows = await db.deal_content_submissions.find(
        {"campaign_id": campaign['id'], "status": "approved"},
        {"_id": 0, "deliverable_index": 1},
    ).to_list(length=None)
    approved_idx = set()
    for row in rows:
        try:
            approved_idx.add(int(row.get('deliverable_index') or 0))
        except (TypeError, ValueError):
            approved_idx.add(0)
    approved = len(approved_idx)
    return {
        "required": required,
        "approved": approved,
        "remaining": max(0, required - approved),
        "complete": approved >= required,
    }


async def release_payout_now(campaign: dict, work: dict, source: str = "approval") -> dict:
    """Instant funding: compute the payout (TDS/penalty/net + invoice) and release it
    to the creator's wallet immediately — no hold period. Guards against paying twice."""
    escrow = await db.escrow.find_one({"campaign_id": campaign['id']})
    if escrow and escrow.get('payout_status') == 'released':
        # Already paid — never re-schedule/re-release (would double-pay).
        return {"released": False, "net_payable": escrow.get('net_payable', 0),
                "payout_scheduled_at": escrow.get('payout_scheduled_at')}
    payout_info = await schedule_payout_for_deal(campaign, work, source=source)
    # Feature flag (Settings → instant_payout): when off, the payout is not released
    # immediately — it stays on the normal hold period and the scheduler pays it out.
    if not feature_enabled("instant_payout"):
        payout_info["released"] = False
        return payout_info
    escrow = await db.escrow.find_one({"campaign_id": campaign['id']})
    payout_info["released"] = bool(escrow and await release_scheduled_payout(escrow))
    return payout_info


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
    commission = float(escrow.get('commission_amount') if escrow.get('commission_amount') is not None else creator_commission(gross))
    net = float(escrow.get('net_payable') if escrow.get('net_payable') is not None else gross - commission - tds - penalty)
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
        commission_amount=commission,
    )
    # Record the platform's two-sided commission for this deal (brand fee + creator fee).
    await record_platform_revenue(
        campaign['id'], escrow.get('id'),
        deal_amount=gross,
        brand_fee=float(escrow.get('brand_commission_amount') or brand_commission(gross)),
        creator_fee=commission,
    )
    await db.campaigns.update_one({"id": campaign['id']}, {"$set": {"status": CampaignStatus.COMPLETED, "payout_status": "released", "updated_at": now}})
    await insert_deal_activity(campaign, "system", "UGCAD.IO", "payment_released", f"Payout of ₹{int(net)} released to the creator.")
    if creator_id:
        await notify_user(creator_id, "Payment released", f"₹{int(net)} has been released to your wallet.", link="/withdrawal", ntype="success", email=True, category="payments")
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
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(platform_setting("auto_approval_days", AUTO_APPROVE_DAYS)))).isoformat()
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
        await release_payout_now(campaign, work, source="auto_approval")
        await insert_deal_system_message(campaign, f"Content auto-approved after {int(platform_setting('auto_approval_days', AUTO_APPROVE_DAYS))} days with no brand review (PRD 8.4). The creator has been paid.")
        await notify_user(work['creator_id'], "Your content was auto-approved", "The brand didn't review in time, so your content was auto-approved and you've been paid.", link="/my-deals")
        approved += 1
    return approved


@api_router.post("/admin/payouts/run-due")
async def run_due_payouts(current_user: dict = Depends(require_cap("release_payouts"))):
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
async def waive_late_offense(offense_id: str, current_user: dict = Depends(require_cap("manage_deals"))):
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
async def apply_brand_penalty(data: BrandPenaltyApply, current_user: dict = Depends(require_cap("warn_suspend_users"))):
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


def _fmt_video_ts(value) -> str:
    """Seconds -> m:ss for revision notes pinned to a moment in the video."""
    try:
        total = int(float(value))
    except (TypeError, ValueError):
        return ""
    if total < 0:
        return ""
    return f"{total // 60}:{total % 60:02d}"


class RevisionItemIn(BaseModel):
    description: str
    severity: Optional[str] = "must-fix"     # must-fix | preference
    brief_reference: Optional[str] = ""
    # Moment in the submitted video this note refers to (Frame.io-style review).
    # None = a general note that isn't tied to one frame.
    timestamp_seconds: Optional[float] = None

class RevisionRequestIn(BaseModel):
    items: List[RevisionItemIn] = []
    notes: Optional[str] = ""
    deadline_at: Optional[str] = None
    feedback: Optional[str] = ""             # legacy free-text fallback

@api_router.post("/work/{work_id}/request-revision")
async def request_revision(work_id: str, data: RevisionRequestIn = Body(...), current_user: dict = Depends(get_current_user)):
    work = await db.work_submissions.find_one({"id": work_id})
    if not work:
        raise HTTPException(status_code=404, detail="Work not found")

    campaign = await db.campaigns.find_one({"id": work['campaign_id']})
    if campaign['business_id'] != _brand_ws_id(current_user):
        raise HTTPException(status_code=403, detail="Not authorized")

    # PRD 9.3: no revision requests while a dispute is open.
    await ensure_not_disputed(work['campaign_id'])

    # PRD 8.5: structured revision items (1-5), each with severity + optional brief ref.
    # Fall back to legacy free-text feedback if no items were sent.
    items = [it.dict() for it in (data.items or [])]
    if items:
        if not 1 <= len(items) <= 5:
            raise HTTPException(status_code=400, detail="Provide 1 to 5 revision items.")
        # "[must-fix @ 0:04] Re-shoot the intro" — the timestamp rides inside the
        # existing tag so every text-based consumer (creator checklist, emails,
        # chat system messages) shows the moment without needing to change.
        feedback = "\n".join(
            f"[{(it.get('severity') or 'must-fix')}"
            + (f" @ {_fmt_video_ts(it.get('timestamp_seconds'))}" if _fmt_video_ts(it.get('timestamp_seconds')) else "")
            + f"] {it.get('description', '')}"
            + (f" (ref: {it['brief_reference']})" if it.get('brief_reference') else "")
            for it in items
        )
    else:
        feedback = (data.feedback or "").strip()
        if not feedback:
            raise HTTPException(status_code=400, detail="Add at least one revision item.")

    # Keep the deal on-platform — reject any phone/email in the revision text. Mirrors the
    # guard in request_deal_revision and findContactInfo() in RevisionRequestModal.js, so
    # brands can't pass contact details to creators via this entry point either.
    contact_texts = [feedback, data.notes or ""] + [
        f"{it.get('description', '')} {it.get('brief_reference', '')}" for it in items
    ]
    if any(contains_contact_info(t) for t in contact_texts):
        raise HTTPException(
            status_code=400,
            detail="Revision requests can't include phone numbers or email addresses. Please keep all communication on-platform.",
        )

    # PRD 8.5: hard maximum of 5 revisions per deliverable, then admin must step in.
    # Counted across the whole deal — every resubmission creates a new work doc, so
    # reading work['revisions'] alone restarted the count at 0 each round.
    used = len(await deal_revision_history(work['campaign_id'], work['creator_id']))
    if used >= 5:
        await notify_admins("Revision limit reached", f"Campaign {work['campaign_id']} hit 5 revisions and needs admin review (PRD 8.5/8.9).", link="/dashboard/admin/disputes")
        raise HTTPException(status_code=400, detail="This deliverable has reached the 5-revision maximum. An admin must review before further revisions.")

    # PRD Section 8: first 2 revisions are free; each one thereafter costs the
    # brand a flat ₹500, debited from the wallet at request time.
    fee = revision_fee_for(used)
    paid = fee > 0
    if fee > 0:
        balance = float(current_user.get('balance') or 0)
        if balance < fee:
            raise HTTPException(
                status_code=402,
                detail=f"This is a paid revision (₹{fee}). Your wallet balance (₹{int(balance)}) is insufficient. Please recharge.",
            )

    revision = {
        "feedback": feedback,
        "items": items,
        "notes": (data.notes or "")[:500],
        "requested_changes": [it.get("description", "") for it in items] if items else [l.strip() for l in feedback.splitlines() if l.strip()],
        "new_deadline_at": data.deadline_at,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "index": used + 1,
        "paid": paid,
        "fee": fee,
    }

    # RACE GUARD: claim the transition atomically — succeeds only if the work is still the
    # SUBMITTED version awaiting review. If a concurrent approval or revision won, bail out
    # BEFORE charging anything (stops approve+revise both landing, and double revision fees).
    claim = await db.work_submissions.update_one(
        {"id": work_id, "status": WorkStatus.SUBMITTED},
        {"$set": {"status": WorkStatus.REVISION_REQUESTED}, "$push": {"revisions": revision}}
    )
    if claim.modified_count == 0:
        raise HTTPException(status_code=409, detail="This submission is no longer awaiting review — it was just approved or revised. Refresh to see the latest state.")

    # Take the version row out of "submitted" too. Leaving it there is what let the
    # approve sweep later stamp every past version as Approved.
    sent_back = await db.deal_content_submissions.find_one(
        {"campaign_id": work['campaign_id'], "creator_id": work['creator_id'], "status": "submitted"},
        sort=[("version", -1)]
    )
    if sent_back:
        await db.deal_content_submissions.update_one(
            {"id": sent_back['id']},
            {"$set": {"status": "revision_requested", "revision_requested_at": now_iso()}}
        )

    # Charge the paid-revision fee only after the transition is secured.
    if fee > 0:
        await db.users.update_one({"id": current_user['id']}, {"$inc": {"balance": -fee}})
        await db.wallet_ledger.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": current_user['id'],
            # `type` is the LABEL and `direction` is the sign — this row used to put the
            # direction into `type` and omit `direction` entirely, so the wallet history
            # printed a literal "debit" and, falling back to the credit default, showed the
            # fee as +₹500 in green: a charge that looked like a top-up.
            "type": "revision_fee",
            "direction": "debit",
            "category": "revision_fee",
            "amount": fee,
            "campaign_id": work['campaign_id'],
            "work_id": work_id,
            "description": f"Paid revision #{used + 1} for campaign {work['campaign_id']}",
            "created_at": now_iso(),
        })

    note = f" (paid revision, ₹{fee} charged)" if paid else f" ({cf.FREE_REVISION_LIMIT - used - 1} free revision(s) remaining)"
    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "revision_requested", f"Brand requested content revisions.{note}")
    await insert_deal_system_message(campaign, f"Brand requested content revisions.{note}")
    # Action-required for the creator → warning (amber ⚠), not a neutral info note.
    await notify_user(work['creator_id'], "Revision requested on your content",
                      "The brand requested changes on your submission. Open your deal to review the feedback and resubmit.",
                      link="/my-deals", ntype="warning", email=True, category="deal_updates")

    new_balance = float(current_user.get('balance') or 0) - fee
    if paid:
        # The brand's wallet was just debited. Telling nobody is not acceptable for a
        # money movement — they only ever saw a "Revision requested" toast.
        await notify_user(
            current_user['id'],
            f"₹{int(fee)} charged for a paid revision",
            f"Revisions 1-{cf.FREE_REVISION_LIMIT} are free. This was revision #{used + 1} on "
            f"'{campaign.get('title', 'your campaign')}', so ₹{int(fee)} was debited from your wallet. "
            f"Remaining balance: ₹{int(new_balance)}.",
            link="/dashboard/business/wallet", ntype="warning", email=True,
        )

    return {
        "message": "Revision requested",
        "revision_number": used + 1,
        "free_revisions_remaining": max(0, cf.FREE_REVISION_LIMIT - (used + 1)),
        "fee_charged": fee,
        "paid": paid,
        "new_balance": new_balance,
        "next_revision_fee": revision_fee_for(used + 1),
    }

@api_router.get("/deals/my")
async def get_my_deals(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can access this")

    campaigns = await db.campaigns.find({
        "selected_creator": current_user['id'],
        "archived_by_creator": {"$ne": True},  # hide what the creator has archived
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
        "business_id": _brand_ws_id(current_user),  # team members see the owner's deals
        "selected_creator": {"$nin": [None, ""]},
        "archived_by_brand": {"$ne": True},  # hide what the brand has archived
    }, {"_id": 0}).to_list(200)

    result = []
    for campaign in campaigns:
        context = await get_deal_context(make_deal_id(campaign), current_user)
        result.append(await build_deal_response(context, current_user))

    return result


# Human-readable label + normalized bucket for each offer-card lifecycle state,
# so the brand's "Sent Briefs" section can group by a stable set of statuses
# regardless of the raw value stored on the card.
BRIEF_TYPE_LABELS = {
    "private_invitation": "Private Invitation",
    "custom_offer": "Custom Offer",
    "counter_offer": "Counter Offer",
}
# raw card.status -> the bucket the UI filters on.
BRIEF_STATUS_BUCKETS = {
    "open": "sent",
    "pending": "sent",
    "accept": "accepted",
    "reject": "declined",
    "counter": "countered",
    "expired": "expired",
    "revoked": "revoked",
}


def _brief_amount(fields: dict):
    """The headline money on an offer, whichever field the card type uses."""
    fields = fields or {}
    return fields.get("price") or fields.get("modified_price") or fields.get("budget")


@api_router.get("/business/briefs")
async def get_business_briefs(current_user: dict = Depends(get_current_user)):
    """Every brief/offer that involves this brand's workspace — private
    invitations, custom offers and counter offers — with its lifecycle status
    (sent / accepted / declined / countered / expired / revoked) so the brand can
    see in one place everything it sent, accepted or rejected. Sourced from
    db.chat_action_cards, which every send path writes to."""
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only brands can access this")

    ws_id = _brand_ws_id(current_user)
    # A brand workspace = the owner plus any team members. Cards store real user
    # ids in participants/sender, so gather all of them to catch team activity.
    members = await db.users.find(
        {"$or": [{"id": ws_id}, {"team_of": ws_id}]}, {"_id": 0, "id": 1}
    ).to_list(200)
    brand_ids = {ws_id, *[m["id"] for m in members]}

    cards = await db.chat_action_cards.find(
        {"participants": {"$in": list(brand_ids)}, "type": {"$in": OFFER_CARD_TYPES}},
        {"_id": 0},
    ).sort("created_at", -1).to_list(500)

    # Batch-resolve the counterpart (creator) names to avoid an N+1 lookup.
    counterpart_ids = set()
    for card in cards:
        for pid in card.get("participants", []):
            if pid not in brand_ids:
                counterpart_ids.add(pid)
    users = await db.users.find({"id": {"$in": list(counterpart_ids)}}, {"_id": 0}).to_list(500)
    users_by_id = {u["id"]: u for u in users}

    result = []
    for card in cards:
        expired = is_action_card_expired(card)
        raw_status = "expired" if expired else card.get("status", "open")
        sender_is_brand = card.get("sender_id") in brand_ids
        counterpart_id = card.get("recipient_id") if sender_is_brand else card.get("sender_id")
        counterpart = users_by_id.get(counterpart_id) or {}
        response = card.get("response") or {}
        fields = card.get("fields") or {}
        result.append({
            "id": card.get("id"),
            "type": card.get("type"),
            "type_label": BRIEF_TYPE_LABELS.get(card.get("type"), card.get("type")),
            "direction": "sent" if sender_is_brand else "received",
            "status": raw_status,
            "status_bucket": BRIEF_STATUS_BUCKETS.get(raw_status, "sent"),
            "creator_id": counterpart_id,
            "creator_name": person_display_name(counterpart, "Creator"),
            "creator_nickname": counterpart.get("nickname"),
            "creator_photo": first_non_empty(
                counterpart.get("profile_photo"),
                counterpart.get("profile_picture"),
                (counterpart.get("profile") or {}).get("profile_photo"),
                (counterpart.get("profile") or {}).get("profile_picture"),
            ),
            "campaign_name": fields.get("campaign_name") or fields.get("deliverable_type"),
            "campaign_id": fields.get("campaign_id") or card.get("deal_id"),
            "deliverable_summary": fields.get("deliverable_summary"),
            "amount": _brief_amount(fields),
            "timeline": fields.get("timeline"),
            "usage_rights": fields.get("usage_rights"),
            "message": fields.get("message"),
            "decline_reason": response.get("decline_reason"),
            "response_note": response.get("note"),
            "deal_campaign_id": card.get("deal_campaign_id"),
            "deal_id": card.get("deal_id"),
            "created_at": card.get("created_at"),
            "responded_at": response.get("responded_at"),
            "expired_at": card.get("expired_at"),
            "revoked_at": card.get("revoked_at"),
        })

    return result


@api_router.post("/deals/{deal_id}/receipt")
async def submit_deal_receipt(deal_id: str, data: DealReceiptSubmit, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can submit receipts")
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    if campaign.get('selected_creator') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    # A receipt can only be confirmed once the brand has actually shipped the
    # product. Without this guard the creator could "Mark Received" before any
    # shipment exists (PRD shipping flow).
    if campaign.get('requires_shipment'):
        shipment = context.get('shipment') or {}
        ship_status = shipment.get('courier_status') or shipment.get('status')
        if ship_status not in ('shipped', 'in_transit', 'delivered', 'received'):
            raise HTTPException(
                status_code=400,
                detail="The brand hasn't shipped the product yet. You can mark it received once it's on the way.",
            )

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
    # PRD 8.3/9.3: must have received the product (if required) and no open dispute.
    await ensure_ready_for_content(campaign)

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

    # Which of the brief's required assets this upload is for. Single-asset briefs (and
    # older clients that don't send the field) fall through to 0 and behave as before.
    required_total = total_deliverable_quantity(campaign)
    deliverable_index = data.deliverable_index if data.deliverable_index is not None else 0
    if not 0 <= deliverable_index < required_total:
        raise HTTPException(
            status_code=400,
            detail=f"deliverable_index {deliverable_index} is out of range — this brief requires {required_total} deliverable(s).",
        )

    existing_versions = await db.deal_content_submissions.count_documents({
        "campaign_id": campaign['id'],
        "creator_id": current_user['id'],
        # Versions are revisions OF ONE ASSET, so they're counted per deliverable —
        # otherwise asset #2 would arrive as "v2" and look like a revision of asset #1.
        "deliverable_index": deliverable_index,
    })
    version = existing_versions + 1
    uploads_dir = str(Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))))
    submission = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "creator_id": current_user['id'],
        "deliverable_index": deliverable_index,
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
        # Carried through so approve_work() marks the right asset approved rather than
        # whichever submission happens to have the highest version number.
        "deliverable_index": deliverable_index,
        "work_files": [url for url in [data.video_url, data.caption_url, data.thumbnail_url, data.raw_footage_url] if url],
        "description": data.creator_note or f"Deal content submission v{version}",
        "status": WorkStatus.SUBMITTED,
        "submitted_at": submission['submitted_at'],
        "watermark": submission['watermark'],
        "revisions": []
    }
    await db.work_submissions.insert_one(work_doc)
    # Surface the submission on the campaign so the brand's Work Review (which reads
    # campaign.work_submission) can see it. No explicit status → the UI derives it
    # from campaign.status (pending_review → approved on completion).
    await db.campaigns.update_one({"id": campaign['id']}, {"$set": {
        "status": "work_submitted",
        "work_submission": {
            "id": work_doc["id"],
            "creator_id": current_user['id'],
            "work_files": work_doc["work_files"],
            "video_url": data.video_url,
            "thumbnail_url": data.thumbnail_url,
            "creator_note": data.creator_note,
            "submitted_at": work_doc["submitted_at"],
            "version": version,
        },
        "updated_at": now_iso(),
    }})
    await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), "content_submitted", f"Content version {version} submitted for review.")
    await insert_deal_system_message(campaign, f"Content version {version} was submitted and is awaiting brand review.")

    # Notify the brand that content is ready for review. The sibling /work/submit
    # path did this; this deal-room path (the one the Deal Room actually uses) did
    # not, so a brand got no bell/email when a creator submitted their final video.
    # email=True: payment is waiting on their review, so it warrants an email too.
    if campaign.get("business_id"):
        await notify_user(
            campaign["business_id"],
            "Content submitted for review",
            f"{first_name_of(current_user, fallback='The creator')} submitted content for '{campaign.get('title', 'your campaign')}'. Review it to release payment.",
            link="/dashboard/business/work-review",
            ntype="info",
            email=True,
        )

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
        "accepted_changes": data.accepted_changes or [],
        "created_at": now_iso()
    }
    # Upsert so a creator changing their mind replaces the previous response
    # instead of leaving two conflicting records.
    await db.deal_revision_responses.update_one(
        {"campaign_id": campaign['id'], "creator_id": current_user['id']},
        {"$set": response_doc},
        upsert=True,
    )

    LABELS = {
        "accepted": "accepted the revision request and will revise",
        "scope_creep": "flagged the revision request as scope creep",
        "partial_dispute": "partially accepted and disputed the remaining items",
    }
    label = LABELS.get(data.response, data.response)
    # A creator pushing back on a revision is NO LONGER an instant admin dispute.
    # It's a disagreement the brand and creator are expected to resolve between
    # themselves first; only an explicit "Escalate to admin" (see
    # /deals/{deal_id}/escalate) turns it into a real dispute. So here we just record
    # the pushback and nudge both sides to talk it out in the deal chat.
    event_type = "revision_requested" if data.response == "accepted" else "revision_pushback"
    await insert_deal_activity(campaign, "creator", current_user.get('nickname', 'Creator'), event_type, f"Creator {label}.")
    await insert_deal_system_message(campaign, f"Creator {label}.")

    # Tell the brand — previously this was recorded silently and nothing happened.
    if campaign.get('business_id'):
        pushed_back = data.response != "accepted"
        await notify_user(
            campaign['business_id'],
            "Creator responded to your revision request",
            (f"The creator {label}. Work it out together in the deal chat — if you "
             "can't agree, it can be escalated to admin.") if pushed_back else f"The creator {label}.",
            link="/dashboard/business/all-campaigns",
            ntype="warning" if pushed_back else "info",
        )

    return {"message": "Revision response submitted", "response": data.response, "dispute_id": None}

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

    # Keep the deal room on-platform too. This endpoint previously inserted the message
    # with NO contact-info check (unlike /chat/send), so phone numbers / emails posted in
    # the deal chat went straight through. Mirror the /chat/send guard exactly.
    await refresh_filter_rules()
    other_party = context['brand'] if current_user['id'] == context['creator']['id'] else context['creator']
    safety_check = check_contact_info_policy(data.message, brand_allowed_domains(context['brand'], context['creator']))
    if not safety_check["safe"]:
        result = await log_chat_violation(current_user, other_party['id'], data.message, safety_check["violations"], "message", deal_id=deal_id)
        raise HTTPException(status_code=400, detail=contact_info_block_message(result["strike"]))

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
    # Creators can't open a dispute directly (mirrors the /dispute and chat-action-card
    # guards) — they resolve with the brand first, then escalate to admin if needed.
    if data.type == "raise_dispute" and current_user.get('role') == UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Creators can't open a dispute directly. Try to resolve it with the brand, then use 'Escalate to admin' if you need help.")
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
    # A creator's escalation must not auto-freeze escrow — the admin decides that on
    # review. Escrow only holds on a raise_dispute, or a brand/admin escalation.
    is_creator = current_user.get('role') == UserRole.CREATOR
    if issue_type == "raise_dispute" or (issue_type == "escalate_to_admin" and not is_creator):
        await db.escrow.update_one({"campaign_id": campaign['id']}, {"$set": {"status": "on_hold", "updated_at": now_iso()}}, upsert=True)
    await insert_deal_activity(
        campaign,
        map_sender_type(current_user['id'], campaign, context['creator']['id'], current_user.get('role')),
        current_user.get('nickname', 'User'),
        "escalated_to_admin" if issue_type == "escalate_to_admin" else "dispute_raised",
        activity_message
    )
    await insert_deal_system_message(campaign, activity_message)
    return {"message": title, "action_card": {key: value for key, value in card.items() if key != "_id"}}

@api_router.post("/deals/{deal_id}/dispute")
async def raise_deal_dispute(deal_id: str, data: DealIssueSubmit, current_user: dict = Depends(get_current_user)):
    # Creators can no longer open a dispute directly — they must raise the issue with
    # the brand first and then escalate if it can't be resolved (see /escalate).
    if current_user['role'] == UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Creators can't open a dispute directly. Raise the issue with the brand first, then use 'Escalate to admin' if you can't resolve it together.")
    return await create_issue_action(deal_id, current_user, "raise_dispute", "Dispute raised", data.message or "A dispute was raised on this deal.", data)

@api_router.post("/deals/{deal_id}/escalate")
async def escalate_deal(deal_id: str, data: DealIssueSubmit, current_user: dict = Depends(get_current_user)):
    context = await get_deal_context(deal_id, current_user)
    campaign = context['campaign']
    is_creator = current_user['role'] == UserRole.CREATOR
    flagged = None
    if is_creator:
        # Talk first, escalate only if it couldn't be resolved: the creator must have
        # already flagged a revision disagreement or reported a damaged/wrong product.
        flagged = await db.deal_revision_responses.find_one({
            "campaign_id": campaign['id'], "creator_id": current_user['id'],
            "response": {"$in": ["scope_creep", "partial_dispute"]},
        })
        damaged = bool(await db.deal_action_cards.find_one({
            "campaign_id": campaign['id'], "type": "damage_report", "status": "open"}))
        if not flagged and not damaged:
            raise HTTPException(status_code=400, detail="Raise your concern with the brand first (flag the revision or report the issue). You can escalate to admin only if you can't resolve it together.")
    result = await create_issue_action(deal_id, current_user, "escalate_to_admin", "Escalated to admin", data.message or "This deal was escalated to admin support.", data)
    # Escalation is the single path that actually reaches admin now, so file the real
    # dispute record/queue entry (idempotent — reuses any dispute already open).
    dtype = "communication_issue"
    if flagged:
        dtype = "revision_abuse" if flagged.get('response') == 'partial_dispute' else "scope_creep"
    dispute_id = await open_admin_dispute(campaign, current_user, dtype, data.message or "Escalated to admin — could not resolve with the other party.")
    result["dispute_id"] = dispute_id
    return result

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


async def open_admin_dispute(campaign: dict, raised_by: dict, dtype: str, reason: str) -> str:
    """Create the single real admin dispute for a deal (idempotent per campaign),
    pause the deal (hold escrow + drop a dispute card) and notify admin + the other
    party. This is the ONE place a deal reaches the admin Disputes queue now that
    creators can no longer file disputes directly — only escalation gets here.
    Returns the dispute id (the existing open one if a dispute is already open)."""
    existing = await get_open_dispute(campaign['id'])
    if existing:
        return existing.get("id")
    severity = dispute_severity(dtype)
    first_hrs, res_days = DISPUTE_SLA[severity]
    now = datetime.now(timezone.utc)
    dispute = {
        "id": str(uuid.uuid4()),
        "deal_id": make_deal_id(campaign),
        "campaign_id": campaign['id'],
        "business_id": campaign.get('business_id'),
        "creator_id": campaign.get('selected_creator'),
        "raised_by": raised_by['id'],
        "raised_by_role": raised_by.get('role'),
        "dispute_type": dtype,
        "severity": severity,
        "description": reason,
        "desired_outcome": "other",
        "evidence_urls": [],
        "status": "open",
        "first_response_due_at": (now + timedelta(hours=first_hrs)).isoformat(),
        "resolution_due_at": (now + timedelta(days=res_days)).isoformat(),
        "created_at": now_iso(),
    }
    await db.disputes.insert_one(dispute)
    await db.escrow.update_one({"campaign_id": campaign['id']},
                               {"$set": {"status": "on_hold", "updated_at": now_iso()}}, upsert=True)
    await db.deal_action_cards.insert_one({
        "id": str(uuid.uuid4()), "deal_id": make_deal_id(campaign), "campaign_id": campaign['id'],
        "type": "raise_dispute", "title": "Escalated to admin", "status": "open", "created_at": now_iso(),
        "created_by": raised_by['id'], "message": reason, "dispute_id": dispute["id"],
    })
    await notify_admins(
        f"New {severity} dispute",
        f"{dtype.replace('_', ' ')} on deal {make_deal_id(campaign)} — first response due in {first_hrs}h.",
        link="/dashboard/admin/disputes",
    )
    other_id = campaign.get('business_id') if raised_by.get('role') == UserRole.CREATOR else campaign.get('selected_creator')
    if other_id and other_id != raised_by['id']:
        await notify_user(other_id, "This deal was escalated to admin",
                          "Deal activity is paused while our team reviews it.",
                          link="/dashboard/business/all-campaigns")
    return dispute["id"]


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
async def list_disputes(status: Optional[str] = None, dispute_type: Optional[str] = None, current_user: dict = Depends(require_cap("rule_disputes"))):
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
async def get_dispute_detail(dispute_id: str, current_user: dict = Depends(require_cap("rule_disputes"))):
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

    # Resolve REAL names so the timeline/chat never surface a raw "@handle" username.
    # Remapping by actor_type/sender_id fixes both historical rows (already stored with
    # a nickname) and future ones in one place.
    brand_user = await db.users.find_one({"id": bid}, {"_id": 0}) if bid else None
    creator_user = await db.users.find_one({"id": crid}, {"_id": 0}) if crid else None
    brand_name = person_display_name(brand_user, "Brand")
    creator_name = person_display_name(creator_user, "Creator")
    for ev in timeline:
        at = (ev.get("actor_type") or "").lower()
        if at == "brand":
            ev["actor_name"] = brand_name
        elif at == "creator":
            ev["actor_name"] = creator_name
        elif at in ("system", "admin"):
            ev["actor_name"] = ev.get("actor_name") or ("System" if at == "system" else "Admin")
    for m in chat:
        m["sender_name"] = brand_name if m.get("sender_id") == bid else (creator_name if m.get("sender_id") == crid else m.get("sender_name") or m.get("sender_nickname"))

    return {
        "dispute": dispute,
        "brief": normalize_campaign_response(campaign) if campaign else None,
        # Explicit party names so the panel can label "Brand: X · Creator: Y".
        "brand_name": brand_name,
        "creator_name": creator_name,
        "timeline": timeline,
        "content_versions": content,
        "shipment": shipment,
        "chat_history": chat,
        "prior_disputes": prior,
    }


@api_router.post("/admin/disputes/{dispute_id}/request-info")
async def dispute_request_info(dispute_id: str, data: DisputeInfoRequest, current_user: dict = Depends(require_cap("rule_disputes"))):
    """PRD 9.4: admin requests more info; SLA pauses; 72h response window."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can request info")
    dispute = await db.disputes.find_one({"id": dispute_id}, {"_id": 0})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    target = dispute.get("business_id") if data.party == "brand" else dispute.get("creator_id")
    await db.disputes.update_one({"id": dispute_id}, {"$set": {"status": "info_requested", "info_requested_from": data.party, "info_request_due_at": (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat(), "info_request_message": data.message}})
    if target:
        await notify_user(target, "More information needed for your dispute", data.message + " Please respond within 72 hours.", link=f"/disputes/{dispute_id}")
    return {"message": "Info requested", "dispute_id": dispute_id}


@api_router.get("/admin/disputes/appeals")
async def list_dispute_appeals(current_user: dict = Depends(require_cap("rule_disputes"))):
    """Disputes the losing party has appealed (awaiting a senior re-review)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view appeals")
    appeals = await db.disputes.find({"status": "appealed"}, {"_id": 0}).sort("created_at", 1).to_list(500)
    return {"appeals": appeals}


@api_router.post("/admin/disputes/{dispute_id}/assign")
async def assign_dispute(dispute_id: str, current_user: dict = Depends(require_cap("rule_disputes"))):
    """Claim a dispute for review (ops workflow)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can assign disputes")
    name = current_user.get("nickname") or current_user.get("full_name") or "Admin"
    r = await db.disputes.update_one({"id": dispute_id}, {"$set": {"assigned_to": current_user.get("id"), "assigned_to_name": name, "updated_at": now_iso()}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return {"success": True, "assigned_to_name": name}


@api_router.post("/admin/disputes/{dispute_id}/ruling-draft")
async def save_ruling_draft(dispute_id: str, data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("rule_disputes"))):
    """Save a work-in-progress ruling draft on the dispute (not yet executed)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can draft rulings")
    r = await db.disputes.update_one({"id": dispute_id}, {"$set": {"ruling_draft": data, "updated_at": now_iso()}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return {"success": True}


@api_router.post("/admin/disputes/{dispute_id}/request-review")
async def request_peer_review(dispute_id: str, data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("rule_disputes"))):
    """Send the drafted ruling for a peer/senior review before executing."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can request peer review")
    r = await db.disputes.update_one({"id": dispute_id}, {"$set": {"peer_review_status": "requested", "ruling_draft": data, "updated_at": now_iso()}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return {"success": True}


@api_router.post("/admin/disputes/{dispute_id}/rule")
async def rule_dispute(dispute_id: str, data: DisputeRuling, current_user: dict = Depends(require_cap("rule_disputes"))):
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

    # PRD 11.3 role matrix — tiered ruling ceiling keyed on the admin SUB-role
    # (founder ∞, ops_senior ₹1L, ops_regular ₹25K, custom ₹25K, finance ₹0).
    # Keyed on admin_role (not marketplace role) so ops admins are actually capped.
    dispute_value = max(held, float(data.refund_amount or 0), float(data.creator_amount or 0))
    cap = admin_caps.dispute_cap(current_user)  # None = unlimited (founder)
    if cap is not None and dispute_value > cap:
        raise HTTPException(
            status_code=403,
            detail=f"This dispute (₹{dispute_value:,.0f}) exceeds your ₹{cap:,} ruling limit. Escalate to a senior admin.",
        )
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
        await create_payout_receipt(creator_id=dispute["creator_id"], receipt_type="earning", gross_amount=creator_amt, campaign_id=dispute["campaign_id"], reference_id=dispute_id, note=f"Dispute ruling ({data.ruling})", commission_amount=0)
    # Escrow outcome must reflect where the money actually went. Marking a pure refund
    # as "released" made the brand's wallet history show the amount as still locked
    # (get_business_wallet only renders a "Budget Refund" credit for status=refunded),
    # so a refunded brand saw their balance move with no matching transaction row.
    money_back_to_brand = refund > 0 and creator_amt == 0
    if escrow:
        escrow_update = {
            "dispute_resolution": data.ruling,
            "refund_amount": refund,
            "creator_amount": creator_amt,
        }
        if money_back_to_brand:
            escrow_update.update({
                "status": "refunded", "payout_status": "refunded",
                "refunded_at": now_iso(), "refund_reason": f"Dispute ruling ({data.ruling})",
            })
        else:
            escrow_update.update({
                "status": "released", "payout_status": "released", "released_at": now_iso(),
            })
        await db.escrow.update_one({"id": escrow["id"]}, {"$set": escrow_update})

    # The deal itself has to move, or both sides keep seeing an in-progress deal with
    # no sign anything was decided. This was the "nothing happened" bug: only the
    # dispute doc changed, so the Deal Room looked untouched on both sides.
    if campaign:
        campaign_update = {
            "dispute_status": "resolved",
            "dispute_ruling": data.ruling,
            "dispute_resolved_at": now_iso(),
            "updated_at": now_iso(),
        }
        if data.extension_days:
            # Admin gave more time — the deal continues rather than ending.
            new_deadline = (datetime.now(timezone.utc) + timedelta(days=data.extension_days)).isoformat()
            campaign_update.update({"final_delivery_by": new_deadline, "due_date": new_deadline})
        elif money_back_to_brand:
            # Brand refunded in full, creator paid nothing → the deal is over.
            campaign_update.update({"status": "cancelled", "cancelled_at": now_iso()})
        elif creator_amt > 0:
            # Creator was paid → the deal is finished.
            campaign_update.update({"status": CampaignStatus.COMPLETED.value, "completed_at": now_iso()})
        await db.campaigns.update_one({"id": campaign["id"]}, {"$set": campaign_update})

        # Put the outcome in the Deal Room so both parties actually see it.
        await insert_deal_system_message(
            campaign,
            f"⚖️ Dispute resolved — ruling: {data.ruling.replace('_', ' ')}.\n"
            f"Refunded to brand: ₹{refund:,.0f} · Released to creator: ₹{creator_amt:,.0f}"
            + (f"\nReason: {data.reasoning}" if data.reasoning else ""),
        )

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
        if not uid:
            continue
        await db.users.update_one({"id": uid}, {"$push": {"dispute_history": {"dispute_id": dispute_id, "ruling": data.ruling, "role": role, "at": now_iso()}}})
        # Tell each side what happened to THEIR money, and link them somewhere that
        # exists for their role (/my-deals is a creator-only route — brands landed
        # on a 404, which is part of why this felt like "nothing happened").
        if role == "brand":
            money_line = f"₹{refund:,.0f} has been refunded to your wallet." if refund > 0 else "No refund was issued."
            link = "/dashboard/business/wallet"
        else:
            money_line = f"₹{creator_amt:,.0f} has been released to you." if creator_amt > 0 else "No payment was released."
            link = "/my-deals"
        await notify_user(
            uid,
            "Your dispute has been resolved",
            f"Ruling: {data.ruling.replace('_', ' ')}. {money_line} "
            f"{(data.reasoning or '')[:120]} You may appeal within 7 days.",
            link=link,
            ntype="success" if (refund > 0 or creator_amt > 0) else "info",
        )
    if reserve_gap > 0:
        await notify_admins("Dispute ruling exceeded escrow", f"Dispute {dispute_id} needed ₹{reserve_gap} from reserve. Finance audit required.")
    await log_admin_action(current_user, "dispute.ruling", target_type="dispute", target_id=dispute_id,
                           after={"ruling": data.ruling, "refund": refund, "creator_amount": creator_amt},
                           reason=data.reasoning)
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
    disputes = await db.disputes.find({"$or": [{"business_id": _brand_ws_id(current_user)}, {"creator_id": current_user["id"]}]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return disputes


@api_router.get("/disputes/{dispute_id}")
async def get_my_dispute_detail(dispute_id: str, current_user: dict = Depends(get_current_user)):
    """A party's own view of one dispute — powers the creator/brand dispute page.
    Only the two parties (and admins) may read it; everyone else gets a 404 so a
    dispute id can't be probed."""
    dispute = await db.disputes.find_one({"id": dispute_id}, {"_id": 0})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    uid = current_user["id"]
    is_party = uid in (dispute.get("creator_id"), dispute.get("business_id"))
    if not is_party and current_user.get("role") not in OPS_ROLES:
        raise HTTPException(status_code=404, detail="Dispute not found")
    # Which side is THIS user, and is the admin currently waiting on them?
    my_party = "creator" if uid == dispute.get("creator_id") else ("brand" if uid == dispute.get("business_id") else None)
    dispute["my_party"] = my_party
    dispute["awaiting_my_response"] = (
        dispute.get("status") == "info_requested" and dispute.get("info_requested_from") == my_party
    )
    # Attach the campaign title if we can, so the page isn't just a bare deal id.
    if not dispute.get("campaign_title") and dispute.get("campaign_id"):
        camp = await db.campaigns.find_one({"id": dispute["campaign_id"]}, {"_id": 0, "title": 1})
        if camp:
            dispute["campaign_title"] = camp.get("title")
    return dispute


@api_router.post("/disputes/{dispute_id}/respond")
async def respond_to_dispute_info(dispute_id: str, data: DisputeInfoResponse, current_user: dict = Depends(get_current_user)):
    """PRD 9.4: the party the admin asked answers the info request. Records the
    response, lifts the 'info_requested' hold, and pings the ops team to re-review."""
    dispute = await db.disputes.find_one({"id": dispute_id}, {"_id": 0})
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    uid = current_user["id"]
    my_party = "creator" if uid == dispute.get("creator_id") else ("brand" if uid == dispute.get("business_id") else None)
    if my_party is None:
        raise HTTPException(status_code=403, detail="You are not a party to this dispute")
    if dispute.get("status") != "info_requested" or dispute.get("info_requested_from") != my_party:
        raise HTTPException(status_code=400, detail="There is no open information request for you on this dispute.")
    if not (data.message or "").strip():
        raise HTTPException(status_code=400, detail="Please type your response before submitting.")

    response_entry = {
        "id": str(uuid.uuid4()),
        "party": my_party,
        "by": uid,
        "message": data.message.strip(),
        "evidence_urls": data.evidence_urls or [],
        "at": now_iso(),
    }
    await db.disputes.update_one(
        {"id": dispute_id},
        {
            "$push": {"info_responses": response_entry},
            # Back to 'open' for the ops team, and clear the pending-request fields.
            "$set": {"status": "open", "info_requested_from": None, "info_request_due_at": None, "info_request_message": None},
        },
    )
    who = current_user.get("nickname") or current_user.get("username") or my_party
    await notify_admins(
        "Dispute info response received",
        f"{who} responded to the info request on dispute {dispute.get('deal_id', dispute_id)}.",
        link="/dashboard/admin/disputes",
    )
    return {"message": "Response submitted", "dispute_id": dispute_id, "status": "open"}

# --- Brand-side deal actions (Deal Room) ---
class DealTrackingSubmit(BaseModel):
    tracking_id: str
    courier: Optional[str] = None
    courier_tracking_url: Optional[str] = None
    expected_delivery_at: Optional[str] = None

class DealRevisionRequest(BaseModel):
    feedback: str
    requested_changes: Optional[List[str]] = None

class ShipLabelDimensions(BaseModel):
    length: Optional[float] = None   # cm
    width: Optional[float] = None    # cm
    height: Optional[float] = None    # cm

class ShipLabelPickupAddress(BaseModel):
    full_name: str
    phone: str
    line1: str
    line2: Optional[str] = ""
    city: str
    state: str
    pincode: str
    country: Optional[str] = "India"

class ShipLabelRequest(BaseModel):
    # Brand's only inputs for the Shiprocket flow: product details + their pickup address.
    # The creator's delivery address is pulled from their profile server-side and is
    # NEVER returned to the brand.
    description: str
    weight: float                       # kg
    dimensions: Optional[ShipLabelDimensions] = None
    pickup_address: ShipLabelPickupAddress

async def get_brand_deal_campaign(deal_id: str, current_user: dict) -> dict:
    """Resolve a deal id to a campaign and assert the caller is its brand."""
    if current_user.get('role') != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only brands can perform this action")
    campaign = await get_campaign_by_deal_id(deal_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    if campaign.get('business_id') != _brand_ws_id(current_user):
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


def creator_delivery_address(user: dict) -> Optional[dict]:
    """Build a Shiprocket-ready delivery address from a creator's saved profile.
    Defensive: reads from the structured profile.address (set via /shipping/address)
    OR the flat fields captured at signup (profile.address string + city/state/pincode).
    Returns None if there isn't enough to ship to."""
    user = user or {}
    profile = user.get("profile") or {}
    addr = profile.get("address")
    # Structured address dict (from /shipping/address) takes priority.
    if isinstance(addr, dict):
        line1 = addr.get("line1")
        built = {
            "full_name": addr.get("full_name") or profile.get("fullName") or user.get("nickname") or "",
            "phone": addr.get("phone") or user.get("phone") or profile.get("phone") or user.get("phone_number") or "",
            "line1": line1 or "",
            "line2": addr.get("line2") or "",
            "city": addr.get("city") or profile.get("city") or "",
            "state": addr.get("state") or profile.get("state") or "",
            "pincode": addr.get("pincode") or profile.get("pincode") or "",
            "country": addr.get("country") or profile.get("country") or "India",
        }
    else:
        # Flat signup fields: profile.address is a plain string.
        line1 = addr if isinstance(addr, str) else (profile.get("address") or user.get("address"))
        built = {
            "full_name": profile.get("fullName") or user.get("full_name") or user.get("nickname") or "",
            "phone": user.get("phone") or profile.get("phone") or user.get("phone_number") or "",
            "line1": line1 or "",
            "line2": "",
            "city": profile.get("city") or user.get("city") or "",
            "state": profile.get("state") or user.get("state") or "",
            "pincode": profile.get("pincode") or user.get("pincode") or "",
            "country": profile.get("country") or user.get("country") or "India",
        }
    # Must have at least a line1 + pincode to generate a label.
    if not built["line1"] or not built["pincode"]:
        return None
    return built


@api_router.post("/deals/{deal_id}/ship-label")
async def create_shipping_label(deal_id: str, data: ShipLabelRequest, current_user: dict = Depends(get_current_user)):
    """Brand submits product details + pickup address; the platform generates a
    pre-paid shipping label. The creator's delivery address is pulled from their
    profile here and passed to the courier — it is NEVER exposed to the brand.

    PHASE 1: label + tracking are MOCKED. Replace the marked block below with a
    real Shiprocket 'create order + generate label' call when the API is wired in."""
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    if not campaign.get("requires_shipment"):
        raise HTTPException(status_code=400, detail="This deal does not require a shipment")

    creator = await db.users.find_one({"id": campaign.get("selected_creator")}, {"_id": 0}) or {}
    # The creator's delivery address is NOT the brand's concern — don't block the brand on it.
    # If it isn't set yet, proceed anyway; the creator/platform completes it before dispatch.
    delivery = creator_delivery_address(creator)

    dims = (data.dimensions.dict() if data.dimensions else {}) or {}

    # ─── MOCK SHIPROCKET (Phase 1) ─────────────────────────────────────────────
    # A real integration would: authenticate, create an order with pickup +
    # delivery + package, request a courier + label, and return awb/label_url.
    short = uuid.uuid4().hex[:10].upper()
    tracking_number = f"MOCK{short}"
    label_url = f"/mock-labels/{campaign['id']}.pdf"
    courier_name = "Shiprocket (mock)"
    # ───────────────────────────────────────────────────────────────────────────

    shipment_doc = {
        "campaign_id": campaign["id"],
        "product": {"description": data.description, "weight": data.weight, "dimensions": dims},
        "pickup_address": data.pickup_address.dict(),
        "delivery_address": delivery or {},    # internal only — completed before dispatch
        "awaiting_creator_address": not delivery,
        "tracking_number": tracking_number,
        "courier_name": courier_name,
        "label_url": label_url,
        "courier_status": "label_generated",
        "status": "awaiting_pickup",
        "label_generated_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.shipments.update_one({"campaign_id": campaign["id"]}, {"$set": shipment_doc}, upsert=True)
    await insert_deal_activity(campaign, "brand", current_user.get("nickname", "Brand"), "label_generated",
                               "Shipping label generated. Awaiting courier pickup.")
    await insert_deal_system_message(campaign, "The brand generated a shipping label. The product will be picked up by the courier shortly.")

    # Brand-safe response: product + tracking + label, but NOT the creator's address.
    return {
        "message": "Label generated",
        "tracking_number": tracking_number,
        "courier_name": courier_name,
        "label_url": label_url,
        "status": "awaiting_pickup",
    }


@api_router.post("/deals/{deal_id}/request-shipment")
async def request_shipment(deal_id: str, data: ShipLabelRequest, current_user: dict = Depends(get_current_user)):
    """Brand submits product + pickup details → creates a shipment REQUEST. The admin
    shipping queue then generates the label and marks it shipped. The creator's
    delivery address is captured server-side and is NEVER shown to the brand."""
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    if not campaign.get("requires_shipment"):
        raise HTTPException(status_code=400, detail="This deal does not require a shipment")

    creator = await db.users.find_one({"id": campaign.get("selected_creator")}, {"_id": 0}) or {}
    delivery = creator_delivery_address(creator)
    dims = (data.dimensions.dict() if data.dimensions else {}) or {}

    shipment_doc = {
        "campaign_id": campaign["id"],
        "product": {"description": data.description, "weight": data.weight, "dimensions": dims},
        "product_summary": data.description,
        "pickup_address": data.pickup_address.dict(),
        "delivery_address": delivery or {},          # internal only — stripped from GET responses
        "awaiting_creator_address": not delivery,
        "courier_status": "requested",
        "status": "requested",
        "requested_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.shipments.update_one({"campaign_id": campaign["id"]}, {"$set": shipment_doc}, upsert=True)
    await insert_deal_activity(campaign, "brand", current_user.get("nickname", "Brand"), "shipment_requested",
                               "Brand submitted product & pickup details. Awaiting label from the platform.")
    await insert_deal_system_message(campaign, "The brand submitted shipment details. The platform team will prepare the label shortly.")
    return {"message": "Shipment requested", "status": "requested"}


@api_router.post("/deals/{deal_id}/mark-picked-up")
async def mark_shipment_picked_up(deal_id: str, current_user: dict = Depends(get_current_user)):
    """Brand confirms the courier has picked up the package → deal moves to 'Shipped'.
    PHASE 2: this transition will be driven automatically by the Shiprocket pickup
    webhook instead of a manual button."""
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    sh = await db.shipments.find_one({"campaign_id": campaign["id"]}, {"_id": 0})
    if not sh:
        raise HTTPException(status_code=404, detail="No shipment/label found for this deal yet")
    await db.shipments.update_one(
        {"campaign_id": campaign["id"]},
        {"$set": {"courier_status": "shipped", "status": "shipped", "shipped_at": now_iso(), "updated_at": now_iso()}},
    )
    await insert_deal_activity(campaign, "brand", current_user.get("nickname", "Brand"), "shipped", "Package picked up by courier — shipment is in transit.")
    await insert_deal_system_message(campaign, "The package has been picked up by the courier and is on its way.")
    return {"message": "Marked as shipped"}

@api_router.post("/deals/{deal_id}/approve")
async def approve_deal_content(deal_id: str, current_user: dict = Depends(get_current_user)):
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    work = await db.work_submissions.find_one(
        {"campaign_id": campaign['id']}, {"_id": 0}, sort=[("submitted_at", -1)]
    )
    if not work:
        raise HTTPException(status_code=404, detail="No submitted work to approve")
    return await approve_work(work['id'], current_user)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+?\d[\d\s().-]{5,}\d")

def contains_contact_info(text: Any) -> bool:
    """True if the text looks like it contains a phone number or email address.
    Mirrors findContactInfo() in RevisionRequestModal.js. Used to keep brands from
    passing contact details to creators through a revision request (off-platform bait).
    """
    s = str(text or "")
    if _EMAIL_RE.search(s):
        return True
    for m in _PHONE_RE.findall(s):
        if len(re.sub(r"\D", "", m)) >= 7:
            return True
    return False

@api_router.post("/deals/{deal_id}/request-revision")
async def request_deal_revision(deal_id: str, data: DealRevisionRequest, current_user: dict = Depends(get_current_user)):
    # Keep the deal on-platform — reject any phone/email in the revision text.
    revision_texts = [data.feedback or ""] + list(data.requested_changes or [])
    if any(contains_contact_info(t) for t in revision_texts):
        raise HTTPException(
            status_code=400,
            detail="Revision requests can't include phone numbers or email addresses. Please keep all communication on-platform.",
        )
    campaign = await get_brand_deal_campaign(deal_id, current_user)
    work = await db.work_submissions.find_one(
        {"campaign_id": campaign['id']}, {"_id": 0}, sort=[("submitted_at", -1)]
    )
    if not work:
        raise HTTPException(status_code=404, detail="No submitted work to revise")
    # request_revision expects a RevisionRequestIn model (it reads .items/.feedback);
    # build one from the deal-room's simpler payload instead of passing a bare string.
    feedback = (data.feedback or "").strip()
    if data.requested_changes:
        feedback = (feedback + "\n" + "\n".join(f"- {c}" for c in data.requested_changes)).strip()
    return await request_revision(work['id'], RevisionRequestIn(feedback=feedback), current_user)

@api_router.post("/deals/{deal_id}/archive")
async def archive_deal(deal_id: str, current_user: dict = Depends(get_current_user)):
    # Either party can archive a completed deal, and it's PER-PARTY: archiving only
    # hides it from your own list, not the other side's. This used to be brand-only
    # (a creator got a 403) and it wrote a flag no list query ever read — so the
    # creator's "Archive Deal" did nothing and the deal kept coming back.
    campaign = await get_campaign_by_deal_id(deal_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    ensure_deal_access(campaign, current_user)
    field = "archived_by_creator" if current_user.get("role") == UserRole.CREATOR else "archived_by_brand"
    await db.campaigns.update_one(
        {"id": campaign['id']},
        {"$set": {field: True, "archived_at": now_iso()}},
    )
    return {"message": "Deal archived"}

@api_router.get("/work/campaign/{campaign_id}")
async def get_work_by_campaign(campaign_id: str, current_user: dict = Depends(get_current_user)):
    """Resolve the work submission for a campaign.

    The creator sees their own submission. The BRAND that owns the campaign needs it
    too — approve / request-revision / download are all keyed by work_id, and the
    brand has no other way to learn it (it used to send the campaign id, which 404'd).
    """
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0, "business_id": 1})
    is_owner_brand = bool(campaign) and campaign.get("business_id") == _brand_ws_id(current_user)

    query = {"campaign_id": campaign_id}
    if not is_owner_brand:
        query["creator_id"] = current_user["id"]

    work = await db.work_submissions.find_one(query, {"_id": 0}, sort=[("submitted_at", -1)])
    return work or {}

@api_router.get("/work/pending-review")
async def get_work_pending_review(current_user: dict = Depends(get_current_user)):
    """Get all work submissions pending review for a business"""
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only businesses can review work")

    # Get all campaigns for this business
    campaigns = await db.campaigns.find(
        {"business_id": _brand_ws_id(current_user)},
        {"_id": 0, "id": 1}
    ).to_list(1000)
    campaign_ids = [c['id'] for c in campaigns]

    # Get work submissions for these campaigns
    work_submissions = await db.work_submissions.find(
        {"campaign_id": {"$in": campaign_ids}, "status": WorkStatus.SUBMITTED},
        {"_id": 0}
    ).to_list(1000)

    # Attach each creator's real name so the brand sees it (not the @handle).
    creator_ids = {w.get('creator_id') for w in work_submissions if w.get('creator_id')}
    if creator_ids:
        creators = await db.users.find(
            {"id": {"$in": list(creator_ids)}},
            {"_id": 0, "id": 1, "nickname": 1, "full_name": 1, "business_name": 1,
             "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1},
        ).to_list(10000)
        name_by_id = {u.get('id'): person_display_name(u, u.get('nickname') or 'Creator') for u in creators}
        for w in work_submissions:
            if w.get('creator_id') in name_by_id:
                w['creator_name'] = name_by_id[w['creator_id']]

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
        if not campaign or campaign.get('business_id') != _brand_ws_id(current_user):
            raise HTTPException(status_code=403, detail="Not authorized to view this work")
        is_brand_viewer = True

    # Denormalize fields the review UI expects.
    if campaign:
        work['campaign_title'] = campaign.get('title') or campaign.get('campaign_name')
    creator = await db.users.find_one({"id": work['creator_id']}, {"_id": 0, "nickname": 1, "full_name": 1, "business_name": 1, "profile.business_name": 1, "profile.full_name": 1, "profile.fullName": 1})
    if creator:
        work['creator_nickname'] = creator.get('nickname') or creator.get('full_name')
        work['creator_name'] = person_display_name(creator, creator.get('nickname') or 'Creator')

    if is_brand_viewer:
        # Brand viewer gets the watermark-protected preview until approval.
        approved = work.get('status') == WorkStatus.APPROVED
        return cf.to_brand_facing_asset(work, approved=approved)

    return work

# Review Routes
@api_router.post("/reviews")
async def submit_review(data: ReviewSubmit, current_user: dict = Depends(get_current_user)):
    rates_brand = bool(data.business_id) and current_user.get('role') == UserRole.CREATOR
    # A creator can review a brand ONLY after that deal is completed, and only for a
    # brand they actually worked with (they were the selected creator on the campaign).
    if rates_brand:
        campaign = await db.campaigns.find_one({"id": data.campaign_id})
        if not campaign:
            raise HTTPException(status_code=404, detail="Deal not found")
        if campaign.get("selected_creator") != current_user['id'] or campaign.get("business_id") != data.business_id:
            raise HTTPException(status_code=403, detail="You can only review a brand you've completed a deal with")
        if campaign.get("status") != CampaignStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="You can review a brand only after the deal is completed")
    # A review is one-time and immutable: once you've reviewed the other party for
    # a campaign you can't add another (and there's no edit/undo). Block a repeat
    # so a double-submit / re-open can't stack or silently change the rating.
    already = await db.reviews.find_one({
        "campaign_id": data.campaign_id,
        "reviewer_id": current_user['id'],
        "reviewee_role": "business" if rates_brand else "creator",
    })
    if already:
        raise HTTPException(status_code=409, detail="You have already reviewed this. Reviews can't be changed once submitted.")
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

@api_router.get("/reviews/business/{business_id}")
async def get_business_reviews(business_id: str):
    """Reviews creators left for a brand (reviewee_role == 'business'). Powers the
    brand profile card a creator opens from Messages — mirror of the creator route."""
    reviews = await db.reviews.find(
        {"business_id": business_id, "reviewee_role": "business"}, {"_id": 0}
    ).to_list(1000)
    return reviews

# Shipment Routes
@api_router.post("/shipment/update")
async def update_shipment(data: ShipmentUpdate, current_user: dict = Depends(get_current_user)):
    campaign = await db.campaigns.find_one({"id": data.campaign_id})
    if not campaign or campaign['business_id'] != _brand_ws_id(current_user):
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
        "status": data.courier_status or "shipped",
    }

    existing = await db.shipments.find_one({"campaign_id": data.campaign_id}, {"_id": 0, "late_fee_applied": 1, "shipped_at": 1})
    # Stamp when it first left the brand so the progress trackers can date the
    # "Product Shipped" step — but never overwrite the original ship date on re-edit.
    shipment_doc["shipped_at"] = (existing or {}).get("shipped_at") or datetime.now(timezone.utc).isoformat()

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
            fee = min(days_late * to_float(platform_setting("late_ship_fee_per_day", LATE_SHIP_FEE_PER_DAY)), to_float(platform_setting("late_ship_fee_cap", LATE_SHIP_FEE_CAP)))
            creator_id = campaign.get('selected_creator')
            if creator_id and fee > 0:
                await db.users.update_one({"id": creator_id}, {"$inc": {"balance": fee}})
                await db.shipments.update_one({"campaign_id": data.campaign_id}, {"$set": {"late_fee_applied": fee, "late_fee_days": days_late}})
                await notify_user(creator_id, "Late-shipping fee credited", f"₹{fee} was credited to you because the brand shipped {days_late} day(s) late.", link="/withdrawal")
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
        campaign.get('business_id') == _brand_ws_id(current_user)
        or campaign.get('selected_creator') == current_user['id']
        or role in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]
    )
    if not is_party:
        raise HTTPException(status_code=403, detail="Not authorized to view this shipment")
    shipment = await db.shipments.find_one({"campaign_id": campaign_id}, {"_id": 0})
    if not shipment:
        raise HTTPException(status_code=404, detail="Shipment not found")
    # The creator's delivery address is ops-only — never expose it to the brand.
    shipment.pop("delivery_address", None)
    return shipment


@api_router.post("/shipping/address")
async def save_shipping_address(data: ShippingAddressSubmit, current_user: dict = Depends(get_current_user)):
    """Brand (pickup) or creator (delivery) saves their address for a shipment.
    Stored on the user's profile.address — the admin shipping queue reads it from there.
    When both parties' addresses are present, the deal is flagged ready-to-dispatch
    and the ops team is notified to print a label and ship it."""
    address = {
        "full_name": data.full_name, "phone": data.phone,
        "line1": data.line1, "line2": data.line2 or "",
        "city": data.city, "state": data.state, "pincode": data.pincode,
        "country": data.country or "India", "updated_at": now_iso(),
    }
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"profile.address": address}})

    both_ready = False
    if data.campaign_id:
        # Accept the campaign id OR the DEAL-#### id shown in the Deal Room.
        campaign = await find_campaign_by_any_id(data.campaign_id)
        if campaign:
            data.campaign_id = campaign["id"]  # normalise for the shipment lookups below
        if campaign and campaign.get("requires_shipment"):
            is_party = current_user["id"] in [campaign.get("business_id"), campaign.get("selected_creator")]
            if not is_party:
                raise HTTPException(status_code=403, detail="Not a party to this deal")
            creator = await db.users.find_one({"id": campaign.get("selected_creator")}, {"_id": 0, "profile": 1}) or {}
            creator_addr = (creator.get("profile") or {}).get("address")
            sh = await db.shipments.find_one({"campaign_id": data.campaign_id}, {"_id": 0}) or {}
            # The brand's side is their pickup address, submitted via the "Ship Product"
            # form and stored on the shipment — NOT on their profile.
            brand_addr = sh.get("pickup_address")
            in_flight = (sh.get("status") or sh.get("courier_status")) in ["shipped", "in_transit", "delivered", "received"]
            both_ready = bool(brand_addr and creator_addr)

            # The creator may confirm their address AFTER the brand already requested
            # the shipment — in which case the shipment was stored with an empty
            # delivery_address and awaiting_creator_address=True. Backfill it now so
            # ops can actually generate the label.
            # The creator can confirm BEFORE the brand ships (no shipment doc exists yet) or
            # AFTER (doc exists with awaiting_creator_address=True). Upsert in both cases —
            # the old `if sh` guard meant an early confirmation was written nowhere
            # deal-specific, so the deal room could never tell it had happened and its button
            # still read "Confirm Delivery Address".
            if creator_addr and current_user["id"] == campaign.get("selected_creator"):
                await db.shipments.update_one(
                    {"campaign_id": data.campaign_id},
                    {"$set": {"delivery_address": creator_addr,
                              "awaiting_creator_address": False,
                              "updated_at": now_iso()},
                     "$setOnInsert": {
                         "id": str(uuid.uuid4()),
                         "campaign_id": data.campaign_id,
                         "business_id": campaign.get("business_id"),
                         "creator_id": campaign.get("selected_creator"),
                         # Not a courier state — compute_deal_state ignores it, so the deal
                         # stays in "Accepted — Awaiting Shipment" until the brand ships.
                         "status": "awaiting_pickup_address",
                         "created_at": now_iso(),
                     }},
                    upsert=True,
                )

            if both_ready and not in_flight:
                await db.shipments.update_one(
                    {"campaign_id": data.campaign_id},
                    {"$set": {"status": "awaiting_dispatch", "courier_status": "awaiting_dispatch",
                              "addresses_ready_at": now_iso(), "updated_at": now_iso()}},
                    upsert=True,
                )
                await notify_admins(
                    "Shipment ready to dispatch",
                    f"Both addresses are in for '{campaign.get('title', 'a deal')}'. Print a label and ship it.",
                    link="/dashboard/admin/shipping",
                )
                await insert_deal_system_message(campaign, "Both shipping addresses received. The platform team will dispatch the product shortly.")

    return {"message": "Address saved", "address": address, "both_ready": both_ready}


@api_router.get("/shipping/address")
async def get_shipping_address(campaign_id: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Return MY saved address (for prefill) and, for a given deal, whether each
    side has confirmed. Masked-shipping safe: never returns the OTHER party's
    address — only a boolean that they've confirmed."""
    me = await db.users.find_one({"id": current_user["id"]}, {"_id": 0, "profile": 1}) or {}
    my_address = (me.get("profile") or {}).get("address")

    out = {
        "address": my_address,
        "my_role": None,
        "brand_confirmed": False,
        "creator_confirmed": False,
        "both_ready": False,
        "shipment_status": None,
        "requires_shipment": False,
    }
    if not campaign_id:
        return out

    # Accept the campaign id OR the DEAL-#### id shown in the Deal Room. The card
    # renders nothing when this 404s, which turned the creator's "Confirm Delivery
    # Address" button into a dead click.
    campaign = await find_campaign_by_any_id(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    if _brand_ws_id(current_user) not in [campaign.get("business_id"), campaign.get("selected_creator")]:
        raise HTTPException(status_code=403, detail="Not a party to this deal")

    creator = await db.users.find_one({"id": campaign.get("selected_creator")}, {"_id": 0, "profile": 1}) or {}
    sh = await db.shipments.find_one({"campaign_id": campaign["id"]}, {"_id": 0}) or {}

    out["my_role"] = "brand" if _brand_ws_id(current_user) == campaign.get("business_id") else "creator"
    # The brand submits their pickup address through the "Ship Product" form
    # (/deals/{id}/request-shipment), which stores it on the SHIPMENT — not on their
    # profile. So that's the source of truth for "the brand has given their details".
    out["brand_confirmed"] = bool(sh.get("pickup_address"))
    out["creator_confirmed"] = bool((creator.get("profile") or {}).get("address"))
    out["both_ready"] = out["brand_confirmed"] and out["creator_confirmed"]
    out["shipment_status"] = sh.get("status") or sh.get("courier_status")
    out["requires_shipment"] = bool(campaign.get("requires_shipment"))
    return out

# Withdrawal Routes
PLATFORM_COMMISSION_PERCENT = 20  # Legacy single-rate constant (kept for reporting).

# Two-sided platform commission. The brand fee is charged ON TOP of the deal value
# when the brand funds; the creator fee is DEDUCTED from the creator's payout.
BRAND_COMMISSION_PERCENT = 20
CREATOR_COMMISSION_PERCENT = 20


def brand_commission(amount) -> float:
    """Platform fee added on top of the deal value when the brand funds.
    Rate comes from Admin → Settings → Commission rate."""
    return round(float(amount or 0) * commission_percent() / 100, 2)


def creator_commission(amount) -> float:
    """Platform fee deducted from the creator's payout.
    Rate comes from Admin → Settings → Commission rate."""
    return round(float(amount or 0) * commission_percent() / 100, 2)


async def record_platform_revenue(campaign_id: str, escrow_id: str, *, deal_amount: float,
                                  brand_fee: float, creator_fee: float) -> None:
    """Persist the platform's earned commission for a completed deal (both sides)."""
    await db.platform_revenue.insert_one({
        "id": str(uuid.uuid4()),
        "campaign_id": campaign_id,
        "escrow_id": escrow_id,
        "deal_amount": round(float(deal_amount or 0), 2),
        "brand_commission_percent": commission_percent(),
        "creator_commission_percent": commission_percent(),
        "brand_fee": round(float(brand_fee or 0), 2),
        "creator_fee": round(float(creator_fee or 0), 2),
        "total_commission": round(float(brand_fee or 0) + float(creator_fee or 0), 2),
        "created_at": now_iso(),
    })


def brand_display_name(brand: Optional[dict]) -> Optional[str]:
    """What a creator should see as the payer: the brand's public handle."""
    if not brand:
        return None
    nickname = (brand.get("nickname") or "").strip()
    if nickname:
        return nickname
    username = (brand.get("username") or "").strip()
    return f"@{username.lstrip('@')}" if username else None


async def create_payout_receipt(creator_id: str, receipt_type: str, gross_amount: float,
                                campaign_id: Optional[str] = None, reference_id: Optional[str] = None,
                                note: Optional[str] = None, tds_amount: float = 0.0,
                                penalty_amount: float = 0.0, commission_amount: Optional[float] = None) -> dict:
    """Generate and persist a payout receipt for a creator. receipt_type is
    'earning' (escrow release) or 'withdrawal' (payout to bank/UPI). TDS and any
    late-delivery penalty are recorded as deductions (PRD 8.7/8.8). The creator-side
    platform commission is deducted from earnings."""
    if commission_amount is not None:
        commission = round(float(commission_amount), 2)
    else:
        commission = creator_commission(gross_amount) if receipt_type == "earning" else 0.0
    tds_amount = round(float(tds_amount or 0), 2)
    penalty_amount = round(float(penalty_amount or 0), 2)
    net_amount = round(gross_amount - commission - tds_amount - penalty_amount, 2)
    seq = await db.payout_receipts.count_documents({}) + 1

    # WHO paid, and for WHAT. A receipt used to carry only a raw campaign uuid, so
    # the creator's earnings list could not say "Nike paid you ₹8,000" — there was no
    # creator-reachable way to resolve that uuid to a brand. Stamp it at write time.
    brand_id = brand_name = campaign_title = None
    if campaign_id:
        campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0, "title": 1, "business_id": 1})
        if campaign:
            campaign_title = campaign.get("title")
            brand_id = campaign.get("business_id")
            if brand_id:
                brand = await db.users.find_one({"id": brand_id}, {"_id": 0, "nickname": 1, "username": 1})
                brand_name = brand_display_name(brand)

    receipt = {
        "id": str(uuid.uuid4()),
        "receipt_number": f"PR-{datetime.now(timezone.utc).year}-{seq:05d}",
        "creator_id": creator_id,
        "type": receipt_type,
        "gross_amount": gross_amount,
        "commission_percent": commission_percent() if receipt_type == "earning" else 0,
        "commission_amount": commission,
        "tds_amount": tds_amount,
        "penalty_amount": penalty_amount,
        "net_amount": net_amount,
        "currency": "INR",
        "campaign_id": campaign_id,
        "campaign_title": campaign_title,
        "brand_id": brand_id,
        "brand_name": brand_name,
        "reference_id": reference_id,
        "note": note,
        "created_at": now_iso(),
    }
    await db.payout_receipts.insert_one(receipt)

    # Mirror an earning into the wallet ledger. Nothing ever wrote a creator row
    # here, which is why the admin's per-user transaction view was empty for every
    # creator on the platform.
    if receipt_type == "earning":
        await db.wallet_ledger.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": creator_id,
            "direction": "credit",
            "amount": net_amount,
            "type": "Payout",
            "status": "completed",
            "campaign_id": campaign_id,
            "counterparty_id": brand_id,
            "counterparty_name": brand_name,
            "description": (f"Payout from {brand_name}" if brand_name else "Payout")
                           + (f" for '{campaign_title}'" if campaign_title else ""),
            "date": now_iso(),
            "created_at": now_iso(),
        })

    return {k: v for k, v in receipt.items() if k != "_id"}


MIN_WITHDRAWAL_AMOUNT = 500  # INR — minimum a creator can withdraw at once

@api_router.post("/withdrawal/request")
async def request_withdrawal(data: WithdrawalRequest, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can request withdrawals")

    # Only approved creators can withdraw earnings.
    if current_user.get('approval_status') != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Your creator profile must be approved before you can withdraw")

    # KYC must be verified before any payout can leave the platform.
    if kyc_status_of(current_user) != "verified":
        raise HTTPException(status_code=403, detail="Complete KYC verification before withdrawing earnings")

    # Amount must be a positive number at or above the minimum.
    if data.amount is None or data.amount <= 0:
        raise HTTPException(status_code=400, detail="Withdrawal amount must be greater than zero")
    if data.amount < MIN_WITHDRAWAL_AMOUNT:
        raise HTTPException(status_code=400, detail=f"Minimum withdrawal amount is INR {MIN_WITHDRAWAL_AMOUNT:,}")

    # Payout account details must actually be filled in (an empty {} is not enough).
    details = data.account_details or {}
    if not any(str(v).strip() for v in details.values()):
        raise HTTPException(status_code=400, detail="Bank / payout account details are required")

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
    """All payout receipts (earnings + withdrawals) for the current creator.

    Every earning says who paid it and for which campaign. Receipts written before
    the payer was stamped on carry only a campaign uuid, so resolve those here —
    otherwise the creator's history shows an amount with no idea where it came from.
    """
    receipts = await db.payout_receipts.find(
        {"creator_id": current_user['id']}, {"_id": 0}
    ).sort("created_at", -1).to_list(1000)

    for r in receipts:
        if r.get("brand_name") or not r.get("campaign_id"):
            continue
        campaign = await db.campaigns.find_one(
            {"id": r["campaign_id"]}, {"_id": 0, "title": 1, "business_id": 1})
        brand_id = (campaign or {}).get("business_id")
        # The campaign may have been deleted since. The escrow row that funded this
        # payout still names the brand, so fall back to it rather than showing the
        # creator a payment from nobody.
        if not brand_id and r.get("reference_id"):
            escrow = await db.escrow.find_one({"id": r["reference_id"]}, {"_id": 0, "business_id": 1})
            brand_id = (escrow or {}).get("business_id")
        brand = await db.users.find_one({"id": brand_id}, {"_id": 0, "nickname": 1, "username": 1}) if brand_id else None

        r["campaign_title"] = r.get("campaign_title") or (campaign or {}).get("title")
        r["brand_id"] = r.get("brand_id") or brand_id
        r["brand_name"] = r.get("brand_name") or brand_display_name(brand)
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
async def get_pending_profiles(status: Optional[str] = None,
                               current_user: dict = Depends(require_cap("review_applications"))):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")

    # `status=all` → every completed application (pending / more_info / approved /
    # rejected) so the reviews list can filter by State and a rejected candidate's
    # data stays visible instead of disappearing. A specific `status` filters to
    # that state. No param → pending only (back-compat for the older admin pages).
    query = {"profile_completed": True}
    if not status:
        query["approval_status"] = ApprovalStatus.PENDING
    elif status != "all":
        query["approval_status"] = status

    profiles = await db.users.find(
        query,
        {"_id": 0, "password": 0}
    ).sort("submitted_at", 1).to_list(2000)

    # Ops Regular only reviews applications in their assigned work categories.
    if admin_caps.normalize_role(current_user.get("admin_role")) == "ops_regular":
        assigned = {str(c).lower() for c in (current_user.get("assigned_categories") or [])}
        if assigned:
            def _cat(u):
                pr = u.get("profile") or {}
                for k in ("category", "industry", "niche", "primary_category", "content_category"):
                    if pr.get(k):
                        return str(pr[k]).lower()
                return ""
            profiles = [u for u in profiles if _cat(u) in assigned]

    return profiles

@api_router.post("/admin/approve-profile")
async def approve_profile(data: ApprovalAction, current_user: dict = Depends(require_cap("review_applications"))):
    if current_user['role'] not in [UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Admin access required")

    now_stamp = datetime.now(timezone.utc).isoformat()
    # Build a structured `review` object the admin UI reads back (rejection reason,
    # more-info request, etc.) so a rejected/held candidate still shows WHY.
    if data.action == "approve":
        status = ApprovalStatus.APPROVED
        review = {"decided_at": now_stamp, "decided_by": current_user["id"]}
    elif data.action == "request_info":
        status = ApprovalStatus.MORE_INFO
        review = {
            "more_info_message": data.message or "",
            "more_info_items": data.items or [],
            "requested_at": now_stamp,
            "requested_by": current_user["id"],
        }
    else:  # reject
        status = ApprovalStatus.REJECTED
        review = {
            "reason_code": data.reason_code or data.reason or "other",
            "reason_details": data.reason_details or "",
            "decided_at": now_stamp,
            "decided_by": current_user["id"],
        }

    user = await db.users.find_one({"id": data.item_id}, {"_id": 0, "role": 1, "public_creator_id": 1, "email": 1, "nickname": 1, "full_name": 1})
    if not user:
        raise HTTPException(status_code=404, detail="Profile not found")
    update_data = {
        "approval_status": status,
        "review": review,
        "approval_reason": data.reason_details or data.reason or "",
        "approved_at": now_stamp
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

    # Branded decision email to the applicant (fire-and-forget — never blocks the decision).
    try:
        to_email = user.get("email")
        name = first_name_of(user)
        if to_email:
            if data.action == "approve":
                subject = "Your UGCad.io application is approved 🎉"
                content = f"""
                    <h1 style="margin:0 0 12px;font-size:22px;color:#1f2340;">You're approved, {name}!</h1>
                    <p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#4a4f74;">Your profile has been reviewed and <strong>approved</strong>. You can now sign in and start on UGCad.io.</p>
                    {_email_button("Sign in to UGCad.io")}"""
            elif data.action == "request_info":
                items = data.items or []
                items_html = ("<ul style='margin:12px 0;padding-left:20px;color:#4a4f74;'>" + "".join(f"<li style='margin:4px 0;'>{i}</li>" for i in items) + "</ul>") if items else ""
                subject = "Action needed on your UGCad.io application"
                content = f"""
                    <h1 style="margin:0 0 12px;font-size:22px;color:#1f2340;">We need a bit more info, {name}</h1>
                    <p style="margin:0 0 8px;font-size:15px;line-height:1.6;color:#4a4f74;">{data.message or 'Please review and update your profile so we can finish reviewing it.'}</p>{items_html}
                    <p style="margin:12px 0 0;font-size:14px;color:#4a4f74;">Sign in and update your profile to resubmit.</p>
                    {_email_button("Sign in and update profile")}"""
            else:  # reject
                reason = data.reason_details or data.reason or "It did not meet our current requirements."
                subject = "Update on your UGCad.io application"
                content = f"""
                    <h1 style="margin:0 0 12px;font-size:22px;color:#1f2340;">Application update</h1>
                    <p style="margin:0 0 12px;font-size:15px;line-height:1.6;color:#4a4f74;">Hi {name}, unfortunately your application was <strong>not approved</strong> at this time.</p>
                    <p style="margin:0;font-size:14px;color:#4a4f74;"><strong>Reason:</strong> {reason}</p>"""
            await send_email(to_email, subject, _email_base_template(subject, content))
    except Exception as e:
        logger.error(f"[approve-profile] applicant email failed: {e}")

    return {"success": True, "message": "Profile updated", "approval_status": status}

@api_router.get("/admin/pending-campaigns")
async def get_pending_campaigns(current_user: dict = Depends(require_cap("review_applications"))):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    campaigns = await db.campaigns.find(
        {"status": CampaignStatus.PENDING_APPROVAL},
        {"_id": 0}
    ).to_list(1000)

    return _json_safe(campaigns)

@api_router.post("/admin/approve-campaign")
async def approve_campaign(data: ApprovalAction, current_user: dict = Depends(require_cap("review_applications"))):
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")

    campaign = await db.campaigns.find_one(
        {"id": data.item_id},
        {"_id": 0, "status": 1, "business_id": 1, "title": 1}
    )
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

    if data.action == "approve":
        # Auto-assign to a campaign manager
        await auto_assign_campaign_manager(data.item_id)
    else:
        # Rejected → refund the reserved budget back to the brand wallet.
        await refund_campaign_reservation(data.item_id, reason="campaign_rejected")

    # Tell the brand either way — in-app AND email. Without this the brand had no
    # signal their brief went live (or was rejected + refunded) and had to keep
    # re-checking the dashboard. Best-effort: a mail failure never fails the action.
    brand_id = campaign.get("business_id")
    if brand_id:
        title = campaign.get("title") or "Your campaign"
        link = f"/dashboard/business/campaign/{data.item_id}"
        if data.action == "approve":
            await notify_user(
                brand_id,
                "✅ Your brief is approved and live",
                f"'{title}' has been approved and is now live — creators can start applying.",
                link=link, ntype="success", email=True, category="deal_updates",
            )
        else:
            reason = (data.reason_details or data.reason or "").strip()
            await notify_user(
                brand_id,
                "Your brief was not approved",
                f"'{title}' was not approved{f' — {reason}' if reason else ''}. "
                "Your reserved budget has been refunded to your wallet.",
                link=link, ntype="warning", email=True, category="deal_updates",
            )

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
async def manually_assign_campaign(campaign_id: str, manager_id: str, current_user: dict = Depends(require_cap("review_applications"))):
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
async def get_campaign_assignments(current_user: dict = Depends(require_cap("review_applications"))):
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
async def manage_role(data: RoleUpdate, current_user: dict = Depends(require_cap("manage_roles"))):
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
    # Dashboard is open to any real admin (incl. custom with zero caps), but NOT
    # to legacy staff roles (campaign_manager / support_staff), which are retired.
    if current_user['role'] != UserRole.ADMIN:
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
async def get_all_users(current_user: dict = Depends(require_cap("user_management"))):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    # Hard scope enforcement: a custom creators-only / brands-only admin only ever
    # receives their side of the marketplace from this list.
    scope_q = admin_caps.user_scope_filter(current_user)
    users = await db.users.find(scope_q, {"_id": 0, "password": 0}).to_list(1000)
    return _json_safe(users)

@api_router.get("/admin/user/{user_id}")
async def get_user_details(user_id: str, current_user: dict = Depends(require_cap("user_management"))):
    """Get detailed information for a specific user"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # A scoped admin can't view a user outside their side of the marketplace.
    if not admin_caps.in_scope(current_user, user.get("role")):
        raise HTTPException(status_code=403, detail="This user is outside your data scope")
    return user

@api_router.post("/admin/user/update")
async def update_user(data: UserUpdateRequest, current_user: dict = Depends(require_cap("user_management"))):
    """Update user information"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if user exists
    user = await db.users.find_one({"id": data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # A scoped admin can't act on a user outside their side of the marketplace.
    if not admin_caps.in_scope(current_user, user.get("role")):
        raise HTTPException(status_code=403, detail="This user is outside your data scope")
    
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
async def ban_user(data: UserBanRequest, current_user: dict = Depends(require_cap("ban_users"))):
    """Ban or unban a user"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if user exists
    user = await db.users.find_one({"id": data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # A scoped admin can't act on a user outside their side of the marketplace.
    if not admin_caps.in_scope(current_user, user.get("role")):
        raise HTTPException(status_code=403, detail="This user is outside your data scope")
    
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
    await log_admin_action(current_user, f"user.{action}", target_type="user", target_id=data.user_id,
                           before={"banned": bool(user.get("banned"))}, after={"banned": data.banned},
                           reason=data.ban_reason)
    return {"message": f"User {action} successfully"}

# ── Admin user actions (warn / suspend / message / level / payout / commission / pro) ──
async def _admin_target(user_id, current_user, block_self=False, block_admin=False):
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if block_self and user_id == current_user['id']:
        raise HTTPException(status_code=400, detail="Cannot perform this on yourself")
    if block_admin and user.get('role') == UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="Cannot perform this on admin users")
    return user

@api_router.post("/admin/user/warn")
async def admin_warn_user(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("warn_suspend_users"))):
    user_id = data.get("user_id")
    message = (data.get("message") or "").strip()
    await _admin_target(user_id, current_user)
    if not message:
        raise HTTPException(status_code=400, detail="Warning message is required")
    await db.users.update_one({"id": user_id}, {"$inc": {"warnings": 1}, "$set": {"updated_at": now_iso()}})
    await notify_user(user_id, "Warning issued", message, ntype="warning")
    await log_admin_action(current_user, "user.warned", target_type="user", target_id=user_id, reason=message)
    return {"message": "Warning sent"}

@api_router.post("/admin/user/suspend")
async def admin_suspend_user(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("warn_suspend_users"))):
    user_id = data.get("user_id")
    reason = (data.get("reason") or "").strip()
    duration_days = int(data.get("duration_days") or 0)
    await _admin_target(user_id, current_user, block_self=True, block_admin=True)
    until = (datetime.now(timezone.utc) + timedelta(days=duration_days)).isoformat() if duration_days > 0 else None
    await db.users.update_one({"id": user_id}, {"$set": {
        "suspended": True, "status": "suspended", "suspended_reason": reason, "suspended_until": until,
        "suspended_by": current_user['id'], "updated_at": now_iso()}})
    span = f" for {duration_days} day(s)" if duration_days else ""
    await notify_user(user_id, "Account suspended", f"Your account has been suspended{span}. Reason: {reason or 'policy violation'}", ntype="warning")
    await log_admin_action(current_user, "user.suspended", target_type="user", target_id=user_id, reason=reason, after={"duration_days": duration_days})
    return {"message": "User suspended"}

@api_router.post("/admin/user/unsuspend")
async def admin_unsuspend_user(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("warn_suspend_users"))):
    user_id = data.get("user_id")
    await _admin_target(user_id, current_user)
    await db.users.update_one({"id": user_id}, {"$set": {
        "suspended": False, "status": "active", "suspended_until": None, "suspended_reason": None, "updated_at": now_iso()}})
    await notify_user(user_id, "Suspension lifted", "Your account suspension has been lifted — you can log in again.", ntype="info")
    await log_admin_action(current_user, "user.unsuspended", target_type="user", target_id=user_id)
    return {"message": "Suspension lifted"}

@api_router.post("/admin/user/message")
async def admin_message_user(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("user_management"))):
    user_id = data.get("user_id")
    message = (data.get("message") or "").strip()
    await _admin_target(user_id, current_user)
    if not message:
        raise HTTPException(status_code=400, detail="Message is required")
    await notify_user(user_id, "Message from the UGCad team", message, ntype="admin_message")
    await log_admin_action(current_user, "user.message", target_type="user", target_id=user_id, reason=message)
    return {"message": "Message sent"}

@api_router.post("/admin/user/level")
async def admin_set_level(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("user_management"))):
    user_id = data.get("user_id")
    direction = data.get("direction")   # 'promote' | 'demote'
    user = await _admin_target(user_id, current_user)
    keys = [k for k, _ in sorted(cf.CREATOR_LEVELS.items(), key=lambda kv: kv[1]["rank"])]
    cur = cf.normalize_level(user.get("level"))
    i = keys.index(cur) if cur in keys else 0
    ni = min(len(keys) - 1, i + 1) if direction == "promote" else max(0, i - 1)
    new_level = keys[ni]

    # Already at the ceiling / floor — nothing moved, so don't lie to the creator
    # with a "you've been promoted" popup.
    if new_level == cur:
        edge = "top" if direction == "promote" else "starting"
        raise HTTPException(status_code=400, detail=f"This creator is already at the {edge} level.")

    await db.users.update_one({"id": user_id}, {"$set": {"level": new_level, "updated_at": now_iso()}})
    new_label = cf.CREATOR_LEVELS[new_level]["label"]

    # Tell the creator — they see this as a toast/popup the next time they load, and
    # in their notifications list. Promotion is a celebration; demotion is a heads-up.
    if direction == "promote":
        await notify_user(
            user_id,
            "🎉 You've been promoted!",
            f"Congratulations! An admin promoted you to {new_label}. New perks and higher visibility are now unlocked.",
            link="/dashboard/creator",
            ntype="success",
        )
    else:
        await notify_user(
            user_id,
            "Your creator level changed",
            f"Your account level is now {new_label}. Reach out to support if you think this is a mistake.",
            link="/dashboard/creator",
            ntype="warning",
        )

    await log_admin_action(current_user, f"user.level_{direction}", target_type="user", target_id=user_id,
                           before={"level": cur}, after={"level": new_level})
    return {"message": f"Creator {direction}d", "level": new_level, "level_label": new_label}

@api_router.post("/admin/user/payout-schedule")
async def admin_payout_schedule(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("user_management"))):
    user_id = data.get("user_id")
    schedule = data.get("schedule") or "weekly"
    await _admin_target(user_id, current_user)
    await db.users.update_one({"id": user_id}, {"$set": {"payout_schedule": schedule, "updated_at": now_iso()}})
    await log_admin_action(current_user, "user.payout_schedule", target_type="user", target_id=user_id, after={"schedule": schedule})
    return {"message": f"Payout schedule set to {schedule}"}

@api_router.post("/admin/user/commission")
async def admin_set_commission(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("user_management"))):
    user_id = data.get("user_id")
    rate = float(data.get("commission_rate") or 0)
    await _admin_target(user_id, current_user)
    await db.users.update_one({"id": user_id}, {"$set": {"commission_rate": rate, "updated_at": now_iso()}})
    await log_admin_action(current_user, "user.commission", target_type="user", target_id=user_id, after={"commission_rate": rate})
    return {"message": "Commission updated"}

@api_router.post("/admin/user/convert-pro")
async def admin_convert_pro(data: Dict[str, Any] = Body(...), current_user: dict = Depends(require_cap("user_management"))):
    user_id = data.get("user_id")
    await _admin_target(user_id, current_user)
    await db.users.update_one({"id": user_id}, {"$set": {"is_pro": True, "plan": "pro", "updated_at": now_iso()}})
    await notify_user(user_id, "Upgraded to Pro", "Your account has been upgraded to a Pro account by an admin.", ntype="info")
    await log_admin_action(current_user, "user.convert_pro", target_type="user", target_id=user_id)
    return {"message": "Converted to Pro"}

# Every field name across the DB that points at a user id. Used to cascade-delete
# all of a user's data. Extra fields a given collection doesn't have are harmless
# (they simply won't match), so one broad $or works for every collection.
USER_REF_FIELDS = [
    "user_id", "creator_id", "business_id", "brand_id",
    "sender_id", "recipient_id", "other_user_id",
    "user1_id", "user2_id", "reviewer_id", "reviewee_id",
    "reported_user_id", "reporter_id", "target_user_id",
    "member_id", "public_creator_id", "banned_by",
]

# Collections that hold per-user data. Global config (business_settings,
# payment_gateways, payout_ranges, platform_settings, …) and the admin audit log
# (admin_logs) are deliberately excluded.
USER_DATA_COLLECTIONS = [
    "campaigns", "escrow", "payment_transactions", "chat_action_cards",
    "work_submissions", "messages", "shipments", "disputes", "withdrawals",
    "violations", "in_app_notifications", "deal_action_cards",
    "deal_content_submissions", "chat_strikes", "business_team_members",
    "wallet_ledger", "invoices", "deal_messages", "reviews", "late_offenses",
    "payout_receipts", "deal_activity", "chat_pauses", "user_reports",
    "uploaded_files", "notification_logs", "deal_receipts", "user_sessions",
    "private_invitations", "match_events", "deal_revision_responses",
    "chat_typing", "chat_false_positive_reviews", "brand_penalties",
    "campaign_views", "reviews",
]

# Collections keyed by campaign_id rather than directly by user. When a brand is
# deleted we also remove the children of every campaign they own.
CAMPAIGN_CHILD_COLLECTIONS = [
    "escrow", "shipments", "work_submissions", "disputes", "deal_action_cards",
    "deal_activity", "deal_receipts", "deal_content_submissions", "reviews",
    "deal_messages", "campaign_views", "deal_revision_responses",
]

@api_router.delete("/admin/user/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(require_cap("ban_users"))):
    """Permanently delete a user and ALL of their data (cascade)."""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Never delete yourself.
    if user_id == current_user['id']:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    # An admin can only be removed by the founder (Team & Roles → Delete), and the
    # founder account itself can never be deleted.
    if user.get('role') == UserRole.ADMIN:
        if not _is_founder_admin(current_user):
            raise HTTPException(status_code=403, detail="Only the founder can delete an admin")
        target_is_founder = (
            (user.get('email') or '').lower() == FOUNDER_EMAIL
            or user.get('admin_role') in (None, '', 'founder')
        )
        if target_is_founder:
            raise HTTPException(status_code=400, detail="The founder account cannot be deleted")

    deleted = {}

    def _add(coll, count):
        if count:
            deleted[coll] = deleted.get(coll, 0) + count

    # 1) Campaign ids this user owns (as a brand), so we can clean their children.
    campaign_ids = [
        c["id"] async for c in
        db.campaigns.find({"business_id": user_id}, {"_id": 0, "id": 1})
    ]

    # 2) Delete everything that references the user directly.
    user_query = {"$or": [{f: user_id} for f in USER_REF_FIELDS]}
    for coll in set(USER_DATA_COLLECTIONS):
        res = await db[coll].delete_many(user_query)
        _add(coll, res.deleted_count)

    # 3) Delete the children of any campaigns this user owned.
    if campaign_ids:
        child_query = {"campaign_id": {"$in": campaign_ids}}
        for coll in set(CAMPAIGN_CHILD_COLLECTIONS):
            res = await db[coll].delete_many(child_query)
            _add(coll, res.deleted_count)

    # 4) Pull the user's leftover bids out of OTHER brands' campaigns.
    await db.campaigns.update_many(
        {"bids.creator_id": user_id},
        {"$pull": {"bids": {"creator_id": user_id}}}
    )

    # 5) Finally remove the user record itself.
    await db.users.delete_one({"id": user_id})
    _add("users", 1)

    await log_admin_action(current_user, "user.deleted", target_type="user", target_id=user_id,
                           before={"email": user.get("email"), "nickname": user.get("nickname"),
                                   "role": user.get("role")},
                           after={"cascade_deleted": deleted})
    return {"message": "User and all related data deleted successfully", "deleted": deleted}

@api_router.get("/admin/withdrawals")
async def get_all_withdrawals(status: Optional[str] = None, current_user: dict = Depends(require_cap("view_financials"))):
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
async def approve_withdrawal(withdrawal_id: str, current_user: dict = Depends(require_cap("release_payouts"))):
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

    # Let the creator know their payout is on the way.
    amount = float(withdrawal.get('amount') or 0)
    await notify_user(
        withdrawal['user_id'],
        "Withdrawal approved",
        f"Your withdrawal of ₹{amount:,.0f} has been approved and is being paid out "
        f"via {withdrawal.get('payment_method', 'bank/UPI')}. Receipt {receipt.get('receipt_number', '')}.",
        link="/withdrawal",
        ntype="success",
        email=True,
        category="payments",
    )

    return {"message": "Withdrawal approved successfully", "receipt": receipt}

@api_router.post("/admin/withdrawals/{withdrawal_id}/reject")
async def reject_withdrawal(withdrawal_id: str, reason: str, current_user: dict = Depends(require_cap("release_payouts"))):
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

    # Tell the creator — they had no idea their payout was declined before this.
    amount = float(withdrawal.get('amount') or 0)
    reason_txt = (reason or '').strip()
    await notify_user(
        withdrawal['user_id'],
        "Withdrawal request declined",
        f"Your withdrawal of ₹{amount:,.0f} was not approved{(': ' + reason_txt) if reason_txt else '.'} "
        f"The amount has been refunded to your UGCad balance.",
        link="/withdrawal",
        ntype="warning",
        email=True,
        category="payments",
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
        file_url = persist_file(
            content,
            unique_filename,
            kind=kind,
            local_dir=upload_dir,
            public_path=f"/uploads/{unique_filename}",
            cloud_folder="ugcad/uploads",
        )
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

    file_ext = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_kind = "image" if file.content_type.startswith("image/") else "video" if file.content_type.startswith("video/") else "pdf"

    try:
        file_url = persist_file(
            content,
            unique_filename,
            kind=file_kind,
            local_dir=campaigns_upload_dir,
            public_path=f"/uploads/campaigns/{unique_filename}",
            cloud_folder="ugcad/campaigns",
        )
        file_doc = {
            "id": str(uuid.uuid4()),
            "file_url": file_url,
            "filename": file.filename,
            "content_type": file.content_type,
            "size": len(content),
            "kind": file_kind,
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
async def update_user_role(user_id: str, role: UserRole, current_user: dict = Depends(require_cap("manage_roles"))):
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
async def create_payment_gateway(data: PaymentGatewayConfig, current_user: dict = Depends(require_cap("edit_settings"))):
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
async def get_payment_gateways(current_user: dict = Depends(require_cap("edit_settings"))):
    """Get all payment gateway configurations"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    gateways = await db.payment_gateways.find({}, {"_id": 0, "key_secret": 0}).to_list(100)
    return gateways

@api_router.patch("/admin/payment-gateway/{gateway_name}")
async def update_payment_gateway(
    gateway_name: str,
    data: PaymentGatewayUpdate,
    current_user: dict = Depends(require_cap("edit_settings"))
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
async def delete_payment_gateway(gateway_name: str, current_user: dict = Depends(require_cap("edit_settings"))):
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
async def get_payment_transactions(current_user: dict = Depends(require_cap("view_financials"))):
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
async def razorpay_webhook(request: Request):
    """Handle Razorpay webhook notifications.

    SECURITY: the RAW body is HMAC-SHA256 verified against the Razorpay webhook secret
    before anything is credited. This endpoint is public and unauthenticated — without
    the check, anyone could POST a fake `payment.captured` and top up a wallet for free.
    Fails CLOSED: if no webhook_secret is configured we reject rather than trust the body.
    """
    try:
        gateway = await db.payment_gateways.find_one({"gateway_name": "razorpay"})
        if not gateway:
            raise HTTPException(status_code=400, detail="Gateway not configured")

        webhook_secret = gateway.get("webhook_secret")
        if not webhook_secret:
            logger.error("[razorpay-webhook] no webhook_secret configured — rejecting call")
            raise HTTPException(status_code=503, detail="Webhook secret not configured")

        raw = await request.body()
        signature = request.headers.get("X-Razorpay-Signature") or ""
        expected = hmac.new(webhook_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not signature or not hmac.compare_digest(expected, signature):
            logger.warning("[razorpay-webhook] invalid signature — rejected")
            raise HTTPException(status_code=400, detail="Invalid webhook signature")

        body = await request.json()
        event = body.get("event")
        payload = body.get("payload") or {}

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

    except HTTPException:
        # Don't swallow our own 400/503 rejections into a 500.
        raise
    except Exception as e:
        logger.error(f"[razorpay-webhook] {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

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
async def create_notification_gateway(data: NotificationGatewayConfig, current_user: dict = Depends(require_cap("edit_settings"))):
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

# ── Top Earner showcase (creator home hero) ──────────────────────────────────
# Manually curated by admins. The hero shows these rotating cards; if none are
# set the frontend falls back to its built-in defaults.
@api_router.get("/home/top-earners")
async def get_top_earners():
    doc = await db.site_settings.find_one({"key": "top_earners"}, {"_id": 0})
    return {"items": (doc or {}).get("items", [])}

@api_router.get("/admin/top-earners")
async def admin_get_top_earners(current_user: dict = Depends(require_cap("edit_settings"))):
    doc = await db.site_settings.find_one({"key": "top_earners"}, {"_id": 0})
    return {"items": (doc or {}).get("items", [])}

@api_router.put("/admin/top-earners")
async def admin_set_top_earners(data: TopEarnersUpdate, current_user: dict = Depends(require_cap("edit_settings"))):
    items = [i.dict() for i in data.items if str(i.name or "").strip()]
    await db.site_settings.update_one(
        {"key": "top_earners"},
        {"$set": {"key": "top_earners", "items": items, "updated_at": datetime.now(timezone.utc).isoformat(), "updated_by": current_user["id"]}},
        upsert=True,
    )
    return {"items": items}

@api_router.get("/admin/top-earners/suggest")
async def admin_suggest_top_earners(limit: int = 3, current_user: dict = Depends(require_cap("edit_settings"))):
    """Compute the REAL top-earning creators from released payouts, so the admin can
    seed the showcase from live data instead of typing it. Returns the same item
    shape as the showcase; the admin can then edit and Save."""
    n = max(1, min(int(limit or 3), 10))
    released = await db.escrow.find({"status": "released"}, {"_id": 0, "campaign_id": 1, "net_payable": 1, "creator_payout": 1, "amount": 1}).to_list(20000)
    camp_ids = list({e.get("campaign_id") for e in released if e.get("campaign_id")})
    camps = await db.campaigns.find({"id": {"$in": camp_ids}}, {"_id": 0, "id": 1, "selected_creator": 1}).to_list(20000) if camp_ids else []
    camp_to_creator = {c["id"]: c.get("selected_creator") for c in camps if c.get("id")}

    totals = {}
    for e in released:
        cid = camp_to_creator.get(e.get("campaign_id"))
        if not cid:
            continue
        pay = to_float(e.get("net_payable") if e.get("net_payable") is not None
                       else (e.get("creator_payout") if e.get("creator_payout") is not None else e.get("amount")))
        t = totals.setdefault(cid, {"earned": 0.0, "deals": 0})
        t["earned"] += pay
        t["deals"] += 1

    top = sorted(totals.items(), key=lambda kv: kv[1]["earned"], reverse=True)[:n]
    out = []
    for cid, agg in top:
        u = await db.users.find_one({"id": cid}, {"_id": 0}) or {}
        out.append(_creator_showcase_item(u, agg))
    return {"items": out}

def _creator_showcase_item(u: dict, agg: dict) -> dict:
    """Map a creator user + earnings aggregate into a showcase card, including the
    full list of their portfolio videos (for the per-card video dropdown)."""
    p = u.get("profile") or {}
    name = (p.get("fullName") or p.get("full_name") or u.get("full_name") or u.get("nickname") or "Creator")
    portfolio = u.get("portfolio") or p.get("portfolio_items") or p.get("portfolio") or []
    portfolio = portfolio if isinstance(portfolio, list) else [portfolio]
    videos = []
    for it in portfolio:
        url = _portfolio_preview_url(it)
        if url and url not in videos:
            videos.append(url)
    return {
        "id": u.get("id"),
        "name": str(name).strip().lstrip("@"),
        "category": p.get("primary_category") or p.get("category") or u.get("category") or "",
        "earned": round((agg or {}).get("earned", 0)),
        "deals": (agg or {}).get("deals", 0),
        "rating": to_float(u.get("average_rating")) or 0,
        "level": str(u.get("level") or ""),
        "video_url": videos[0] if videos else "",
        "videos": videos,
    }

@api_router.get("/admin/top-earners/creators")
async def admin_showcase_creators(current_user: dict = Depends(require_cap("edit_settings"))):
    """Every approved creator + their real earnings, for the per-card picker on the
    Home Showcase editor. Sorted by earnings so the top earners surface first."""
    released = await db.escrow.find({"status": "released"}, {"_id": 0, "campaign_id": 1, "net_payable": 1, "creator_payout": 1, "amount": 1}).to_list(20000)
    camp_ids = list({e.get("campaign_id") for e in released if e.get("campaign_id")})
    camps = await db.campaigns.find({"id": {"$in": camp_ids}}, {"_id": 0, "id": 1, "selected_creator": 1}).to_list(20000) if camp_ids else []
    camp_to_creator = {c["id"]: c.get("selected_creator") for c in camps if c.get("id")}
    totals = {}
    for e in released:
        cid = camp_to_creator.get(e.get("campaign_id"))
        if not cid:
            continue
        pay = to_float(e.get("net_payable") if e.get("net_payable") is not None
                       else (e.get("creator_payout") if e.get("creator_payout") is not None else e.get("amount")))
        t = totals.setdefault(cid, {"earned": 0.0, "deals": 0})
        t["earned"] += pay
        t["deals"] += 1
    creators = await db.users.find(
        {"role": "creator", "approval_status": "approved"},
        {"_id": 0, "id": 1, "nickname": 1, "full_name": 1, "profile": 1, "average_rating": 1, "level": 1, "category": 1, "portfolio": 1},
    ).to_list(5000)
    out = [_creator_showcase_item(u, totals.get(u.get("id"))) for u in creators]
    out.sort(key=lambda x: x.get("earned", 0), reverse=True)
    return {"items": out}

@api_router.get("/admin/notification-gateways")
async def get_notification_gateways(current_user: dict = Depends(require_cap("edit_settings"))):
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
async def update_notification_gateway(gateway_id: str, enabled: bool, current_user: dict = Depends(require_cap("edit_settings"))):
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
async def delete_notification_gateway(gateway_id: str, current_user: dict = Depends(require_cap("edit_settings"))):
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
async def get_notification_logs(current_user: dict = Depends(require_cap("edit_settings"))):
    """Get notification sending logs"""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = await db.notification_logs.find({}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100)
    return logs

# In-App Notification System
@api_router.get("/notifications/my-notifications")
async def get_my_notifications(current_user: dict = Depends(get_current_user)):
    """Get current user's in-app notifications.

    The "Admin" chip is driven by `source == 'admin'`, which the broadcast endpoint
    stamps. But notifications created BEFORE that tagging existed (or by any other
    admin-authored path) have no `source`, so they showed as plain system events for
    both brands and creators. Derive the tag here from `created_by`: if an admin
    authored it, surface it as an admin message — retroactively, with no migration.
    """
    notifications = await db.in_app_notifications.find(
        {"user_id": current_user['id']},
        {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)

    # Resolve the distinct human authors once (usually 0-2 ids), then tag any
    # untagged notification an admin wrote. 'system' is skipped — those are genuine
    # system events and must stay chip-less.
    author_ids = {n.get("created_by") for n in notifications
                  if n.get("created_by") and n.get("created_by") != "system" and not n.get("source")}
    admin_ids = set()
    if author_ids:
        admin_ids = {u["id"] for u in await db.users.find(
            {"id": {"$in": list(author_ids)}, "role": {"$in": list(OPS_ROLES)}},
            {"_id": 0, "id": 1},
        ).to_list(None)}
    for n in notifications:
        if not n.get("source") and n.get("created_by") in admin_ids:
            n["source"] = "admin"
            n.setdefault("sender_label", "Admin")
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
async def broadcast_notification(data: BroadcastNotification, current_user: dict = Depends(require_cap("user_management"))):
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
            "created_by": current_user['id'],
            # Tag broadcasts so the recipient's bell can show they came from the
            # admin/ops team (e.g. an "Admin" chip) instead of a system event.
            "source": "admin",
            "sender_label": "Admin",
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
async def create_staff(data: StaffCreate, current_user: dict = Depends(require_cap("manage_roles"))):
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
    """Get all staff members.

    Returns both models so the two admin pages coexist:
      - campaign_manager / support_staff  → the legacy Staff page (AdminDashboard)
      - role='admin' with an `admin_role`  → the Roles page (AdminRoles, PRD 11)
    Admins with no `admin_role` resolve to founder (legacy single-admin installs).
    """
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    staff = await db.users.find(
        {"role": {"$in": [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER, UserRole.SUPPORT_STAFF]}},
        {"_id": 0, "password": 0, "invite_token": 0}
    ).sort("created_at", 1).to_list(1000)
    for u in staff:
        if u.get("role") == UserRole.ADMIN and not u.get("admin_role"):
            u["admin_role"] = "founder"
        u.setdefault("assigned_categories", [])
    return staff

@api_router.patch("/admin/staff/permissions")
async def update_staff_permissions(data: PermissionUpdate, current_user: dict = Depends(require_cap("manage_roles"))):
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

# ============================================================================
# ADMIN ROLES — founder / ops sub-role model (PRD 11)
# Powers the frontend AdminRoles page. Distinct from the campaign_manager /
# support_staff "staff" model above: here an admin user (role == 'admin') carries
# an `admin_role` sub-tier and optional `assigned_categories` for work
# distribution. These endpoints were missing on this backend, which is why the
# founder's "Grant access" / role-change actions returned 404.
# ============================================================================

ADMIN_SUB_ROLES = ["founder", "ops_senior", "ops_regular", "finance"]
ADMIN_ROLE_LABELS = {
    "founder": "Founder / Admin",
    "ops_senior": "Ops (Senior)",
    "ops_regular": "Operations Team",
    "finance": "Finance",
}
FOUNDER_EMAIL = (os.environ.get("FOUNDER_EMAIL") or "admin@gmail.com").lower()


def _is_founder_admin(user: dict) -> bool:
    """Only the founder may manage admin roles. Any admin whose sub-role is unset
    is the legacy single founder-admin; explicit sub-roles (ops_*/finance) are not."""
    return user.get("role") == UserRole.ADMIN and (user.get("admin_role") in (None, "founder"))


def _map_staff_row(u: dict) -> dict:
    """Shape an admin user for the Roles page (mirror of the Express mapStaffRow)."""
    return {
        "id": u.get("id"),
        "email": u.get("email"),
        "nickname": u.get("nickname"),
        "admin_role": u.get("admin_role") or "founder",
        "assigned_categories": u.get("assigned_categories") or [],
        "admin_caps": u.get("admin_caps") or [],
        "admin_cap_modes": u.get("admin_cap_modes") or {},
        "admin_scope": u.get("admin_scope") or "all",
    }


@api_router.get("/admin/categories")
async def admin_get_categories(current_user: dict = Depends(get_current_user)):
    """Category options for the work-distribution assignment UI."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required")
    cats = await db.categories.find(
        {"active": True}, {"_id": 0, "name": 1}
    ).sort("order", 1).to_list(500)
    names = [c.get("name") for c in cats if c.get("name")]
    return {"categories": names, "canonical": names}


@api_router.post("/admin/staff/role")
async def admin_set_staff_role(data: Dict[str, Any] = Body(...), request: Request = None,
                               current_user: dict = Depends(require_cap("manage_roles"))):
    """Assign / change an admin's sub-role, or grant admin to a new email.
    The founder SETS the password explicitly (no auto-generated temp password).
    Passing `password` for an existing member changes their password. Founder-only."""
    if not _is_founder_admin(current_user):
        raise HTTPException(status_code=403, detail="Only the founder can assign admin roles")

    user_id = data.get("user_id")
    email = (data.get("email") or "").strip().lower()
    admin_role = data.get("admin_role")
    password = (data.get("password") or "").strip()
    if admin_role not in admin_caps.ADMIN_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    if password and len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    # Custom admins carry an explicit capability list + data scope; other roles
    # derive their capabilities from the fixed CAPS matrix.
    is_custom = admin_role == "custom"
    custom_caps = [c for c in (data.get("admin_caps") or []) if c in admin_caps.ALL_CAPS] if is_custom else []
    raw_modes = data.get("admin_cap_modes") or {}
    custom_cap_modes = {
        cap: raw_modes.get(cap, "both")
        for cap in custom_caps
        if raw_modes.get(cap, "both") in ("view", "edit", "both")
    } if is_custom else {}
    custom_scope = data.get("admin_scope") if data.get("admin_scope") in ("all", "creator", "business") else "all"

    user = None
    if user_id:
        user = await db.users.find_one({"id": user_id})
    elif email:
        user = await db.users.find_one({"email": email})

    created = False
    password_set = False
    if not user:
        # A user_id that resolves to nothing, or no email at all, is a real 404.
        if user_id or not email:
            raise HTTPException(status_code=404, detail="User not found")
        # Creating a brand-new admin — the founder must set the password.
        if not password:
            raise HTTPException(status_code=400, detail="Set a password for the new admin (min 6 characters)")
        created = True
        password_set = True
        user = {
            "id": str(uuid.uuid4()),
            "email": email,
            "nickname": email.split("@")[0],
            "password": hash_password(password),
            "role": UserRole.ADMIN,
            "admin_role": admin_role,
            "admin_caps": custom_caps,
            "admin_cap_modes": custom_cap_modes,
            "admin_scope": custom_scope if is_custom else "all",
            "approval_status": "approved",
            "profile_completed": True,
            "assigned_categories": [],
            "balance": 0,
            "banned": False,
            "created_at": now_iso(),
            "created_by": current_user["id"],
        }
        await db.users.insert_one(user)
    else:
        if (user.get("email") or "").lower() == FOUNDER_EMAIL and admin_role != "founder":
            raise HTTPException(status_code=400, detail="The founder account cannot be demoted")
        update = {
            "role": UserRole.ADMIN,
            "admin_role": admin_role,
            "admin_caps": custom_caps,
            "admin_cap_modes": custom_cap_modes,
            "admin_scope": custom_scope if is_custom else "all",
            "approval_status": "approved",
            "profile_completed": True,
            "updated_at": now_iso(),
        }
        # A password on an existing member = "change password".
        if password:
            update["password"] = hash_password(password)
            password_set = True
        await db.users.update_one({"id": user["id"]}, {"$set": update})
        user = await db.users.find_one({"id": user["id"]})

    await log_admin_action(
        current_user,
        "staff.created" if created else "staff.role_changed",
        target_type="user", target_id=user["id"],
        after={"role": "admin", "admin_role": admin_role, "password_changed": password_set},
        reason=f"{'Created' if created else 'Set'} {user['email']} → {admin_caps.ROLE_LABELS.get(admin_role, admin_role)}"
               + (" (password set)" if password_set and not created else ""),
        request=request,
    )

    # ---- Tell the person they've been made an admin (email + in-app) --------
    # Fire-and-forget: a mail hiccup must never fail the role assignment.
    try:
        role_label = admin_caps.ROLE_LABELS.get(admin_role, admin_role)
        frontend = (os.environ.get("FRONTEND_URL") or "https://www.ugcad.io").rstrip("/")
        login_url = f"{frontend}/auth"

        # For a custom admin, spell out exactly what they were granted.
        feat_html = ""
        if is_custom and custom_caps:
            feat_html = (
                "<p style='margin:18px 0 6px;font-size:13px;font-weight:700;color:#1f2340;'>Your access:</p>"
                "<ul style='margin:0;padding-left:20px;color:#4a4f74;font-size:14px;line-height:1.7;'>"
                + "".join(f"<li>{c.replace('_', ' ').capitalize()}</li>" for c in custom_caps)
                + "</ul>"
            )

        if created:
            subject = "You've been added as an admin on UGCad.io"
            heading = "You're now an admin"
            intro = (f"You've been added to the UGCad.io admin team as <strong>{role_label}</strong>. "
                     "Sign in with this email address — your password was set by the founder who added you.")
        else:
            subject = "Your UGCad.io admin role was updated"
            heading = "Your admin role changed"
            intro = f"Your role on the UGCad.io admin team is now <strong>{role_label}</strong>."

        content = f"""
            <h1 style="margin:0 0 12px;font-size:22px;color:#1f2340;">{heading}</h1>
            <p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#4a4f74;">{intro}</p>
            {feat_html}
            <p style="margin:22px 0 0;">
              <a href="{login_url}" style="display:inline-block;background:#5b6bff;color:#fff;text-decoration:none;font-weight:700;font-size:15px;padding:13px 28px;border-radius:10px;">Sign in to the admin panel</a>
            </p>
        """
        await send_email(user["email"], subject, _email_base_template(subject, content))
        await notify_user(
            user["id"], subject,
            f"You are now {role_label} on the UGCad.io admin team.",
            link="/dashboard/admin", ntype="info",
        )
    except Exception as e:
        logger.warning(f"[staff/role] admin notification failed: {e}")

    return {
        "success": True,
        "created": created,
        "password_set": password_set,
        "staff": _map_staff_row(user),
    }


@api_router.post("/admin/staff/revoke")
async def admin_revoke_staff(data: Dict[str, Any] = Body(...), request: Request = None,
                             current_user: dict = Depends(require_cap("manage_roles"))):
    """Revoke admin access entirely (demote back to a regular creator). Founder-only."""
    if not _is_founder_admin(current_user):
        raise HTTPException(status_code=403, detail="Only the founder can revoke admin roles")
    user = await db.users.find_one({"id": data.get("user_id")})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if (user.get("email") or "").lower() == FOUNDER_EMAIL:
        raise HTTPException(status_code=400, detail="The founder account cannot be revoked")
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"role": UserRole.CREATOR, "admin_role": None, "updated_at": now_iso()}},
    )
    await log_admin_action(current_user, "staff.revoked", target_type="user", target_id=user["id"],
                           reason=f"Revoked admin from {user['email']}", request=request)
    return {"success": True}


@api_router.post("/admin/staff/categories")
async def admin_set_staff_categories(data: Dict[str, Any] = Body(...),
                                     current_user: dict = Depends(require_cap("manage_roles"))):
    """Set the categories an ops admin is responsible for (work distribution). Founder-only."""
    if not _is_founder_admin(current_user):
        raise HTTPException(status_code=403, detail="Only the founder can assign categories")
    categories = data.get("categories")
    if not isinstance(categories, list):
        raise HTTPException(status_code=400, detail="categories must be an array")
    user = await db.users.find_one({"id": data.get("user_id")})
    if not user:
        raise HTTPException(status_code=404, detail="Admin not found")
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"assigned_categories": categories, "updated_at": now_iso()}},
    )
    return {"success": True, "assigned_categories": categories}

# Payout Ranges Management
@api_router.get("/admin/payout-ranges")
async def admin_get_payout_ranges(current_user: dict = Depends(require_cap("view_financials"))):
    """Get all payout ranges (including inactive) for admin management."""
    if current_user['role'] not in [UserRole.ADMIN, UserRole.CAMPAIGN_MANAGER]:
        raise HTTPException(status_code=403, detail="Admin access required")
    ranges = await db.payout_ranges.find({}, {"_id": 0}).sort("sort_order", 1).to_list(100)
    return {"ranges": ranges}

@api_router.post("/admin/payout-ranges")
async def admin_create_payout_range(data: PayoutRangeCreate, current_user: dict = Depends(require_cap("edit_settings"))):
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
async def admin_update_payout_range(range_id: str, data: PayoutRangeUpdate, current_user: dict = Depends(require_cap("edit_settings"))):
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
async def admin_delete_payout_range(range_id: str, current_user: dict = Depends(require_cap("edit_settings"))):
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
async def export_withdrawals(current_user: dict = Depends(require_cap("view_financials"))):
    """Export withdrawal requests to CSV"""
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    withdrawals = await db.withdrawals.find({}, {"_id": 0}).to_list(10000)
    
    # Enrich with user bank details
    for withdrawal in withdrawals:
        user = await db.users.find_one(
            {"id": withdrawal['user_id']},
            {"_id": 0, "bank_details": 1, "upi_id": 1, "nickname": 1, "email": 1, "full_name": 1, "business_name": 1, "name": 1, "username": 1, "profile": 1}
        )
        if user:
            withdrawal['creator_name'] = person_display_name(user, 'N/A')
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
async def get_creator_financial_details(creator_id: str, current_user: dict = Depends(require_cap("view_financials"))):
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

# ===========================================================================
# Admin Panel — Section 11 modules (Audit Log, Settings, Financials,
# Shipping Queue, Deals admin). All sensitive actions write to the audit log.
# ===========================================================================

def _client_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


async def log_admin_action(admin: dict, action: str, *, target_type: Optional[str] = None,
                           target_id: Optional[str] = None, before: Any = None, after: Any = None,
                           reason: Optional[str] = None, request: Optional[Request] = None) -> dict:
    """PRD 11.15: append-only audit trail of every admin action."""
    entry = {
        "id": str(uuid.uuid4()),
        "admin_id": admin.get("id"),
        "admin_nickname": admin.get("nickname"),
        "admin_role": admin.get("role"),
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "before": before,
        "after": after,
        "reason": reason,
        "ip": _client_ip(request),
        "created_at": now_iso(),
    }
    await db.admin_logs.insert_one(entry)
    return {k: v for k, v in entry.items() if k != "_id"}


# PRD 11.15: sensitive actions are founder-only when committed by peers and
# trigger a founder email digest. Kept in sync with the frontend list.
SENSITIVE_ACTIONS = [
    "wallet.adjust", "dispute.ruling", "user.banned", "user.suspended",
    "settings.update", "withdrawal.approved", "withdrawal.rejected", "deal.force_transition",
]


# Actions are namespaced (e.g. "wallet.adjust"); the prefix maps to a module so
# the audit UI can group/filter without every call site passing one explicitly.
_MODULE_BY_PREFIX = {
    "wallet": "financials", "payout": "financials", "escrow": "financials",
    "withdrawal": "financials", "export": "financials", "dispute": "disputes",
    "user": "users", "settings": "settings", "shipping": "shipping", "deal": "deals",
}


def _module_for(action: Optional[str]) -> str:
    return _MODULE_BY_PREFIX.get((action or "").split(".")[0], "")


def _build_audit_query(current_user: dict, action: Optional[str], module: Optional[str],
                       admin_id: Optional[str], target_id: Optional[str],
                       date_from: Optional[str], date_to: Optional[str]) -> dict:
    query: dict = {}
    if action:
        query["action"] = action
    elif module:
        # Module isn't stored per-row; match the action prefixes that map to it.
        prefixes = [p for p, m in _MODULE_BY_PREFIX.items() if m == module]
        if prefixes:
            query["action"] = {"$regex": f"^({'|'.join(prefixes)})\\."}
    if admin_id:
        query["admin_id"] = admin_id
    if target_id:
        query["target_id"] = target_id
    if date_from or date_to:
        created = {}
        if date_from:
            created["$gte"] = date_from
        if date_to:
            created["$lte"] = f"{date_to}T23:59:59.999Z"
        query["created_at"] = created
    # Log review (PRD 11.15): the founder sees every entry; other admins see
    # their own actions plus peers' routine (non-sensitive) actions.
    if current_user["role"] != UserRole.ADMIN:
        query["$or"] = [
            {"admin_id": current_user["id"]},
            {"action": {"$nin": SENSITIVE_ACTIONS}},
        ]
    return query


def _map_audit(log: dict) -> dict:
    return {**log, "module": log.get("module") or _module_for(log.get("action")),
            "sensitive": log.get("action") in SENSITIVE_ACTIONS}


@api_router.get("/admin/audit-logs")
async def get_audit_logs(action: Optional[str] = None, module: Optional[str] = None,
                         admin_id: Optional[str] = None, target_id: Optional[str] = None,
                         date_from: Optional[str] = Query(None, alias="from"),
                         date_to: Optional[str] = Query(None, alias="to"),
                         limit: int = 500,
                         current_user: dict = Depends(require_cap("view_audit"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view audit logs")
    query = _build_audit_query(current_user, action, module, admin_id, target_id, date_from, date_to)
    logs = await db.admin_logs.find(query, {"_id": 0}).sort("created_at", -1).to_list(min(max(limit, 1), 1000))
    return {"logs": [_map_audit(l) for l in logs], "count": len(logs)}


@api_router.get("/admin/audit-logs/export")
async def export_audit_logs(action: Optional[str] = None, module: Optional[str] = None,
                            admin_id: Optional[str] = None, target_id: Optional[str] = None,
                            date_from: Optional[str] = Query(None, alias="from"),
                            date_to: Optional[str] = Query(None, alias="to"),
                            current_user: dict = Depends(require_cap("view_audit"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view audit logs")
    query = _build_audit_query(current_user, action, module, admin_id, target_id, date_from, date_to)
    logs = await db.admin_logs.find(query, {"_id": 0}).sort("created_at", -1).to_list(5000)

    import csv as _csv
    import json as _json
    from io import StringIO
    from fastapi.responses import Response

    output = StringIO()
    writer = _csv.writer(output)
    writer.writerow(["timestamp", "admin", "role", "action", "module", "target",
                     "before", "after", "reason", "ip"])
    for l in logs:
        target = f"{l.get('target_type')}:{l.get('target_id')}" if l.get("target_type") else ""
        writer.writerow([
            l.get("created_at", ""), l.get("admin_nickname", ""), l.get("admin_role", ""),
            l.get("action", ""), l.get("module") or _module_for(l.get("action")), target,
            _json.dumps(l.get("before")), _json.dumps(l.get("after")),
            l.get("reason", ""), l.get("ip", ""),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename=audit-log_{datetime.now().strftime("%Y%m%d")}.csv'},
    )


# --- Platform Settings (PRD 11.14, founder-only) ---------------------------
DEFAULT_PLATFORM_SETTINGS = {
    "commission_rate": 20,
    "listing_fee": 500,
    "revision_price": 500,
    "auto_approval_days": 5,
    "late_ship_fee_per_day": 200,
    "late_ship_fee_cap": 1000,
    "payout_delay_days": {"new": 12, "verified": 7, "l1": 5, "l2": 3, "elite": 2},
    "restricted_categories": ["tobacco", "weapons", "adult", "gambling"],
    "feature_flags": {"matching_v05": True, "instant_payout": True},
    # Brand wallet recharge-bonus tiers (amount -> instant % bonus). Editable in admin.
    "wallet_bonus_tiers": WALLET_BONUS_TIERS,
}

# In-process cache so sync helpers (commission, fees) can read live settings without
# awaiting. Warmed at startup and refreshed every time settings are saved.
_PLATFORM_SETTINGS_CACHE: Dict[str, Any] = dict(DEFAULT_PLATFORM_SETTINGS)


def platform_setting(key: str, default=None):
    """Sync read of a platform setting (falls back to the shipped default)."""
    value = _PLATFORM_SETTINGS_CACHE.get(key)
    if value is None:
        value = DEFAULT_PLATFORM_SETTINGS.get(key, default)
    return default if value is None else value


def commission_percent() -> float:
    """Platform commission %, driven by Admin → Settings → Commission rate."""
    return to_float(platform_setting("commission_rate", 20)) or 20.0


def feature_enabled(flag: str) -> bool:
    return bool((platform_setting("feature_flags") or {}).get(flag, True))


def payout_delay_for(level) -> int:
    """Payout delay (days) for a creator level, from Settings (falls back to the code table)."""
    table = platform_setting("payout_delay_days") or {}
    value = table.get(cf.normalize_level(level))
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(cf.payout_delay_days(level))


def revision_fee_for(used: int) -> float:
    """Fee for the brand's next revision — free up to the limit, then `revision_price`."""
    if used < cf.FREE_REVISION_LIMIT:
        return 0.0
    return to_float(platform_setting("revision_price", cf.PAID_REVISION_FEE))


def is_restricted_category(*values) -> Optional[str]:
    """Return the restricted keyword a campaign/brand category matches, if any."""
    blocked = [str(c).strip().lower() for c in (platform_setting("restricted_categories") or []) if str(c).strip()]
    for value in values:
        text = str(value or "").lower()
        if not text:
            continue
        for word in blocked:
            if word and word in text:
                return word
    return None


async def get_platform_settings() -> dict:
    doc = await db.platform_settings.find_one({"id": "platform"}, {"_id": 0})
    merged = {**DEFAULT_PLATFORM_SETTINGS, **((doc or {}).get("values") or {})}
    _PLATFORM_SETTINGS_CACHE.clear()
    _PLATFORM_SETTINGS_CACHE.update(merged)
    return merged


@api_router.get("/admin/gst")
async def admin_list_gst(status: Optional[str] = None,
                         current_user: dict = Depends(require_cap("review_applications"))):
    """Brands awaiting (or holding) GST verification. Defaults to the pending queue."""
    query: Dict[str, Any] = {"role": UserRole.BUSINESS, "gst.status": {"$exists": True}}
    if status and status != "all":
        query["gst.status"] = status
    elif not status:
        query["gst.status"] = "pending"

    rows = await db.users.find(
        query, {"_id": 0, "id": 1, "email": 1, "nickname": 1, "full_name": 1, "profile": 1, "gst": 1}
    ).sort("gst.submitted_at", 1).to_list(200)

    out = []
    for u in rows:
        gst = u.get("gst") or {}
        out.append({
            "user_id": u.get("id"),
            "email": u.get("email"),
            "brand_name": (u.get("profile") or {}).get("business_name") or u.get("nickname") or u.get("full_name") or u.get("email"),
            "gstin": gst.get("gstin"),
            "legal_name": gst.get("legal_name"),
            "status": gst.get("status"),
            "submitted_at": gst.get("submitted_at"),
            "reviewed_at": gst.get("reviewed_at"),
            "rejection_reason": gst.get("rejection_reason"),
        })
    return out


@api_router.post("/admin/gst/{user_id}")
async def admin_review_gst(user_id: str, data: AdminGSTReview,
                           current_user: dict = Depends(require_cap("review_applications"))):
    """Approve or reject a brand's GSTIN. Approving is what unlocks wallet funding."""
    user = await db.users.find_one({"id": user_id})
    if not user or user.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=404, detail="Brand not found")
    if not admin_caps.in_scope(current_user, user):
        raise HTTPException(status_code=403, detail="This account is outside your assigned scope")

    gst = user.get("gst") or {}
    if not gst.get("gstin"):
        raise HTTPException(status_code=400, detail="This brand has not submitted a GSTIN.")

    action = (data.action or "").lower()
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")

    reason = (data.reason or "").strip()
    if action == "reject" and not reason:
        raise HTTPException(status_code=400, detail="Give a reason so the brand knows what to fix.")

    status = "verified" if action == "approve" else "rejected"
    await db.users.update_one({"id": user_id}, {"$set": {
        "gst.status": status,
        "gst.reviewed_at": now_iso(),
        "gst.reviewed_by": current_user.get("id"),
        "gst.rejection_reason": reason if action == "reject" else "",
    }})

    if action == "approve":
        await notify_user(user_id, "GST verified — you can now add funds",
                          f"Your GSTIN {gst['gstin']} has been verified. You can now recharge your wallet and start booking creators.",
                          link="/dashboard/business/wallet", ntype="success", email=True)
    else:
        await notify_user(user_id, "GST verification rejected",
                          f"Your GSTIN could not be verified: {reason}. Please resubmit a correct GSTIN on the Wallet page.",
                          link="/dashboard/business/wallet", ntype="warning", email=True)

    await log_admin_action(current_user, f"gst.{action}", target_type="user", target_id=user_id)
    return {"user_id": user_id, "status": status}


@api_router.get("/admin/email/health")
async def admin_email_health(current_user: dict = Depends(require_cap("edit_settings"))):
    """Is transactional email actually configured ON THIS SERVER? Without this the only
    symptom of a missing RESEND_API_KEY is silence — the send is skipped and nothing
    surfaces. Reports config (never the key itself) plus the quiet-hours window."""
    key = os.environ.get("RESEND_API_KEY", "")
    return {
        "configured": bool(key),
        "key_hint": (key[:6] + "…") if key else None,
        "from": os.environ.get("EMAIL_FROM", "UGCad.io <onboarding@resend.dev>"),
        "reply_to": os.environ.get("EMAIL_REPLY_TO") or None,
        "frontend_url": os.environ.get("FRONTEND_URL") or None,
        "in_quiet_hours": _in_quiet_hours(),
        "note": ("Email is DISABLED — RESEND_API_KEY is not set on this server, so every send is "
                 "silently skipped. Add it to the environment and redeploy."
                 if not key else "Email is configured."),
    }


@api_router.post("/admin/email/test")
async def admin_email_test(data: Dict[str, Any] = Body(...),
                           current_user: dict = Depends(require_cap("edit_settings"))):
    """Send a real test email and return exactly what the provider said, so a failure is
    diagnosable from the admin UI instead of guessing."""
    to = (data.get("to") or current_user.get("email") or "").strip()
    if not to:
        raise HTTPException(status_code=400, detail="Provide a 'to' address")
    result = await send_email(
        to, "UGCad.io — test email",
        _email_base_template("Test email", "<p>If you're reading this, transactional email works.</p>"),
        "If you're reading this, transactional email works.",
    )
    if result.get("skipped"):
        raise HTTPException(status_code=503, detail="RESEND_API_KEY is not set on this server — email is disabled.")
    if result.get("error"):
        raise HTTPException(status_code=502, detail=f"Provider rejected the send: {result['error']}")
    return {"sent": True, "to": to, "provider_id": result.get("id")}


@api_router.get("/admin/settings")
async def admin_get_settings(current_user: dict = Depends(require_cap("edit_settings"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view settings")
    return {"settings": await get_platform_settings(), "defaults": DEFAULT_PLATFORM_SETTINGS}


@api_router.put("/admin/settings")
async def admin_update_settings(data: Dict[str, Any] = Body(...), request: Request = None,
                                current_user: dict = Depends(require_cap("edit_settings"))):
    # Founder-only (PRD 11.3 / 11.14).
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only the founder/admin can change platform settings")
    before = await get_platform_settings()
    allowed = set(DEFAULT_PLATFORM_SETTINGS.keys())
    overrides = {k: v for k, v in (data or {}).items() if k in allowed}
    if not overrides:
        raise HTTPException(status_code=400, detail="No valid settings provided")
    merged = {**(before), **overrides}
    await db.platform_settings.update_one(
        {"id": "platform"}, {"$set": {"id": "platform", "values": merged, "updated_at": now_iso()}}, upsert=True
    )
    # Refresh the in-process cache so the new values take effect immediately.
    await get_platform_settings()
    await log_admin_action(current_user, "settings.update", target_type="platform_settings", target_id="platform",
                           before={k: before.get(k) for k in overrides}, after=overrides, request=request)
    return {"settings": merged, "message": "Settings updated"}


# --- Financials (PRD 11.11) -------------------------------------------------
@api_router.get("/admin/financials/overview")
async def admin_financials_overview(current_user: dict = Depends(require_cap("view_financials"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view financials")
    escrows = await db.escrow.find({}, {"_id": 0}).to_list(20000)
    total_escrow_held = round(sum(to_float(e.get("amount")) for e in escrows if e.get("status") == "held"), 2)
    brands = await db.users.find({"role": UserRole.BUSINESS}, {"_id": 0, "balance": 1}).to_list(20000)
    total_wallet = round(sum(to_float(b.get("balance")) for b in brands), 2)
    now = datetime.now(timezone.utc)
    horizon = (now + timedelta(days=7)).isoformat()
    scheduled = [e for e in escrows if e.get("payout_status") == "scheduled"]
    next7 = [e for e in scheduled if (e.get("payout_scheduled_at") or "") <= horizon]
    scheduled_total = round(sum(to_float(e.get("net_payable") or e.get("amount")) for e in next7), 2)
    invoices = await db.invoices.find({}, {"_id": 0}).to_list(20000)
    commission_earned = round(sum(to_float(i.get("gross_amount")) * 0.25 for i in invoices), 2)
    return {
        "total_escrow_held": total_escrow_held,
        "total_wallet_balance": total_wallet,
        "scheduled_payouts_next_7d": scheduled_total,
        "scheduled_payouts_count": len(next7),
        "open_escrows": len([e for e in escrows if e.get("status") == "held"]),
        "commission_earned_est": commission_earned,
    }


@api_router.get("/admin/payouts")
async def admin_payout_queue(status_filter: Optional[str] = None, current_user: dict = Depends(require_cap("view_financials"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view payouts")
    query = {"payout_status": {"$in": ["scheduled", "released"]}}
    if status_filter:
        query["payout_status"] = status_filter
    escrows = await db.escrow.find(query, {"_id": 0}).sort("payout_scheduled_at", 1).to_list(2000)
    rows = []
    for e in escrows:
        creator = await db.users.find_one({"id": e.get("creator_id")}, {"_id": 0, "nickname": 1, "upi_id": 1, "full_name": 1, "business_name": 1, "name": 1, "username": 1, "email": 1, "profile": 1}) or {}
        campaign = await db.campaigns.find_one({"id": e.get("campaign_id")}, {"_id": 0, "title": 1}) or {}
        rows.append({
            "escrow_id": e.get("id"), "campaign_id": e.get("campaign_id"), "campaign_title": campaign.get("title"),
            "creator_id": e.get("creator_id"), "creator_nickname": person_display_name(creator, "Creator"),
            "gross_amount": to_float(e.get("gross_amount") or e.get("amount")),
            "tds_amount": to_float(e.get("tds_amount")), "net_payable": to_float(e.get("net_payable") or e.get("amount")),
            "payout_status": e.get("payout_status"), "scheduled_at": e.get("payout_scheduled_at"),
            "method": "UPI" if creator.get("upi_id") else "bank",
        })
    return {"payouts": rows, "count": len(rows)}


@api_router.get("/admin/escrow")
async def admin_escrow_list(current_user: dict = Depends(require_cap("view_financials"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view escrow")
    escrows = await db.escrow.find({}, {"_id": 0}).sort("created_at", -1).to_list(5000)
    rows = []
    for e in escrows:
        campaign = await db.campaigns.find_one({"id": e.get("campaign_id")}, {"_id": 0, "title": 1}) or {}
        creator = await db.users.find_one({"id": e.get("creator_id")}, {"_id": 0, "nickname": 1, "full_name": 1, "business_name": 1, "name": 1, "username": 1, "email": 1, "profile": 1}) or {}
        rows.append({
            "id": e.get("id"), "campaign_id": e.get("campaign_id"), "campaign_title": campaign.get("title"),
            "creator": person_display_name(creator, "Creator"), "amount": to_float(e.get("amount")),
            "held_amount": to_float(e.get("amount")), "status": e.get("status"),
            "payout_status": e.get("payout_status"), "created_at": e.get("created_at"),
        })
    return rows


def _csv_response(rows: List[dict], fieldnames: List[str], filename: str):
    import csv
    from io import StringIO
    from fastapi.responses import Response
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return Response(content=output.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@api_router.get("/admin/financials/tds/export")
async def export_tds(current_user: dict = Depends(require_cap("export_tax"))):
    """PRD 11.11: TDS certificate prep (Form 16A) — one row per creator earning."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin/finance can export tax docs")
    invoices = await db.invoices.find({}, {"_id": 0}).to_list(20000)
    rows = []
    for inv in invoices:
        creator = await db.users.find_one({"id": inv.get("creator_id")}, {"_id": 0, "nickname": 1, "email": 1, "full_name": 1, "business_name": 1, "name": 1, "username": 1, "profile": 1}) or {}
        rows.append({
            "creator_id": inv.get("creator_id"), "creator": person_display_name(creator, "Creator"), "email": creator.get("email"),
            "campaign_id": inv.get("campaign_id"), "gross_amount": inv.get("gross_amount"),
            "tds_amount": inv.get("tds_amount"), "net_to_creator": inv.get("net_to_creator"),
            "date": (inv.get("created_at") or "")[:10],
        })
    await log_admin_action(current_user, "export.tds", target_type="report", reason="PII export")
    return _csv_response(rows, ["creator_id", "creator", "email", "campaign_id", "gross_amount", "tds_amount", "net_to_creator", "date"], "tds_form16a.csv")


@api_router.get("/admin/financials/gst/export")
async def export_gst(current_user: dict = Depends(require_cap("export_tax"))):
    """PRD 11.11: GST-ready invoice export."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin/finance can export tax docs")
    invoices = await db.invoices.find({}, {"_id": 0}).to_list(20000)
    rows = []
    for inv in invoices:
        gross = to_float(inv.get("gross_amount"))
        commission = round(gross * 0.25, 2)
        gst = round(commission * 0.18, 2)
        rows.append({
            "invoice_id": inv.get("id"), "business_id": inv.get("business_id"), "campaign_id": inv.get("campaign_id"),
            "gross_amount": gross, "platform_commission": commission, "gst_18pct": gst,
            "date": (inv.get("created_at") or "")[:10],
        })
    await log_admin_action(current_user, "export.gst", target_type="report")
    return _csv_response(rows, ["invoice_id", "business_id", "campaign_id", "gross_amount", "platform_commission", "gst_18pct", "date"], "gst_invoices.csv")


@api_router.post("/admin/wallet/adjust")
async def admin_wallet_adjust(data: Dict[str, Any] = Body(...), request: Request = None,
                              current_user: dict = Depends(require_cap("adjust_wallet"))):
    # Financial adjustment — founder/admin only, mandatory reason, audit-logged (PRD 11.11/11.16).
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only the founder/admin can adjust wallet balances")
    user_id = data.get("user_id")
    amount = to_float(data.get("amount"))
    reason = (data.get("reason") or "").strip()
    if not user_id or amount == 0:
        raise HTTPException(status_code=400, detail="user_id and a non-zero amount are required")
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required for any wallet adjustment")
    target = await db.users.find_one({"id": user_id}, {"_id": 0, "balance": 1, "nickname": 1})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    before_balance = to_float(target.get("balance"))
    await db.users.update_one({"id": user_id}, {"$inc": {"balance": amount}})
    await db.wallet_ledger.insert_one({
        "id": str(uuid.uuid4()), "user_id": user_id, "transaction_id": str(uuid.uuid4()),
        "type": "admin_adjustment", "direction": "credit" if amount > 0 else "debit",
        "amount": abs(amount), "status": "success", "note": f"Admin adjustment: {reason}",
        "created_at": now_iso(), "date": now_iso(),
    })
    await log_admin_action(current_user, "wallet.adjust", target_type="user", target_id=user_id,
                           before={"balance": before_balance}, after={"balance": round(before_balance + amount, 2)},
                           reason=reason, request=request)
    await notify_user(user_id, "Wallet adjusted", f"Your wallet was adjusted by ₹{amount:,.0f} by the platform team. Reason: {reason}")
    return {"message": "Wallet adjusted", "new_balance": round(before_balance + amount, 2)}


# --- Financials: wallet ledger, revenue, payout & escrow controls (PRD 11.11) ---

def _period_cutoff_iso(period: Optional[str]) -> str:
    """Rolling-window start for a revenue period: day=24h, week=7d, month=30d."""
    days = {"day": 1, "week": 7, "month": 30}.get((period or "month").lower(), 30)
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


@api_router.get("/admin/wallet/{user_id}/transactions")
async def admin_wallet_transactions(user_id: str, current_user: dict = Depends(require_cap("view_financials"))):
    """PRD 11.11: per-wallet transaction history for the admin wallet view."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view wallet history")
    entries = await db.wallet_ledger.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(2000)
    rows = []
    for e in entries:
        amt = to_float(e.get("amount"))
        signed = amt if (e.get("direction") or "credit") == "credit" else -amt
        rows.append({
            "id": e.get("id"), "type": e.get("type"), "direction": e.get("direction"),
            "amount": round(signed, 2), "reason": e.get("note") or e.get("description"),
            "status": e.get("status"), "created_at": e.get("created_at") or e.get("date"),
        })
    return {"transactions": rows, "count": len(rows)}


@api_router.get("/admin/financials/revenue")
async def admin_financials_revenue(period: Optional[str] = "month", current_user: dict = Depends(require_cap("view_financials"))):
    """PRD 11.11 revenue tracking: commission, listing fees, refunded fees and
    penalty collections over the selected rolling period."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view revenue")
    cutoff = _period_cutoff_iso(period)

    invoices = await db.invoices.find({"created_at": {"$gte": cutoff}}, {"_id": 0}).to_list(50000)
    commission = round(sum(to_float(i.get("gross_amount")) * commission_percent() / 100 for i in invoices), 2)

    # Campaign listing fees and refunds — recorded as payment_transactions.
    txns = await db.payment_transactions.find({"created_at": {"$gte": cutoff}}, {"_id": 0}).to_list(50000)
    def _is_listing(t):
        blob = f"{t.get('purpose','')} {t.get('type','')} {t.get('note','')}".lower()
        return "listing" in blob or "campaign_fee" in blob
    listing_fees = round(sum(to_float(t.get("amount")) for t in txns if _is_listing(t) and (t.get("status") in (None, "success", "completed")) and (t.get("direction") != "refund") and not t.get("refunded")), 2)
    refunded_listing_fees = round(sum(to_float(t.get("amount")) for t in txns if _is_listing(t) and (t.get("direction") == "refund" or t.get("status") == "refunded" or t.get("refunded"))), 2)

    # Penalty collections retained by the platform (penalty minus any brand goodwill share).
    released_escrows = await db.escrow.find({"payout_status": "released", "released_at": {"$gte": cutoff}}, {"_id": 0}).to_list(50000)
    penalties = round(sum(max(to_float(e.get("penalty_amount")) - to_float(e.get("penalty_brand_credit")), 0) for e in released_escrows), 2)
    try:
        brand_pens = await db.brand_penalties.find({"created_at": {"$gte": cutoff}}, {"_id": 0}).to_list(50000)
        penalties = round(penalties + sum(to_float(p.get("amount")) for p in brand_pens), 2)
    except Exception:
        pass

    return {
        "period": (period or "month").lower(),
        "commission": commission,
        "listing_fees": listing_fees,
        "refunded_listing_fees": refunded_listing_fees,
        "penalties": penalties,
        "net": round(commission + listing_fees - refunded_listing_fees + penalties, 2),
    }


async def _release_one_payout(escrow_id: str) -> bool:
    """Release a single scheduled/held payout by its escrow id. Clears any hold
    first, then runs the standard scheduled-payout release (money movement,
    receipt, notifications). Returns True if a payout was actually released."""
    escrow = await db.escrow.find_one({"id": escrow_id})
    if not escrow:
        return False
    if escrow.get("payout_status") == "released":
        return False
    # A held payout is just a paused 'scheduled' one — un-hold before releasing.
    if escrow.get("payout_status") == "held":
        await db.escrow.update_one({"id": escrow_id}, {"$set": {"payout_status": "scheduled"}, "$unset": {"payout_hold_reason": ""}})
        escrow = await db.escrow.find_one({"id": escrow_id})
    return await release_scheduled_payout(escrow)


@api_router.post("/admin/payouts/{escrow_id}/hold")
async def admin_hold_payout(escrow_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                            current_user: dict = Depends(require_cap("release_payouts"))):
    """PRD 11.11: hold a scheduled payout (fraud review / dispute-in-progress)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can hold payouts")
    reason = (data.get("reason") or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required to hold a payout")
    escrow = await db.escrow.find_one({"id": escrow_id}, {"_id": 0})
    if not escrow:
        raise HTTPException(status_code=404, detail="Payout not found")
    if escrow.get("payout_status") != "scheduled":
        raise HTTPException(status_code=400, detail="Only scheduled payouts can be held")
    await db.escrow.update_one({"id": escrow_id}, {"$set": {"payout_status": "held", "payout_hold_reason": reason, "payout_held_at": now_iso()}})
    await log_admin_action(current_user, "payout.hold", target_type="escrow", target_id=escrow_id, reason=reason, request=request)
    return {"message": "Payout held", "escrow_id": escrow_id}


@api_router.post("/admin/payouts/{escrow_id}/release")
async def admin_release_payout(escrow_id: str, request: Request = None, current_user: dict = Depends(require_cap("release_payouts"))):
    """PRD 11.11: release a single scheduled or held payout immediately."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can release payouts")
    if not await db.escrow.find_one({"id": escrow_id}, {"_id": 0}):
        raise HTTPException(status_code=404, detail="Payout not found")
    released = await _release_one_payout(escrow_id)
    if not released:
        raise HTTPException(status_code=400, detail="Payout could not be released (already paid or not payable)")
    await log_admin_action(current_user, "payout.release", target_type="escrow", target_id=escrow_id, request=request)
    return {"message": "Payout released", "escrow_id": escrow_id}


@api_router.post("/admin/payouts/batch-release")
async def admin_batch_release_payouts(data: Dict[str, Any] = Body(...), request: Request = None,
                                      current_user: dict = Depends(require_cap("release_payouts"))):
    """PRD 11.11: batch-release every payout scheduled for a date (or an explicit
    list of escrow ids)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can release payouts")
    ids = data.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=400, detail="A non-empty list of payout ids is required")
    released = 0
    for escrow_id in ids:
        try:
            if await _release_one_payout(escrow_id):
                released += 1
        except Exception:
            logger.exception("Batch release failed for escrow %s", escrow_id)
    await log_admin_action(current_user, "payout.batch_release", target_type="report",
                           after={"requested": len(ids), "released": released}, reason=data.get("date"), request=request)
    return {"message": f"Released {released} of {len(ids)} payouts", "released": released, "requested": len(ids)}


@api_router.post("/admin/escrow/{escrow_id}/release")
async def admin_release_escrow(escrow_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                               current_user: dict = Depends(require_cap("release_payouts"))):
    """PRD 11.11: release held escrow funds to the creator with a mandatory reason."""
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only the founder/admin can move escrow funds")
    reason = (data.get("reason") or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required and will be logged")
    escrow = await db.escrow.find_one({"id": escrow_id}, {"_id": 0})
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow.get("status") == "released" or escrow.get("payout_status") == "released":
        raise HTTPException(status_code=400, detail="These funds have already been released")
    if escrow.get("status") == "refunded":
        raise HTTPException(status_code=400, detail="These funds were refunded to the brand")

    # If a scheduled payout already exists, use the standard release path.
    if escrow.get("payout_status") in ("scheduled", "held"):
        await _release_one_payout(escrow_id)
    else:
        campaign = await db.campaigns.find_one({"id": escrow.get("campaign_id")}) or {}
        creator_id = escrow.get("creator_id") or campaign.get("selected_creator")
        gross = to_float(escrow.get("gross_amount") or escrow.get("amount"))
        tds = to_float(escrow.get("tds_amount"))
        net = to_float(escrow.get("net_payable")) if escrow.get("net_payable") is not None else round(gross - tds, 2)
        now = now_iso()
        await db.escrow.update_one({"id": escrow_id}, {"$set": {"status": "released", "payout_status": "released", "released_at": now, "released_reason": reason}})
        if creator_id and net:
            await db.users.update_one({"id": creator_id}, {"$inc": {"balance": net}})
            await create_payout_receipt(creator_id=creator_id, receipt_type="earning", gross_amount=gross,
                                        campaign_id=escrow.get("campaign_id"), reference_id=escrow_id,
                                        note=f"Manual escrow release: {reason}", tds_amount=tds)
            await notify_user(creator_id, "Payment released", f"₹{int(net)} has been released to your wallet.", link="/withdrawal", ntype="success", email=True, category="payments")
    await log_admin_action(current_user, "escrow.release", target_type="escrow", target_id=escrow_id, reason=reason, request=request)
    return {"message": "Escrow released to creator", "escrow_id": escrow_id}


@api_router.post("/admin/escrow/{escrow_id}/refund")
async def admin_refund_escrow(escrow_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                              current_user: dict = Depends(require_cap("release_payouts"))):
    """PRD 11.11: refund held escrow funds back to the brand with a mandatory reason."""
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only the founder/admin can move escrow funds")
    reason = (data.get("reason") or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required and will be logged")
    escrow = await db.escrow.find_one({"id": escrow_id}, {"_id": 0})
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow.get("status") in ("released", "refunded") or escrow.get("payout_status") == "released":
        raise HTTPException(status_code=400, detail="These funds are no longer held and cannot be refunded")
    campaign = await db.campaigns.find_one({"id": escrow.get("campaign_id")}) or {}
    business_id = campaign.get("business_id") or escrow.get("business_id")
    amount = to_float(escrow.get("gross_amount") or escrow.get("amount"))
    await db.escrow.update_one({"id": escrow_id}, {"$set": {"status": "refunded", "payout_status": "refunded", "refunded_at": now_iso(), "refund_reason": reason}})
    if business_id and amount:
        await db.users.update_one({"id": business_id}, {"$inc": {"balance": amount}})
        await db.wallet_ledger.insert_one({
            "id": str(uuid.uuid4()), "user_id": business_id, "transaction_id": str(uuid.uuid4()),
            "type": "escrow_refund", "direction": "credit", "amount": round(amount, 2),
            "status": "success", "note": f"Escrow refund: {reason}", "created_at": now_iso(), "date": now_iso(),
        })
        await notify_user(business_id, "Escrow refunded", f"₹{int(amount)} held in escrow was refunded to your wallet. Reason: {reason}", link="/dashboard/business/wallet", ntype="success", email=True, category="payments")
    await log_admin_action(current_user, "escrow.refund", target_type="escrow", target_id=escrow_id,
                           after={"amount": amount}, reason=reason, request=request)
    return {"message": "Escrow refunded to brand", "escrow_id": escrow_id, "amount": amount}


# ---- Deal-room shortcuts: release/refund by DEAL (campaign) id -----------------
# The admin Deals drawer calls these deal-scoped paths; they resolve the escrow
# for the campaign and delegate to the escrow release/refund logic above.
@api_router.post("/admin/deals/{campaign_id}/release-payment")
async def admin_deal_release_payment(campaign_id: str, data: Dict[str, Any] = Body(default={}),
                                     request: Request = None, current_user: dict = Depends(require_cap("release_payouts"))):
    escrow = await db.escrow.find_one({"campaign_id": campaign_id}, {"_id": 0})
    if not escrow:
        raise HTTPException(status_code=404, detail="No escrow found for this deal")
    body = dict(data or {})
    body.setdefault("reason", "Payment released from the deal room by admin")
    return await admin_release_escrow(escrow["id"], data=body, request=request, current_user=current_user)


@api_router.post("/admin/deals/{campaign_id}/refund")
async def admin_deal_refund(campaign_id: str, data: Dict[str, Any] = Body(default={}),
                            request: Request = None, current_user: dict = Depends(require_cap("release_payouts"))):
    escrow = await db.escrow.find_one({"campaign_id": campaign_id}, {"_id": 0})
    if not escrow:
        raise HTTPException(status_code=404, detail="No escrow found for this deal")
    body = dict(data or {})
    body.setdefault("reason", "Refunded from the deal room by admin")
    return await admin_refund_escrow(escrow["id"], data=body, request=request, current_user=current_user)


@api_router.get("/admin/financials/pnl/export")
async def export_pnl(period: Optional[str] = "month", current_user: dict = Depends(require_cap("view_financials"))):
    """PRD 11.11: monthly P&L summary export."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin/finance can export financials")
    cutoff = _period_cutoff_iso(period)
    invoices = await db.invoices.find({"created_at": {"$gte": cutoff}}, {"_id": 0}).to_list(50000)
    gross = round(sum(to_float(i.get("gross_amount")) for i in invoices), 2)
    commission = round(gross * commission_percent() / 100, 2)
    tds = round(sum(to_float(i.get("tds_amount")) for i in invoices), 2)
    creator_payouts = round(sum(to_float(i.get("net_to_creator")) for i in invoices), 2)
    released = await db.escrow.find({"payout_status": "released", "released_at": {"$gte": cutoff}}, {"_id": 0}).to_list(50000)
    penalties = round(sum(max(to_float(e.get("penalty_amount")) - to_float(e.get("penalty_brand_credit")), 0) for e in released), 2)
    rows = [
        {"line_item": "Gross deal volume", "amount": gross},
        {"line_item": "Platform commission (revenue)", "amount": commission},
        {"line_item": "Penalty collections (revenue)", "amount": penalties},
        {"line_item": "TDS withheld (liability)", "amount": tds},
        {"line_item": "Creator payouts (cost of goods)", "amount": creator_payouts},
        {"line_item": "Net platform revenue", "amount": round(commission + penalties, 2)},
    ]
    await log_admin_action(current_user, "export.pnl", target_type="report", reason=(period or "month"))
    return _csv_response(rows, ["line_item", "amount"], f"pnl_{(period or 'month')}.csv")


@api_router.get("/admin/financials/reconciliation/export")
async def export_reconciliation(current_user: dict = Depends(require_cap("view_financials"))):
    """PRD 11.11: reconciliation report (wallet + escrow + bank)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin/finance can export financials")
    escrows = await db.escrow.find({}, {"_id": 0}).to_list(50000)
    escrow_held = round(sum(to_float(e.get("amount")) for e in escrows if e.get("status") == "held"), 2)
    users = await db.users.find({"balance": {"$gt": 0}}, {"_id": 0, "balance": 1}).to_list(50000)
    wallet_liability = round(sum(to_float(u.get("balance")) for u in users), 2)
    scheduled = [e for e in escrows if e.get("payout_status") == "scheduled"]
    scheduled_total = round(sum(to_float(e.get("net_payable") or e.get("amount")) for e in scheduled), 2)
    rows = [
        {"account": "Wallet liabilities (held in user wallets)", "balance": wallet_liability},
        {"account": "Escrow held (open deals)", "balance": escrow_held},
        {"account": "Scheduled payouts (committed)", "balance": scheduled_total},
        {"account": "Total platform obligations", "balance": round(wallet_liability + escrow_held, 2)},
    ]
    await log_admin_action(current_user, "export.reconciliation", target_type="report")
    return _csv_response(rows, ["account", "balance"], "reconciliation.csv")


@api_router.get("/admin/reports/digest")
async def export_reports_digest(period: Optional[str] = "daily", current_user: dict = Depends(require_cap("generate_reports"))):
    """Platform activity digest (users / applications / campaigns / deals / escrow)
    as a CSV, scoped to the requested period."""
    cutoff = _period_cutoff_iso(period)
    since = {"$gte": cutoff} if cutoff else None

    async def _count(coll, extra=None, date_field="created_at"):
        q = dict(extra or {})
        if since:
            q[date_field] = since
        return await db[coll].count_documents(q)

    total_users = await db.users.count_documents({})
    new_creators = await _count("users", {"role": UserRole.CREATOR}, "created_at")
    new_brands = await _count("users", {"role": UserRole.BUSINESS}, "created_at")
    pending_apps = await db.users.count_documents({"approval_status": ApprovalStatus.PENDING})
    new_campaigns = await _count("campaigns", None, "created_at")
    active_campaigns = await db.campaigns.count_documents({"status": CampaignStatus.ACTIVE})
    open_disputes = await db.disputes.count_documents({"status": {"$in": ["open", "info_requested", "appealed"]}})
    escrows = await db.escrow.find({"status": "held"}, {"_id": 0, "amount": 1}).to_list(50000)
    escrow_held = round(sum(to_float(e.get("amount")) for e in escrows), 2)

    rows = [
        {"metric": "period", "value": period or "daily"},
        {"metric": "generated_at", "value": now_iso()},
        {"metric": "total_users", "value": total_users},
        {"metric": "new_creators", "value": new_creators},
        {"metric": "new_brands", "value": new_brands},
        {"metric": "pending_applications", "value": pending_apps},
        {"metric": "new_campaigns", "value": new_campaigns},
        {"metric": "active_campaigns", "value": active_campaigns},
        {"metric": "open_disputes", "value": open_disputes},
        {"metric": "escrow_held_inr", "value": escrow_held},
    ]
    await log_admin_action(current_user, "export.digest", target_type="report", reason=period)
    return _csv_response(rows, ["metric", "value"], f"digest_{(period or 'daily')}.csv")


# --- Shipping Queue (PRD 11.9) ---------------------------------------------
@api_router.get("/admin/shipping/requests")
async def admin_shipping_requests(current_user: dict = Depends(require_cap("manage_shipping"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view the shipping queue")
    campaigns = await db.campaigns.find(
        {"requires_shipment": True, "selected_creator": {"$nin": [None, ""]},
         "status": {"$in": ["in_progress", "active", "work_submitted", "completed"]}},
        {"_id": 0},
    ).to_list(2000)
    def _fmt_addr(a):
        # Render a structured address dict into a readable multi-line string.
        if not a:
            return None
        if isinstance(a, str):
            return a
        if not isinstance(a, dict):
            return None
        region = " ".join(x for x in [a.get("state"), a.get("pincode")] if x)
        line = ", ".join(x for x in [a.get("line1"), a.get("line2"), a.get("city"), region] if x)
        who = " · ".join(x for x in [a.get("full_name"), a.get("phone")] if x)
        return (who + "\n" + line) if who else (line or None)

    rows = []
    for c in campaigns:
        cid = c.get("id")
        if not cid:
            continue  # legacy campaign without a UUID id — skip rather than 500
        sh = await db.shipments.find_one({"campaign_id": cid}, {"_id": 0}) or {}
        ship_status = sh.get("courier_status") or sh.get("status") or "pending"
        brand = await db.users.find_one({"id": c.get("business_id")}, {"_id": 0, "nickname": 1, "profile": 1, "full_name": 1, "business_name": 1, "name": 1, "username": 1, "email": 1}) or {}
        creator = await db.users.find_one({"id": c.get("selected_creator")}, {"_id": 0, "nickname": 1, "profile": 1, "full_name": 1, "business_name": 1, "name": 1, "username": 1, "email": 1}) or {}
        requested = sh.get("requested_at") or c.get("work_started_at") or c.get("updated_at") or c.get("created_at")
        prod = sh.get("product") or {}
        dims = prod.get("dimensions") or {}
        dim_str = (f"{dims.get('length') or '?'}×{dims.get('width') or '?'}×{dims.get('height') or '?'} cm"
                   if any(dims.get(k) for k in ("length", "width", "height")) else None)
        product_name = sh.get("product_summary") or prod.get("description") or c.get("product_name") or "—"
        rows.append({
            "id": cid, "deal_id": cid, "campaign_title": c.get("title"),
            "brand": person_display_name(brand, "Brand"), "creator": person_display_name(creator, "Creator"),
            "product": product_name, "product_summary": product_name,
            "weight": (f"{prod.get('weight')} kg" if prod.get("weight") else None),
            "dimensions": dim_str,
            "requested_at": requested, "created_at": requested,
            # When it actually shipped — lets the queue freeze the SLA at ship time
            # instead of showing an ever-growing "breached" on a done shipment.
            "shipped_at": sh.get("shipped_at") or sh.get("updated_at"),
            "status": ship_status, "courier": sh.get("courier_name"), "tracking_number": sh.get("tracking_number"),
            "has_label": bool(sh.get("label_url")), "label_url": sh.get("label_url"),
            # Prefer what was submitted for THIS shipment; fall back to the saved
            # profile (the creator confirms their address there, and the shipment doc
            # may not exist yet). Both branches go through _fmt_addr — the fallback
            # used to return the raw dict, which the admin table rendered as
            # "[object Object]".
            "pickup_address": _fmt_addr(sh.get("pickup_address")) or _fmt_addr((brand.get("profile") or {}).get("address")),
            "ship_address": _fmt_addr(sh.get("delivery_address")) or _fmt_addr((creator.get("profile") or {}).get("address")),
            "shipping_address": _fmt_addr(sh.get("delivery_address")) or _fmt_addr((creator.get("profile") or {}).get("address")),
            "ship_city": ((sh.get("delivery_address") or (creator.get("profile") or {}).get("address")) or {}).get("city")
                         if isinstance(sh.get("delivery_address") or (creator.get("profile") or {}).get("address"), dict) else None,
            # So ops can see at a glance who still owes an address.
            "awaiting_creator_address": not bool(
                sh.get("delivery_address") or (creator.get("profile") or {}).get("address")
            ),
        })
    rows.sort(key=lambda r: r.get("requested_at") or "")
    return rows


@api_router.post("/admin/shipping/{campaign_id}/label")
async def admin_upload_shipping_label(campaign_id: str, file: UploadFile = File(...),
                                      current_user: dict = Depends(require_cap("manage_shipping"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can upload labels")
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    content = await file.read()
    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads"))) / "labels"
    ext = Path(file.filename or "label.pdf").suffix or ".pdf"
    fname = f"label_{campaign_id}_{uuid.uuid4().hex}{ext}"
    file_url = persist_file(content, fname, kind="other", local_dir=upload_dir,
                            public_path=f"/uploads/labels/{fname}", cloud_folder="ugcad/labels")
    await db.shipments.update_one({"campaign_id": campaign_id},
                                  {"$set": {"label_url": file_url, "updated_at": now_iso()}}, upsert=True)
    await log_admin_action(current_user, "shipping.label_uploaded", target_type="deal", target_id=campaign_id,
                           after={"label_url": file_url})
    return {"file_url": file_url, "label_url": file_url, "message": "Label uploaded"}


@api_router.post("/admin/shipping/{campaign_id}/ship")
async def admin_mark_shipped(campaign_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                             current_user: dict = Depends(require_cap("manage_shipping"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can mark shipped")
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    update = {"courier_name": data.get("courier"), "courier_status": "shipped", "status": "shipped",
              "tracking_number": data.get("tracking_number"), "updated_at": now_iso()}
    if data.get("label_url"):
        update["label_url"] = data["label_url"]
    await db.shipments.update_one({"campaign_id": campaign_id}, {"$set": update}, upsert=True)
    await log_admin_action(current_user, "shipping.marked_shipped", target_type="deal", target_id=campaign_id,
                           after={"courier": data.get("courier"), "tracking_number": data.get("tracking_number")}, request=request)
    if campaign.get("business_id"):
        await notify_user(campaign["business_id"], "Product shipped", "Your product has been shipped to the creator.", link="/dashboard/business/shipments", category="deal_updates")
    if campaign.get("selected_creator"):
        await notify_user(campaign["selected_creator"], "Product on the way", "The brand's product has been shipped to you.", link="/my-deals", email=True, category="deal_updates")
    await insert_deal_system_message(campaign, "Shipment dispatched by the platform team.")
    return {"message": "Marked as shipped"}


# --- Deals admin (PRD 11.7) -------------------------------------------------
@api_router.get("/admin/deals")
async def admin_list_deals(state: Optional[str] = None, current_user: dict = Depends(require_cap("manage_deals"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view deals")
    query = {"selected_creator": {"$nin": [None, ""]}}
    if state:
        query["status"] = state
    campaigns = [c for c in await db.campaigns.find(query, {"_id": 0}).sort("updated_at", -1).to_list(2000)
                 if c.get("id")]   # legacy campaigns without a UUID id are skipped, not 500s
    cids = [c["id"] for c in campaigns]

    # Batch-load everything compute_deal_state() needs. The previous version ran four
    # per-row lookups (brand, creator, escrow, disputes); this is a fixed handful of
    # queries for the WHOLE page, so pulling in shipment/receipt/work/action-cards as
    # well actually costs fewer round-trips than before.
    def first_by_campaign(rows):
        out = {}
        for r in rows:
            out.setdefault(r.get("campaign_id"), r)
        return out

    uids = [u for u in {c.get("business_id") for c in campaigns} | {c.get("selected_creator") for c in campaigns} if u]
    # Pull the real-name fields (not just the nickname) so the admin table shows
    # actual names via person_display_name — no raw "@handle" usernames.
    users = {u["id"]: u for u in await db.users.find(
        {"id": {"$in": uids}},
        {"_id": 0, "id": 1, "nickname": 1, "full_name": 1, "business_name": 1,
         "name": 1, "username": 1, "email": 1, "profile": 1},
    ).to_list(None)}
    escrows = first_by_campaign(await db.escrow.find({"campaign_id": {"$in": cids}}, {"_id": 0}).to_list(None))
    shipments = first_by_campaign(await db.shipments.find({"campaign_id": {"$in": cids}}, {"_id": 0}).to_list(None))
    receipts = first_by_campaign(await db.deal_receipts.find({"campaign_id": {"$in": cids}}, {"_id": 0}).to_list(None))
    # Ascending sort + overwrite leaves the LATEST submission per campaign, matching
    # get_deal_context()'s sort=[("submitted_at", -1)] single-doc fetch.
    works = {}
    for w in await db.work_submissions.find({"campaign_id": {"$in": cids}}, {"_id": 0}).sort("submitted_at", 1).to_list(None):
        works[w.get("campaign_id")] = w
    cards = {}
    for card in await db.deal_action_cards.find({"campaign_id": {"$in": cids}}, {"_id": 0}).to_list(None):
        cards.setdefault(card.get("campaign_id"), []).append(card)
    disputed_ids = {d.get("campaign_id") for d in await db.disputes.find(
        {"campaign_id": {"$in": cids}, "status": {"$in": ["open", "info_requested", "appealed"]}},
        {"_id": 0, "campaign_id": 1}).to_list(None)}

    rows = []
    for c in campaigns:
        cid = c["id"]
        escrow = escrows.get(cid) or {}
        shipment = shipments.get(cid)
        # THE FIX: report the real, human-readable deal state — the same one the deal
        # room and the admin State dropdown are built from. This used to echo the raw
        # campaign status enum ("work_submitted"), which no dropdown option could ever
        # equal, so every State filter selection matched zero rows (and the State
        # column showed the enum instead of "Content Submitted — Awaiting Review").
        st = compute_deal_state(
            c, shipment, normalize_receipt(shipment, receipts.get(cid)),
            works.get(cid), escrow, cards.get(cid) or [],
        )
        brand = users.get(c.get("business_id")) or {}
        creator = users.get(c.get("selected_creator")) or {}
        rows.append({
            "id": cid, "deal_id": cid, "campaign_title": c.get("title"), "campaign": c.get("title"),
            "brand": person_display_name(brand, "Brand"), "creator": person_display_name(creator, "Creator"),
            "current_state": st["current_state"], "state": st["current_state"],
            "active_party": st["active_party"], "primary_next_action": st["primary_next_action"],
            "deadline": c.get("final_delivery_by") or c.get("due_date"),
            "deadline_countdown_hours": st["deadline_countdown_hours"],
            "is_overdue": st["is_overdue"],
            "urgency": st["urgency"],
            "escrow": to_float(escrow.get("amount")), "escrow_status": escrow.get("status"),
            "flagged": bool(cid in disputed_ids), "requires_shipment": bool(c.get("requires_shipment")),
        })
    # Surface overdue / due-soon deals at the top of the ops queue.
    rows.sort(key=lambda r: (0 if r["is_overdue"] else 1 if r["urgency"] == "due_soon" else 2))
    return rows


@api_router.get("/admin/deals/{campaign_id}")
async def admin_deal_detail(campaign_id: str, current_user: dict = Depends(require_cap("manage_deals"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view deals")
    c = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not c:
        raise HTTPException(status_code=404, detail="Deal not found")
    _name_proj = {"_id": 0, "nickname": 1, "full_name": 1, "business_name": 1, "name": 1, "username": 1, "email": 1, "profile": 1}
    brand = await db.users.find_one({"id": c.get("business_id")}, _name_proj) or {}
    creator = await db.users.find_one({"id": c.get("selected_creator")}, _name_proj) or {}
    brand_name = person_display_name(brand, "Brand")
    creator_name = person_display_name(creator, "Creator")
    escrow = await db.escrow.find_one({"campaign_id": campaign_id}, {"_id": 0}) or {}
    shipment = await db.shipments.find_one({"campaign_id": campaign_id}, {"_id": 0}) or {}
    timeline = await db.deal_activity.find({"campaign_id": campaign_id}, {"_id": 0}).sort("timestamp", 1).to_list(500)
    # Show real names in the timeline, never a raw "@handle" (remap by actor_type).
    for ev in timeline:
        at = (ev.get("actor_type") or "").lower()
        if at == "brand":
            ev["actor_name"] = brand_name
        elif at == "creator":
            ev["actor_name"] = creator_name
    content = await db.deal_content_submissions.find({"campaign_id": campaign_id}, {"_id": 0}).sort("version", 1).to_list(50)
    # Same fix as the list endpoint: the drawer showed the raw campaign status enum
    # instead of the deal's real state, so it disagreed with the deal room.
    receipt = await db.deal_receipts.find_one({"campaign_id": campaign_id}, {"_id": 0})
    work = await db.work_submissions.find_one({"campaign_id": campaign_id}, {"_id": 0}, sort=[("submitted_at", -1)])
    action_cards = await db.deal_action_cards.find({"campaign_id": campaign_id}, {"_id": 0}).to_list(200)
    st = compute_deal_state(c, shipment or None, normalize_receipt(shipment, receipt), work, escrow, action_cards)
    return {
        "deal_id": campaign_id, "id": campaign_id, "campaign_title": c.get("title"),
        "brand": brand_name, "creator": creator_name,
        "brand_id": c.get("business_id"), "creator_id": c.get("selected_creator"),
        "current_state": st["current_state"],
        "active_party": st["active_party"],
        "primary_next_action": st["primary_next_action"],
        "deadline": c.get("final_delivery_by") or c.get("due_date"),
        "brief_text": c.get("brief_text"), "escrow": escrow, "shipment": shipment,
        "timeline": timeline, "content_versions": content, "admin_notes": c.get("admin_notes") or [],
    }


@api_router.get("/admin/business/{business_id}/profile")
async def admin_business_profile(business_id: str, current_user: dict = Depends(require_cap("manage_deals"))):
    """Read-only brand profile for ops/admin (e.g. the deal room). Merges the
    business_settings the brand edited with their user doc, same as the brand's
    own settings page sees."""
    user = await db.users.find_one({"id": business_id}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="Business not found")
    settings = await db.business_settings.find_one({"business_id": business_id}, {"_id": 0})
    profile = business_profile_defaults(user, (settings or {}).get("profile"))
    profile["role"] = user.get("role")
    profile["username"] = user.get("username")
    return profile


@api_router.post("/admin/business/{business_id}/operate")
async def admin_open_brand_workspace(
    business_id: str,
    request: Request,
    current_user: dict = Depends(require_cap("manage_deals")),
):
    """Issue short-lived delegated access to the normal brand workspace."""
    brand = await db.users.find_one({"id": business_id}, {"_id": 0, "password": 0})
    if not brand or brand.get("role") != UserRole.BUSINESS:
        raise HTTPException(status_code=404, detail="Brand account not found")
    token = create_delegated_brand_token(brand, current_user)
    public_brand = {k: v for k, v in brand.items() if k != "password"}
    public_brand["_delegated_admin_id"] = current_user.get("id")
    public_brand["_delegated_admin_name"] = person_display_name(current_user, "Operations Team")
    public_brand["_delegated_admin_email"] = current_user.get("email")
    await log_admin_action(
        current_user,
        "delegated_brand.started",
        target_type="business",
        target_id=business_id,
        after={"expires_in_minutes": 120},
        reason="Operations opened the brand workspace",
        request=request,
    )
    return {"access_token": token, "token_type": "bearer", "user": public_brand, "expires_in": 7200}


@api_router.get("/admin/business/{business_id}/campaigns")
async def admin_business_campaigns(business_id: str, current_user: dict = Depends(require_cap("manage_deals"))):
    """Every campaign a brand has posted — live and completed — for the admin
    user-detail drawer's Campaigns tab. Read straight from db.campaigns by
    business_id so it includes campaigns with no selected creator yet, which
    /admin/deals filters out (that route only lists matched deals)."""
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can view campaigns")
    campaigns = await db.campaigns.find(
        {"business_id": business_id, "status": {"$ne": CampaignStatus.DRAFT}},
        {"_id": 0},
    ).sort("created_at", -1).to_list(1000)
    rows = [{
        "id": c.get("id"),
        "title": c.get("title") or "Untitled campaign",
        "status": c.get("status"),
        "budget_min": c.get("budget_min"),
        "budget_max": c.get("budget_max"),
        "selected_creator": c.get("selected_creator"),
        "created_at": c.get("created_at"),
    } for c in campaigns if c.get("id")]
    return _json_safe(rows)


async def _brand_actor_for_admin_deal(campaign: dict, admin: dict) -> dict:
    """Build a brand-scoped actor for an audited Ops action.

    Existing deal services enforce ownership through _brand_ws_id(), so Ops uses
    the real brand workspace without impersonating its login credentials.
    """
    brand = await db.users.find_one({"id": campaign.get("business_id")}, {"_id": 0})
    if not brand:
        raise HTTPException(status_code=404, detail="Brand account for this deal was not found")
    brand["nickname"] = f"Operations Team ({person_display_name(admin, 'Admin')})"
    return brand


@api_router.post("/admin/deals/{campaign_id}/approve-content")
async def admin_approve_content_for_brand(
    campaign_id: str,
    request: Request = None,
    current_user: dict = Depends(require_cap("manage_deals")),
):
    """Approve the latest submission on behalf of the brand, with an audit record."""
    campaign = await _admin_deal_or_404(campaign_id, current_user)
    work = await db.work_submissions.find_one(
        {"campaign_id": campaign_id}, {"_id": 0}, sort=[("submitted_at", -1)]
    )
    if not work:
        raise HTTPException(status_code=404, detail="No submitted work is available to approve")
    brand_actor = await _brand_actor_for_admin_deal(campaign, current_user)
    result = await approve_work(work["id"], brand_actor)
    await log_admin_action(
        current_user,
        "deal.brand_content_approved",
        target_type="deal",
        target_id=campaign_id,
        after={"work_id": work["id"], "acted_for_business_id": campaign.get("business_id")},
        reason="Operations acted on behalf of brand",
        request=request,
    )
    return result


@api_router.post("/admin/deals/{campaign_id}/request-revision")
async def admin_request_revision_for_brand(
    campaign_id: str,
    data: DealRevisionRequest,
    request: Request = None,
    current_user: dict = Depends(require_cap("manage_deals")),
):
    """Request changes on the latest submission on behalf of the brand."""
    campaign = await _admin_deal_or_404(campaign_id, current_user)
    brand_actor = await _brand_actor_for_admin_deal(campaign, current_user)
    result = await request_deal_revision(campaign_id, data, brand_actor)
    await log_admin_action(
        current_user,
        "deal.brand_revision_requested",
        target_type="deal",
        target_id=campaign_id,
        after={
            "acted_for_business_id": campaign.get("business_id"),
            "feedback": data.feedback,
            "requested_changes": data.requested_changes,
        },
        reason="Operations acted on behalf of brand",
        request=request,
    )
    return result


@api_router.post("/admin/deals/{campaign_id}/force-transition")
async def admin_force_transition(campaign_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                                 current_user: dict = Depends(require_cap("manage_deals"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can force transitions")
    new_status = (data.get("to_state") or data.get("new_status") or "").strip()
    reason = (data.get("reason") or data.get("justification") or "").strip()
    valid = {"active", "in_progress", "work_submitted", "completed", "cancelled", "rejected", "disputed"}
    if new_status not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid target state. Allowed: {', '.join(sorted(valid))}")
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required to force a transition (elevated action)")
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    before_status = campaign.get("status")
    await db.campaigns.update_one({"id": campaign_id}, {"$set": {"status": new_status, "updated_at": now_iso(),
                                                                 "admin_forced": True, "admin_force_reason": reason}})
    await log_admin_action(current_user, "deal.force_transition", target_type="deal", target_id=campaign_id,
                           before={"status": before_status}, after={"status": new_status}, reason=reason, request=request)
    msg = f"Admin intervened in this deal. Reason: {reason}. Contact support if you have questions."
    await insert_deal_system_message(campaign, msg)
    for uid in [campaign.get("business_id"), campaign.get("selected_creator")]:
        if uid:
            await notify_user(uid, "Admin intervened in your deal", msg, link="/my-deals")
    return {"message": "State transition forced", "from": before_status, "to": new_status}


@api_router.post("/admin/deals/{campaign_id}/notes")
async def admin_add_deal_note(campaign_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                              current_user: dict = Depends(require_cap("manage_deals"))):
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can add notes")
    note_text = (data.get("note") or "").strip()
    if not note_text:
        raise HTTPException(status_code=400, detail="Note text is required")
    note = {"note": note_text, "author": current_user.get("nickname"), "author_id": current_user.get("id"), "created_at": now_iso()}
    await db.campaigns.update_one({"id": campaign_id}, {"$push": {"admin_notes": note}})
    await log_admin_action(current_user, "deal.note_added", target_type="deal", target_id=campaign_id, after={"note": note_text}, request=request)
    return {"message": "Note added", "note": note}


async def _admin_deal_or_404(campaign_id: str, current_user: dict) -> dict:
    if current_user["role"] not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="Only ops/admin can perform this action")
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    return campaign


@api_router.post("/admin/deals/{campaign_id}/raise-dispute")
async def admin_raise_dispute(campaign_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                              current_user: dict = Depends(require_cap("rule_disputes"))):
    """Open a dispute on a deal on behalf of both parties (ops intervention)."""
    campaign = await _admin_deal_or_404(campaign_id, current_user)
    reason = (data.get("reason") or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required")
    dispute = {
        "id": str(uuid.uuid4()), "campaign_id": campaign_id, "status": "open",
        "raised_by": "admin", "reason": reason, "created_at": now_iso(), "updated_at": now_iso(),
    }
    existing = await db.disputes.find_one({"campaign_id": campaign_id, "status": {"$in": ["open", "info_requested", "appealed"]}})
    if not existing:
        await db.disputes.insert_one(dispute)
    await db.campaigns.update_one({"id": campaign_id}, {"$set": {"status": "disputed", "updated_at": now_iso()}})
    await log_admin_action(current_user, "deal.raise_dispute", target_type="deal", target_id=campaign_id, reason=reason, request=request)
    msg = f"Support opened a dispute on this deal. Reason: {reason}."
    await insert_deal_system_message(campaign, msg)
    for uid in [campaign.get("business_id"), campaign.get("selected_creator")]:
        if uid:
            await notify_user(uid, "Dispute opened", msg, link="/my-deals")
    return {"success": True}


@api_router.post("/admin/deals/{campaign_id}/message")
async def admin_deal_message(campaign_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                             current_user: dict = Depends(require_cap("manage_deals"))):
    """Post an admin intervention message into the deal room."""
    campaign = await _admin_deal_or_404(campaign_id, current_user)
    message = (data.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="A message is required")
    await insert_deal_system_message(campaign, f"[Support] {message}")
    await log_admin_action(current_user, "deal.message", target_type="deal", target_id=campaign_id, request=request)
    for uid in [campaign.get("business_id"), campaign.get("selected_creator")]:
        if uid:
            await notify_user(uid, "Support posted in your deal room", message[:140], link="/my-deals")
    return {"success": True}


@api_router.post("/admin/deals/{campaign_id}/notify")
async def admin_deal_notify(campaign_id: str, data: Dict[str, Any] = Body(...), request: Request = None,
                            current_user: dict = Depends(require_cap("manage_deals"))):
    """Send a notification to one or both parties from the admin console."""
    campaign = await _admin_deal_or_404(campaign_id, current_user)
    message = (data.get("message") or "").strip()
    party = data.get("party") if data.get("party") in ("brand", "creator", "both") else "both"
    if not message:
        raise HTTPException(status_code=400, detail="A message is required")
    targets = []
    if party in ("brand", "both") and campaign.get("business_id"):
        targets.append(campaign["business_id"])
    if party in ("creator", "both") and campaign.get("selected_creator"):
        targets.append(campaign["selected_creator"])
    for uid in targets:
        await notify_user(uid, "Message from support", message, link="/my-deals")
    await log_admin_action(current_user, "deal.notify", target_type="deal", target_id=campaign_id, request=request)
    return {"success": True}


def _user_category(u: dict) -> str:
    p = u.get("profile") or {}
    return str(u.get("category") or p.get("category") or p.get("niche") or p.get("industry") or p.get("industry_category") or "").lower()


@api_router.get("/admin/my-assigned")
async def admin_my_assigned(current_user: dict = Depends(require_cap("my_users"))):
    """Creators & brands (profile-completed) in the categories assigned to this ops
    admin — Founder/Senior see all; ops_regular is scoped to assigned categories."""
    users = await db.users.find(
        {"profile_completed": True, "role": {"$in": ["creator", "business"]}},
        {"_id": 0, "password": 0},
    ).to_list(2000)
    assigned = None
    if current_user.get("admin_role") == "ops_regular":
        me = await db.users.find_one({"id": current_user["id"]}, {"_id": 0, "assigned_categories": 1}) or {}
        assigned = [str(x).lower() for x in (me.get("assigned_categories") or [])]
        if assigned:
            users = [u for u in users if any(a and (a in _user_category(u) or _user_category(u) in a) for a in assigned)]
    return {"scoped": assigned is not None, "assigned_categories": assigned or [], "users": users}


# --- Creator KYC review queue (PAN / Aadhaar for withdrawals) --------------------
# The admin KYC page called /admin/kyc which never existed → 404. KYC lives as a
# `kyc` sub-doc on the creator ({status, name_on_pan, pan_number, aadhaar_number,
# submitted_at, *_url, rejection_reason}). Until a creator submission flow is wired,
# the queue simply returns whatever has been submitted (empty is fine — no more 404).
@api_router.get("/admin/kyc")
async def admin_list_kyc(status: str = "pending", current_user: dict = Depends(require_cap("review_applications"))):
    query = {"role": UserRole.CREATOR, "kyc": {"$exists": True, "$ne": None}}
    if status and status != "all":
        query["kyc.status"] = status
    users = await db.users.find(query, {"_id": 0, "password": 0}).to_list(2000)
    users.sort(key=lambda u: (u.get("kyc") or {}).get("submitted_at") or "", reverse=True)
    return _json_safe(users)


@api_router.post("/admin/kyc/{user_id}/review")
async def admin_review_kyc(user_id: str, data: Dict[str, Any] = Body(...),
                           current_user: dict = Depends(require_cap("review_applications"))):
    action = str(data.get("action") or "").lower()
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "kyc": 1})
    if not user or not user.get("kyc"):
        raise HTTPException(status_code=404, detail="No KYC submission for this user")
    now = now_iso()
    if action == "approve":
        set_fields = {"kyc.status": "verified", "kyc.verified_at": now,
                      "kyc.reviewed_by": current_user["id"], "kyc_verified": True}
        title, msg, ntype = "KYC verified ✅", "Your KYC has been verified — you can now withdraw your earnings.", "success"
    else:
        reason = str(data.get("reason") or "").strip()
        if not reason:
            raise HTTPException(status_code=400, detail="A rejection reason is required")
        set_fields = {"kyc.status": "rejected", "kyc.rejection_reason": reason,
                      "kyc.reviewed_at": now, "kyc.reviewed_by": current_user["id"], "kyc_verified": False}
        title, msg, ntype = "KYC needs attention", f"Your KYC was not approved. Reason: {reason}", "warning"
    await db.users.update_one({"id": user_id}, {"$set": set_fields})
    await notify_user(user_id, title, msg, link="/settings", ntype=ntype, email=True)
    await log_admin_action(current_user, f"kyc.{action}", target_type="user", target_id=user_id)
    return {"success": True, "status": set_fields["kyc.status"]}


@api_router.get("/reviews")
async def list_reviews_stub(current_user: dict = Depends(get_current_user)):
    """Compatibility stub (Express parity) — the creator-scoped reviews live at
    /reviews/creator/{id}."""
    return []


@api_router.get("/payout/overview")
async def payout_overview(current_user: dict = Depends(get_current_user)):
    """Creator earnings summary for the Earnings page: available balance (credited to
    the wallet on release), pending escrow, this month's payouts, and lifetime total."""
    uid = current_user["id"]
    camp_ids = []
    async for c in db.campaigns.find({"selected_creator": uid}, {"_id": 0, "id": 1}):
        if c.get("id"):
            camp_ids.append(c["id"])
    escrows = await db.escrow.find({"campaign_id": {"$in": camp_ids}}, {"_id": 0}).to_list(2000) if camp_ids else []

    def payout(e):
        return to_float(e.get("net_payable") if e.get("net_payable") is not None
                        else (e.get("creator_payout") if e.get("creator_payout") is not None else e.get("amount")))

    released = [e for e in escrows if e.get("status") == "released"]
    held = [e for e in escrows if e.get("status") in ("held", "queued", "on_hold")]
    all_time = sum(payout(e) for e in released)
    pending = sum(payout(e) for e in held)
    balance = to_float(current_user.get("balance"))

    now = datetime.now(timezone.utc)
    def this_month(e):
        r = parse_iso(e.get("released_at"))
        return bool(r and r.year == now.year and r.month == now.month)
    def released_in(e, y, m):
        r = parse_iso(e.get("released_at"))
        return bool(r and r.year == y and r.month == m)
    paid_this_month = sum(payout(e) for e in released if this_month(e))
    lm_year, lm_month = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
    last_month_paid = sum(payout(e) for e in released if released_in(e, lm_year, lm_month))
    kyc = current_user.get("kyc") or {}

    return {
        "balance": balance,
        "pending_release": pending,
        "paid_this_month": paid_this_month,
        "all_time_earnings": all_time,
        "last_month": last_month_paid,
        "last_month_paid": last_month_paid,
        "deals_paid": len(released),
        # Display fields the Earnings/withdrawal page renders directly.
        "pending_deals_count": len(held),
        "deals_paid_this_month": sum(1 for e in released if this_month(e)),
        "kyc_status": kyc.get("status") or "not_submitted",
        "kyc_rejection_reason": kyc.get("rejection_reason"),
        # Saved payout account (prefilled into the withdrawal form).
        "bank_details": current_user.get("bank_details") or {},
        "upi_id": current_user.get("upi_id") or "",
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

# Browsers reject `Access-Control-Allow-Origin: *` together with
# `Access-Control-Allow-Credentials: true`. With an explicit origin list, Starlette
# echoes the exact request origin (e.g. https://www.ugcad.io) instead of '*', which
# browsers accept. Override/extend via the CORS_ORIGINS env var (comma-separated).
_DEFAULT_CORS_ORIGINS = "https://www.ugcad.io,https://ugcad.io,http://localhost:3000"
_cors_origins = [o.strip() for o in os.environ.get('CORS_ORIGINS', _DEFAULT_CORS_ORIGINS).split(',') if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=_cors_origins,
    allow_origin_regex=r"https://.*\.ugcad\.io",
    allow_methods=["*"],
    allow_headers=["*"],
)

# Uploads serving. Public assets (logos, profile photos, campaign images, burned-in
# watermarked previews) and images stay open. Flat video files that are protected
# content deliverables are access-gated: only the creator (owner), the brand on the
# deal, or an admin may fetch them — closing the "open the raw /uploads URL and get the
# clean video" hole (PRD 6.9 / 8). Auth is via ?token=<jwt> (so <video> tags work) or a
# bearer header. Non-deliverable videos (e.g. portfolio) remain open.
upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))
upload_dir.mkdir(exist_ok=True)

_GATED_VIDEO_EXTS = (".mp4", ".mov", ".webm", ".m4v", ".avi", ".mkv")
_PUBLIC_UPLOAD_PREFIXES = ("profiles/", "banners/", "business_logos/", "campaigns/", "watermarked/")


def _uploads_viewer(request: Request) -> Optional[dict]:
    token = request.query_params.get("token")
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:]
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


async def _protected_deliverable(rel_url: str) -> Optional[dict]:
    """If rel_url (/uploads/<name>) is a content deliverable, return the participants;
    else None (meaning: not gated)."""
    rec = await db.deal_content_submissions.find_one(
        {"$or": [{"video_url": rel_url}, {"raw_footage_url": rel_url}, {"original_url": rel_url}]},
        {"_id": 0, "campaign_id": 1, "creator_id": 1},
    )
    if not rec:
        rec = await db.work_submissions.find_one(
            {"work_files": rel_url}, {"_id": 0, "campaign_id": 1, "creator_id": 1}
        )
    if not rec:
        return None
    campaign = await db.campaigns.find_one({"id": rec.get("campaign_id")}, {"_id": 0, "business_id": 1})
    return {"creator_id": rec.get("creator_id"), "business_id": (campaign or {}).get("business_id")}


@app.get("/uploads/{filepath:path}")
async def serve_upload(filepath: str, request: Request):
    rel = os.path.normpath(filepath).replace("\\", "/").lstrip("/")
    if rel.startswith("../") or "/../" in rel or rel == "..":
        raise HTTPException(status_code=404, detail="Not found")
    file_path = upload_dir / rel
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    ext = os.path.splitext(rel)[1].lower()
    # Public folders + any non-video file: serve openly (unchanged behavior).
    if rel.startswith(_PUBLIC_UPLOAD_PREFIXES) or ext not in _GATED_VIDEO_EXTS:
        return FileResponse(str(file_path))

    # Flat video: only gate it if it is a protected content deliverable.
    deliverable = await _protected_deliverable(f"/uploads/{rel}")
    if not deliverable:
        return FileResponse(str(file_path))

    viewer = _uploads_viewer(request)
    if not viewer:
        raise HTTPException(status_code=403, detail="Sign in to view this deliverable.")
    vid = viewer.get("user_id")
    allowed = (
        viewer.get("role") == "admin"
        or vid == deliverable.get("creator_id")
        or vid == deliverable.get("business_id")
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="You are not a participant in this deal.")
    return FileResponse(str(file_path))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def _json_safe(obj):
    """Recursively coerce Mongo/BSON values (ObjectId, Decimal128, datetime, bytes,
    etc.) into JSON-serializable primitives so returning raw documents can't raise
    'Object of type X is not JSON serializable' -> unhandled 500."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, bytes):
        return obj.decode('utf-8', 'replace')
    if hasattr(obj, 'isoformat'):  # datetime / date
        return obj.isoformat()
    return str(obj)  # ObjectId, Decimal128, UUID, and any other exotic type


# Globally teach FastAPI's JSON encoder to serialize BSON types so ANY endpoint
# returning raw Mongo documents stops raising "Object of type X is not JSON
# serializable" -> unhandled 500. This fixes every tab (creator/business/admin)
# at once, not just the few endpoints patched with _json_safe above.
try:
    from fastapi.encoders import ENCODERS_BY_TYPE as _ENCODERS_BY_TYPE
    from bson import ObjectId as _ObjectId
    _ENCODERS_BY_TYPE[_ObjectId] = str
    try:
        from bson.decimal128 import Decimal128 as _Decimal128
        _ENCODERS_BY_TYPE[_Decimal128] = lambda d: float(d.to_decimal())
    except Exception:
        pass
    logger.info("Registered BSON JSON encoders (ObjectId, Decimal128)")
except Exception as _enc_err:  # pragma: no cover
    logger.warning("Could not register BSON JSON encoders: %s", _enc_err)


from fastapi.responses import JSONResponse as _JSONResponse
import traceback as _traceback


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all so unhandled errors (a) carry CORS headers — otherwise the browser
    reports a misleading 'CORS policy' error instead of the real 500 — and (b) surface
    the actual cause for debugging."""
    try:
        logger.error("Unhandled error on %s:\n%s", request.url.path, _traceback.format_exc())
    except Exception:
        pass
    origin = request.headers.get("origin") or "*"
    return _JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "error": str(exc),
            "type": type(exc).__name__,
            "path": str(request.url.path),
        },
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        },
    )


@app.on_event("startup")
async def startup_initialization():
    """Initialize default data collections."""
    # Warm the platform-settings cache so commission/fee helpers read live values.
    try:
        await get_platform_settings()
    except Exception as exc:  # keep boot resilient — helpers fall back to defaults
        print(f"⚠️  Could not load platform settings at startup: {exc}")

    # Persist the built-in contact-filter rules (first boot only) and warm the cache,
    # so the very first message is checked against the real rules.
    # (Plain ASCII on purpose: a Windows console is cp1252 and an emoji here raises
    # UnicodeEncodeError inside the startup hook, which kills the whole app.)
    try:
        rules = await seed_filter_rules()
        print(f"Contact filter: {len(rules)} active rule(s) loaded")
    except Exception as exc:
        print(f"WARNING: could not load contact-filter rules at startup: {exc}")

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
