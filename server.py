from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, UploadFile, File
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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

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
    profile_picture: Optional[str] = None
    banner: Optional[str] = None
    intro_video: Optional[str] = None
    bio: str
    tags: List[str]
    social_links: Dict[str, str]
    portfolio: List[str] = []
    rate_card: Dict[str, Any]
    availability_calendar: Optional[Dict[str, Any]] = None
    payment_methods: Dict[str, str]
    receive_briefs: bool = True
    terms_agreed: bool

class BusinessProfileUpdate(BaseModel):
    logo: Optional[str] = None
    banner: Optional[str] = None
    business_description: str
    website: Optional[str] = None
    social_links: Dict[str, str]
    product_type: str
    industry_category: str

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
    creator_id: str
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

class DealIssueSubmit(BaseModel):
    message: Optional[str] = None
    attachment_urls: List[str] = []

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
    return {
        "revision_count_used": len(revisions),
        "revision_limit": (work or {}).get('revision_limit', 2),
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

async def get_deal_context(deal_id: str, current_user: dict) -> dict:
    campaign = await get_campaign_by_deal_id(deal_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Deal not found")
    ensure_deal_access(campaign, current_user)
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
        "approval_status": ApprovalStatus.PENDING if data.role in [UserRole.CREATOR, UserRole.BUSINESS] else ApprovalStatus.APPROVED,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "balance": 0.0
    }
    
    await db.users.insert_one(user_doc)
    token = create_token(user_id, data.email, data.role)
    
    return {"token": token, "user_id": user_id, "nickname": nickname, "role": data.role}

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
        "role": user['role'],
        "profile_completed": user.get('profile_completed', False),
        "approval_status": user.get('approval_status', ApprovalStatus.PENDING),
        "profile_photo": user.get('profile_photo')
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {k: v for k, v in current_user.items() if k != 'password'}

# Profile Routes
@api_router.put("/profile/creator")
async def update_creator_profile(data: CreatorProfileUpdate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can update creator profile")
    
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
    
    return {"message": "Profile submitted for review"}

@api_router.patch("/profile/portfolio")
async def update_portfolio(portfolio: List[str], current_user: dict = Depends(get_current_user)):
    """Update only the portfolio field without affecting approval status"""
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can update portfolio")
    
    await db.users.update_one(
        {"id": current_user['id']},
        {"$set": {
            "portfolio": portfolio,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {"message": "Portfolio updated successfully"}

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
async def update_profile_info(bio: Optional[str] = None, description: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Update basic profile information without affecting approval status"""
    update_data = {"updated_at": datetime.now(timezone.utc).isoformat()}
    
    if bio is not None:
        update_data["bio"] = bio
    if description is not None:
        update_data["description"] = description
    
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
    
    return user

# Campaign Routes
@api_router.post("/campaigns")
async def create_campaign(data: CampaignCreate, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.BUSINESS:
        raise HTTPException(status_code=403, detail="Only businesses can create campaigns")
    
    if current_user.get('approval_status') != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=403, detail="Your profile must be approved first")
    
    campaign_id = str(uuid.uuid4())
    campaign_doc = {
        "id": campaign_id,
        "business_id": current_user['id'],
        "business_nickname": current_user['nickname'],
        **data.dict(),
        "status": CampaignStatus.PENDING_APPROVAL,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "bids": [],
        "selected_creator": None
    }
    
    await db.campaigns.insert_one(campaign_doc)
    return {"campaign_id": campaign_id, "message": "Campaign submitted for approval"}

@api_router.get("/campaigns")
async def get_campaigns(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {}
    
    if current_user['role'] == UserRole.CREATOR:
        # Creators should see both active campaigns (for browsing) and in_progress campaigns where they are selected
        query = {
            "$or": [
                {"status": CampaignStatus.ACTIVE},
                {"status": CampaignStatus.IN_PROGRESS, "selected_creator": current_user['id']}
            ]
        }
    elif current_user['role'] == UserRole.BUSINESS:
        query['business_id'] = current_user['id']
    elif status:
        query['status'] = status
    
    campaigns = await db.campaigns.find(query, {"_id": 0}).to_list(1000)
    return campaigns

@api_router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, current_user: dict = Depends(get_current_user)):
    campaign = await db.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
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
    # Check content safety
    safety_check = check_content_safety(data.message)
    
    original_message = data.message
    message_filtered = False
    warning_issued = False
    
    if not safety_check["safe"]:
        # Sanitize the message
        data.message = sanitize_message(data.message)
        message_filtered = True
        
        # Log violation
        violation_doc = {
            "id": str(uuid.uuid4()),
            "user_id": current_user['id'],
            "user_nickname": current_user['nickname'],
            "original_message": original_message,
            "filtered_message": data.message,
            "violations": safety_check["violations"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await db.violations.insert_one(violation_doc)
        
        # Update user warning count
        user = await db.users.find_one({"id": current_user['id']})
        warning_count = user.get('warning_count', 0) + 1
        
        await db.users.update_one(
            {"id": current_user['id']},
            {"$set": {
                "warning_count": warning_count,
                "last_warning_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        
        warning_issued = True
        
        # Check if user should be banned (3+ warnings)
        if warning_count >= 3:
            await db.users.update_one(
                {"id": current_user['id']},
                {"$set": {"banned": True, "banned_reason": "Multiple chat policy violations"}}
            )
            raise HTTPException(status_code=403, detail="Account banned for repeated violations")
    
    message_doc = {
        "id": str(uuid.uuid4()),
        "sender_id": current_user['id'],
        "sender_nickname": current_user['nickname'],
        "recipient_id": data.recipient_id,
        "message": data.message,
        "attachment_urls": data.attachment_urls,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read": False,
        "filtered": message_filtered
    }
    
    await db.messages.insert_one(message_doc)
    
    return {
        "message": "Message sent",
        "filtered": message_filtered,
        "warning_issued": warning_issued,
        "warning_count": user.get('warning_count', 0) if warning_issued else None
    }

@api_router.get("/chat/conversations")
async def get_conversations(current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find({
        "$or": [
            {"sender_id": current_user['id']},
            {"recipient_id": current_user['id']}
        ]
    }, {"_id": 0}).to_list(10000)

    # Group by conversation partner and compute unread count per partner
    conversations = {}
    unread_per_partner = {}

    for msg in messages:
        # Skip system messages for conversation grouping
        if msg['sender_id'] == 'system':
            continue

        other_id = msg['recipient_id'] if msg['sender_id'] == current_user['id'] else msg['sender_id']

        # Count unread from this partner
        if msg['sender_id'] == other_id and msg['recipient_id'] == current_user['id'] and not msg.get('read'):
            unread_per_partner[other_id] = unread_per_partner.get(other_id, 0) + 1

        # Update conversation only if this is a newer message
        if other_id not in conversations or msg['timestamp'] > conversations[other_id]['last_message']['timestamp']:
            other_user = await db.users.find_one({"id": other_id}, {"_id": 0, "nickname": 1, "role": 1, "profile_picture": 1})
            if other_user:  # Only add if user exists
                conversations[other_id] = {
                    "user_id": other_id,
                    "nickname": other_user.get('nickname', 'Unknown'),
                    "role": other_user.get('role', ''),
                    "profile_picture": other_user.get('profile_picture'),
                    "last_message": msg,
                    "unread_count": unread_per_partner.get(other_id, 0)
                }

    return list(conversations.values())

@api_router.get("/chat/unread-count")
async def get_unread_count(current_user: dict = Depends(get_current_user)):
    count = await db.messages.count_documents({
        "recipient_id": current_user['id'],
        "read": False
    })
    return {"unread_count": count}

@api_router.get("/chat/warnings")
async def get_user_warnings(current_user: dict = Depends(get_current_user)):
    """Get user's warning count and status"""
    user = await db.users.find_one({"id": current_user['id']}, {"warning_count": 1, "banned": 1, "last_warning_at": 1})
    return {
        "warning_count": user.get('warning_count', 0),
        "banned": user.get('banned', False),
        "last_warning_at": user.get('last_warning_at')
    }

@api_router.get("/chat/{other_user_id}")
async def get_chat_history(other_user_id: str, current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find({
        "$or": [
            {"sender_id": current_user['id'], "recipient_id": other_user_id},
            {"sender_id": other_user_id, "recipient_id": current_user['id']}
        ]
    }, {"_id": 0}).sort("timestamp", 1).to_list(1000)

    for msg in messages:
        msg["attachment_urls"] = msg.get("attachment_urls", [])

    # Mark as read
    await db.messages.update_many(
        {"sender_id": other_user_id, "recipient_id": current_user['id']},
        {"$set": {"read": True}}
    )

    return messages

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
        user1 = await db.users.find_one({"id": conv_data['user1_id']}, {"_id": 0, "nickname": 1, "role": 1})
        user2 = await db.users.find_one({"id": conv_data['user2_id']}, {"_id": 0, "nickname": 1, "role": 1})
        
        # Count violations for this conversation
        violation_count = await db.violations.count_documents({
            "user_id": {"$in": [conv_data['user1_id'], conv_data['user2_id']]}
        })
        
        conversations.append({
            "conversation_id": f"{conv_data['user1_id']}_{conv_data['user2_id']}",
            "user1": {
                "id": conv_data['user1_id'],
                "nickname": user1.get('nickname', 'Unknown') if user1 else 'Unknown',
                "role": user1.get('role', '') if user1 else ''
            },
            "user2": {
                "id": conv_data['user2_id'],
                "nickname": user2.get('nickname', 'Unknown') if user2 else 'Unknown',
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
    
    return messages

# Work Submission Routes
@api_router.post("/work/submit")
async def submit_work(data: WorkSubmission, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != UserRole.CREATOR:
        raise HTTPException(status_code=403, detail="Only creators can submit work")

    campaign = await db.campaigns.find_one({"id": data.campaign_id}, {"_id": 0})
    if not campaign or campaign.get('selected_creator') != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")

    work_doc = {
        "id": str(uuid.uuid4()),
        "campaign_id": data.campaign_id,
        "creator_id": current_user['id'],
        "work_files": data.work_files,
        "description": data.description,
        "status": WorkStatus.SUBMITTED,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
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

@api_router.post("/work/{work_id}/approve")
async def approve_work(work_id: str, current_user: dict = Depends(get_current_user)):
    work = await db.work_submissions.find_one({"id": work_id})
    if not work:
        raise HTTPException(status_code=404, detail="Work not found")
    
    campaign = await db.campaigns.find_one({"id": work['campaign_id']})
    if campaign['business_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Update work status
    await db.work_submissions.update_one(
        {"id": work_id},
        {"$set": {"status": WorkStatus.APPROVED, "approved_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    # Release escrow to creator
    escrow = await db.escrow.find_one({"campaign_id": work['campaign_id']})
    if escrow:
        await db.escrow.update_one(
            {"id": escrow['id']},
            {"$set": {"status": "released", "released_at": datetime.now(timezone.utc).isoformat()}}
        )
        
        # Update creator balance
        await db.users.update_one(
            {"id": work['creator_id']},
            {"$inc": {"balance": escrow['amount']}}
        )
    
    # Update campaign status
    await db.campaigns.update_one(
        {"id": work['campaign_id']},
        {"$set": {"status": CampaignStatus.COMPLETED}}
    )

    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "payment_released", "Work was approved and payment was released.")
    await insert_deal_system_message(campaign, "Work was approved and payment was released.")
    
    return {"message": "Work approved and payment released"}

@api_router.post("/work/{work_id}/request-revision")
async def request_revision(work_id: str, feedback: str, current_user: dict = Depends(get_current_user)):
    work = await db.work_submissions.find_one({"id": work_id})
    if not work:
        raise HTTPException(status_code=404, detail="Work not found")
    
    campaign = await db.campaigns.find_one({"id": work['campaign_id']})
    if campaign['business_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    revision = {
        "feedback": feedback,
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.work_submissions.update_one(
        {"id": work_id},
        {"$set": {"status": WorkStatus.REVISION_REQUESTED}, "$push": {"revisions": revision}}
    )

    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "revision_requested", "Brand requested content revisions.")
    await insert_deal_system_message(campaign, "Brand requested content revisions.")
    
    return {"message": "Revision requested"}

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
        "creator_note": data.creator_note,
        "submitted_at": now_iso(),
        "status": "submitted"
    }
    await db.deal_content_submissions.insert_one(submission)
    work_doc = {
        "id": str(uuid.uuid4()),
        "campaign_id": campaign['id'],
        "creator_id": current_user['id'],
        "work_files": [url for url in [data.video_url, data.caption_url, data.thumbnail_url, data.raw_footage_url] if url],
        "description": data.creator_note or f"Deal content submission v{version}",
        "status": WorkStatus.SUBMITTED,
        "submitted_at": submission['submitted_at'],
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

    return work_submissions

@api_router.get("/work/{work_id}")
async def get_work_by_id(work_id: str, current_user: dict = Depends(get_current_user)):
    """Get a single work submission by ID"""
    work = await db.work_submissions.find_one({"id": work_id}, {"_id": 0})

    if not work:
        raise HTTPException(status_code=404, detail="Work not found")

    # Verify authorization - user must be creator or the business reviewing it
    if current_user['id'] != work['creator_id']:
        campaign = await db.campaigns.find_one({"id": work['campaign_id']})
        if campaign['business_id'] != current_user['id']:
            raise HTTPException(status_code=403, detail="Not authorized to view this work")

    return work

# Review Routes
@api_router.post("/reviews")
async def submit_review(data: ReviewSubmit, current_user: dict = Depends(get_current_user)):
    review_doc = {
        "id": str(uuid.uuid4()),
        "campaign_id": data.campaign_id,
        "creator_id": data.creator_id,
        "reviewer_id": current_user['id'],
        "rating": data.rating,
        "review": data.review,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.reviews.insert_one(review_doc)
    
    # Update creator's average rating
    reviews = await db.reviews.find({"creator_id": data.creator_id}, {"_id": 0}).to_list(1000)
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
    
    await db.shipments.update_one(
        {"campaign_id": data.campaign_id},
        {"$set": shipment_doc},
        upsert=True
    )

    await insert_deal_activity(campaign, "brand", current_user.get('nickname', 'Brand'), "tracking_uploaded", "Shipment tracking was uploaded.")
    await insert_deal_system_message(campaign, "Shipment tracking was uploaded by the brand.")
    
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
    shipment = await db.shipments.find_one({"campaign_id": campaign_id}, {"_id": 0})
    if not shipment:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return shipment

# Withdrawal Routes
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
    
    await db.users.update_one(
        {"id": data.item_id},
        {"$set": {
            "approval_status": status,
            "approval_reason": data.reason,
            "approved_at": datetime.now(timezone.utc).isoformat()
        }}
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
    
    await db.withdrawals.update_one(
        {"id": withdrawal_id},
        {"$set": {
            "status": WithdrawalStatus.COMPLETED,
            "approved_by": current_user['id'],
            "approved_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {"message": "Withdrawal approved successfully"}

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
    """Upload files (videos, images) for profile or portfolio"""
    # Create uploads directory if it doesn't exist
    upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))
    upload_dir.mkdir(exist_ok=True)

    # Validate file type
    allowed_types = [
        'image/jpeg', 'image/png', 'image/jpg', 'image/webp', 'image/gif',
        'video/mp4', 'video/quicktime', 'video/webm', 'video/x-msvideo', 
        'video/mpeg', 'video/3gpp', 'video/x-matroska'
    ]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"File type '{file.content_type}' not allowed. Allowed types: images (JPEG, PNG, WebP, GIF) and videos (MP4, MOV, WebM, AVI, MPEG)")
    
    # Generate unique filename
    file_ext = Path(file.filename).suffix
    unique_filename = f"{current_user['id']}_{uuid.uuid4()}{file_ext}"
    file_path = upload_dir / unique_filename
    
    # Save file
    try:
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)
        
        # Return file URL
        file_url = f"/uploads/{unique_filename}"
        return {"file_url": file_url, "filename": unique_filename}
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
                
                # Update transaction status
                await db.payment_transactions.update_one(
                    {"gateway_order_id": gateway_order_id},
                    {"$set": {
                        "status": "success",
                        "gateway_payment_id": gateway_payment_id,
                        "gateway_signature": gateway_signature,
                        "completed_at": datetime.now(timezone.utc).isoformat()
                    }}
                )
                
                return {
                    "success": True,
                    "message": "Payment verified successfully",
                    "transaction_id": transaction['id']
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
            await db.payment_transactions.update_one(
                {"gateway_order_id": gateway_order_id},
                {"$set": {
                    "status": "success",
                    "gateway_payment_id": gateway_payment_id,
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }}
            )
            
            return {
                "success": True,
                "message": "Payment verified successfully",
                "transaction_id": transaction['id']
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
            
            # Update transaction
            await db.payment_transactions.update_one(
                {"gateway_order_id": order_id},
                {"$set": {
                    "status": "success",
                    "gateway_payment_id": payment_id,
                    "webhook_received": True,
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }}
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
            
            await db.payment_transactions.update_one(
                {"gateway_order_id": order_id},
                {"$set": {
                    "status": "success",
                    "gateway_payment_id": payment_id,
                    "webhook_received": True,
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }}
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

app.include_router(api_router)

# Mount static files for uploads
upload_dir = Path(os.environ.get("UPLOAD_DIR", str(ROOT_DIR / "uploads")))
upload_dir.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(upload_dir)), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
