from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import os
import uuid
import jwt
import re
from datetime import datetime, timezone, timedelta

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

applications_router = APIRouter(prefix="/api/admin/applications")
security = HTTPBearer()

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

# ============================================================================
# ENUMS
# ============================================================================

class ApplicationStatus(str, Enum):
    PENDING = "pending"
    MORE_INFO = "more_info"
    APPROVED = "approved"
    REJECTED = "rejected"

class GSTVerificationStatus(str, Enum):
    VERIFIED = "verified"
    PENDING = "pending"
    FAILED = "failed"

class RequestType(str, Enum):
    DOCUMENT = "document"
    CLARIFICATION = "clarification"
    VERIFICATION = "verification"

class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class RejectionReasonCode(str, Enum):
    INVALID_DOCUMENTS = "invalid_documents"
    INCOMPLETE_KYC = "incomplete_kyc"
    RESTRICTED_CATEGORY = "restricted_category"
    FRAUD_DETECTED = "fraud_detected"
    OTHER = "other"

# ============================================================================
# PYDANTIC MODELS - REQUEST/RESPONSE
# ============================================================================

class RequestMoreInfoBody(BaseModel):
    request_type: RequestType
    message: str
    required_fields: List[str] = []
    deadline_days: int = 3
    priority: Priority = Priority.MEDIUM

class ApproveApplicationBody(BaseModel):
    notes: Optional[str] = None
    approved_by: str

class RejectApplicationBody(BaseModel):
    reason_code: RejectionReasonCode
    reason_details: str
    rejected_by: str

class RequestMoreInfoResponse(BaseModel):
    id: str
    application_id: str
    status: str
    message: str
    required_fields: List[str]
    deadline: str
    created_at: str
    notification_sent: bool

class ApprovalResponse(BaseModel):
    id: str
    status: str
    approved_at: str
    approved_by: str
    message: str

class RejectionResponse(BaseModel):
    id: str
    status: str
    rejected_at: str
    rejected_by: str
    reason_code: str
    message: str

# ============================================================================
# AUTH DEPENDENCY
# ============================================================================

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

def require_admin(current_user: dict):
    if current_user.get('role') not in ['admin', 'campaign_manager']:
        raise HTTPException(status_code=403, detail="Admin access required")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None

def calculate_sla_remaining(submitted_date: str, sla_days: int = 7) -> int:
    submitted = parse_iso(submitted_date)
    if not submitted:
        return sla_days
    now = datetime.now(timezone.utc)
    days_elapsed = (now - submitted).days
    return max(0, sla_days - days_elapsed)

def is_handle_real_name(nickname: str) -> bool:
    clean = nickname.lstrip('@')
    pattern = re.compile(r'^[A-Z][a-z]+ [A-Z][a-z]+$')
    return bool(pattern.match(clean))

def mask_pan(pan_number: str) -> str:
    if not pan_number or len(pan_number) < 4:
        return "****"
    return "X" * (len(pan_number) - 4) + pan_number[-4:]

GST_REGEX = r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$'

GST_STATE_CODES = {
    "01": "Jammu & Kashmir", "02": "Himachal Pradesh", "03": "Punjab",
    "04": "Chandigarh", "05": "Uttarakhand", "06": "Haryana",
    "07": "Delhi", "08": "Rajasthan", "09": "Uttar Pradesh",
    "10": "Bihar", "11": "Sikkim", "12": "Arunachal Pradesh",
    "13": "Nagaland", "14": "Manipur", "15": "Mizoram",
    "16": "Tripura", "17": "Meghalaya", "18": "Assam",
    "19": "West Bengal", "20": "Jharkhand", "21": "Odisha",
    "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat",
    "27": "Maharashtra", "28": "Andhra Pradesh", "29": "Karnataka",
    "30": "Goa", "31": "Lakshadweep", "32": "Kerala",
    "33": "Tamil Nadu", "34": "Puducherry", "35": "Andaman & Nicobar",
    "36": "Telangana", "37": "Andhra Pradesh (New)"
}

def validate_gst_number(gst_number: str) -> dict:
    gst_upper = gst_number.upper()
    if not re.match(GST_REGEX, gst_upper):
        return {
            "valid": False,
            "status": GSTVerificationStatus.FAILED,
            "message": "Invalid GST number format"
        }

    state_code = gst_number[:2]
    state = GST_STATE_CODES.get(state_code, "Unknown")

    return {
        "valid": True,
        "status": GSTVerificationStatus.VERIFIED,
        "gstin": gst_upper,
        "state": state,
        "registration_status": "active",
        "verified_at": now_iso()
    }

VALID_STATUS_TRANSITIONS = {
    ApplicationStatus.PENDING: [ApplicationStatus.MORE_INFO, ApplicationStatus.APPROVED, ApplicationStatus.REJECTED],
    ApplicationStatus.MORE_INFO: [ApplicationStatus.PENDING, ApplicationStatus.REJECTED],
    ApplicationStatus.APPROVED: [],
    ApplicationStatus.REJECTED: []
}

def validate_status_transition(current: str, new: str):
    current_status = ApplicationStatus(current)
    new_status = ApplicationStatus(new)
    valid_next = VALID_STATUS_TRANSITIONS.get(current_status, [])
    if new_status not in valid_next:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot transition from '{current}' to '{new}'"
        )

def mask_creator_application_for_list(app: dict) -> dict:
    if app.get('kyc_documents', {}).get('pan', {}).get('number'):
        app['kyc_documents']['pan']['number'] = mask_pan(app['kyc_documents']['pan']['number'])
    return app

# ============================================================================
# ENDPOINTS
# ============================================================================

@applications_router.get("/creators")
async def get_creator_applications(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    submitted_date_from: Optional[str] = Query(None),
    submitted_date_to: Optional[str] = Query(None),
    sort: Optional[str] = Query("submitted_date"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    require_admin(current_user)

    # Build query
    query = {}

    if status:
        query["status"] = status

    if category:
        query["category"] = category

    if submitted_date_from or submitted_date_to:
        query["submitted_date"] = {}
        if submitted_date_from:
            query["submitted_date"]["$gte"] = submitted_date_from
        if submitted_date_to:
            query["submitted_date"]["$lte"] = submitted_date_to

    # Count total
    total = await db.creator_applications.count_documents(query)

    # Fetch with pagination
    skip = (page - 1) * limit
    sort_direction = 1  # ascending (oldest first)

    applications = await db.creator_applications.find(
        query, {"_id": 0}
    ).sort("submitted_date", sort_direction).skip(skip).limit(limit).to_list(limit)

    # Add computed fields and mask PAN
    for app in applications:
        app["sla_remaining_days"] = calculate_sla_remaining(app.get("submitted_date", now_iso()))
        app = mask_creator_application_for_list(app)

    return {"data": applications, "total": total, "page": page, "limit": limit}

@applications_router.get("/brands")
async def get_brand_applications(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    gst_verification_status: Optional[str] = Query(None),
    submitted_date_from: Optional[str] = Query(None),
    submitted_date_to: Optional[str] = Query(None),
    flagged: Optional[bool] = Query(None),
    sort: Optional[str] = Query("submitted_date"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    require_admin(current_user)

    # Build query
    query = {}

    if status:
        query["status"] = status

    if category:
        query["category"] = category

    if gst_verification_status:
        query["gst_verification_status"] = gst_verification_status

    if flagged is not None:
        if flagged:
            query["$or"] = [
                {"flags.free_email_domain": True},
                {"flags.restricted_category": True},
                {"flags.agency_rep": True},
                {"flags.low_trust_indicators": {"$exists": True, "$not": {"$size": 0}}}
            ]

    if submitted_date_from or submitted_date_to:
        query["submitted_date"] = {}
        if submitted_date_from:
            query["submitted_date"]["$gte"] = submitted_date_from
        if submitted_date_to:
            query["submitted_date"]["$lte"] = submitted_date_to

    # Count total
    total = await db.brand_applications.count_documents(query)

    # Fetch with pagination
    skip = (page - 1) * limit
    sort_direction = 1

    applications = await db.brand_applications.find(
        query, {"_id": 0}
    ).sort("submitted_date", sort_direction).skip(skip).limit(limit).to_list(limit)

    # Add computed fields
    for app in applications:
        app["sla_remaining_days"] = calculate_sla_remaining(app.get("submitted_date", now_iso()))

    return {"data": applications, "total": total, "page": page, "limit": limit}

@applications_router.get("/creators/{app_id}")
async def get_creator_application_detail(
    app_id: str,
    current_user: dict = Depends(get_current_user)
):
    require_admin(current_user)

    app = await db.creator_applications.find_one({"id": app_id}, {"_id": 0})

    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    # Add computed fields
    app["sla_remaining_days"] = calculate_sla_remaining(app.get("submitted_date", now_iso()))

    # Add sla_due_date if not present
    if "sla_due_date" not in app:
        submitted = parse_iso(app.get("submitted_date", now_iso()))
        if submitted:
            app["sla_due_date"] = (submitted + timedelta(days=7)).isoformat()

    # In detail view, do NOT mask PAN (admin has full access)

    return app

@applications_router.get("/brands/{app_id}")
async def get_brand_application_detail(
    app_id: str,
    current_user: dict = Depends(get_current_user)
):
    require_admin(current_user)

    app = await db.brand_applications.find_one({"id": app_id}, {"_id": 0})

    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    # Add computed fields
    app["sla_remaining_days"] = calculate_sla_remaining(app.get("submitted_date", now_iso()))

    # Add sla_due_date if not present
    if "sla_due_date" not in app:
        submitted = parse_iso(app.get("submitted_date", now_iso()))
        if submitted:
            app["sla_due_date"] = (submitted + timedelta(days=7)).isoformat()

    return app

@applications_router.post("/{app_id}/request-more-info")
async def request_more_info(
    app_id: str,
    body: RequestMoreInfoBody,
    current_user: dict = Depends(get_current_user)
):
    require_admin(current_user)

    # Find application in creator_applications first, then brand_applications
    app = await db.creator_applications.find_one({"id": app_id}, {"_id": 0})
    is_creator = True

    if not app:
        app = await db.brand_applications.find_one({"id": app_id}, {"_id": 0})
        is_creator = False

    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    # Validate status transition
    validate_status_transition(app.get("status", "pending"), ApplicationStatus.MORE_INFO)

    # Create request document
    request_id = str(uuid.uuid4())
    deadline = datetime.now(timezone.utc) + timedelta(days=body.deadline_days)

    request_doc = {
        "id": request_id,
        "type": body.request_type.value,
        "message": body.message,
        "required_fields": body.required_fields,
        "deadline": deadline.isoformat(),
        "priority": body.priority.value,
        "created_at": now_iso(),
        "resolved_at": None
    }

    # Update application
    collection = db.creator_applications if is_creator else db.brand_applications
    await collection.update_one(
        {"id": app_id},
        {
            "$set": {
                "status": ApplicationStatus.MORE_INFO,
                "updated_at": now_iso()
            },
            "$push": {
                "previous_requests": request_doc
            }
        }
    )

    # Create in-app notification
    notification = {
        "id": str(uuid.uuid4()),
        "user_id": app.get("user_id"),
        "type": "application_more_info",
        "title": "More Information Requested",
        "message": body.message,
        "application_id": app_id,
        "read": False,
        "created_at": now_iso()
    }
    await db.in_app_notifications.insert_one(notification)

    return RequestMoreInfoResponse(
        id=request_id,
        application_id=app_id,
        status="pending",
        message=body.message,
        required_fields=body.required_fields,
        deadline=deadline.isoformat(),
        created_at=now_iso(),
        notification_sent=True
    ).dict()

@applications_router.post("/{app_id}/approve")
async def approve_application(
    app_id: str,
    body: ApproveApplicationBody,
    current_user: dict = Depends(get_current_user)
):
    require_admin(current_user)

    # Find application
    app = await db.creator_applications.find_one({"id": app_id}, {"_id": 0})
    is_creator = True

    if not app:
        app = await db.brand_applications.find_one({"id": app_id}, {"_id": 0})
        is_creator = False

    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    # Validate status transition
    validate_status_transition(app.get("status", "pending"), ApplicationStatus.APPROVED)

    # Create decision record
    decision_id = str(uuid.uuid4())
    decision_doc = {
        "id": decision_id,
        "action": ApplicationStatus.APPROVED,
        "reason": body.notes,
        "reason_code": None,
        "decided_by": body.approved_by,
        "decided_at": now_iso()
    }

    # Update application
    collection = db.creator_applications if is_creator else db.brand_applications
    await collection.update_one(
        {"id": app_id},
        {
            "$set": {
                "status": ApplicationStatus.APPROVED,
                "updated_at": now_iso()
            },
            "$push": {
                "decision_history": decision_doc
            }
        }
    )

    # Sync to db.users
    update_data = {
        "approval_status": "approved",
        "approved_at": now_iso()
    }

    # For creators, also set creator_directory_visible
    if is_creator:
        update_data["creator_directory_visible"] = True

    await db.users.update_one(
        {"id": app.get("user_id")},
        {"$set": update_data}
    )

    # Create in-app notification
    notification = {
        "id": str(uuid.uuid4()),
        "user_id": app.get("user_id"),
        "type": "application_approved",
        "title": "Application Approved",
        "message": "Congratulations! Your application has been approved.",
        "application_id": app_id,
        "read": False,
        "created_at": now_iso()
    }
    await db.in_app_notifications.insert_one(notification)

    return ApprovalResponse(
        id=app_id,
        status=ApplicationStatus.APPROVED,
        approved_at=now_iso(),
        approved_by=body.approved_by,
        message="Application approved successfully"
    ).dict()

@applications_router.post("/{app_id}/reject")
async def reject_application(
    app_id: str,
    body: RejectApplicationBody,
    current_user: dict = Depends(get_current_user)
):
    require_admin(current_user)

    # Find application
    app = await db.creator_applications.find_one({"id": app_id}, {"_id": 0})
    is_creator = True

    if not app:
        app = await db.brand_applications.find_one({"id": app_id}, {"_id": 0})
        is_creator = False

    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    # Validate status transition
    validate_status_transition(app.get("status", "pending"), ApplicationStatus.REJECTED)

    # Create decision record
    decision_id = str(uuid.uuid4())
    decision_doc = {
        "id": decision_id,
        "action": ApplicationStatus.REJECTED,
        "reason": body.reason_details,
        "reason_code": body.reason_code.value,
        "decided_by": body.rejected_by,
        "decided_at": now_iso()
    }

    # Update application
    collection = db.creator_applications if is_creator else db.brand_applications
    await collection.update_one(
        {"id": app_id},
        {
            "$set": {
                "status": ApplicationStatus.REJECTED,
                "updated_at": now_iso()
            },
            "$push": {
                "decision_history": decision_doc
            }
        }
    )

    # Sync to db.users
    await db.users.update_one(
        {"id": app.get("user_id")},
        {"$set": {"approval_status": "rejected"}}
    )

    # Create in-app notification
    notification = {
        "id": str(uuid.uuid4()),
        "user_id": app.get("user_id"),
        "type": "application_rejected",
        "title": "Application Rejected",
        "message": f"Your application has been rejected. Reason: {body.reason_details}",
        "application_id": app_id,
        "read": False,
        "created_at": now_iso()
    }
    await db.in_app_notifications.insert_one(notification)

    return RejectionResponse(
        id=app_id,
        status=ApplicationStatus.REJECTED,
        rejected_at=now_iso(),
        rejected_by=body.rejected_by,
        reason_code=body.reason_code.value,
        message="Application rejected successfully"
    ).dict()
