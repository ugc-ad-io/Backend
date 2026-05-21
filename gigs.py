"""
Gigs Management Module for UGCad Platform.
Handles creation, listing, and approval of gigs by creators and admins.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from enum import Enum
import os
import uuid
import jwt
from datetime import datetime, timezone
from bson import ObjectId

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

gigs_router = APIRouter(prefix="/api/gigs")
security = HTTPBearer()

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
BASE_URL = os.environ.get('BASE_URL', 'https://backend-chq9.onrender.com')

# ============================================================================
# ENUMS
# ============================================================================

class GigCategory(str, Enum):
    SOCIAL_MEDIA = "social_media"
    PRODUCT_REVIEW = "product_review"
    UNBOXING = "unboxing"
    TUTORIAL = "tutorial"
    SPONSORSHIP = "sponsorship"
    BRAND_AMBASSADOR = "brand_ambassador"
    CONTENT_CREATION = "content_creation"
    PHOTOGRAPHY = "photography"
    VIDEOGRAPHY = "videography"
    OTHER = "other"

class GigStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

# ============================================================================
# PYDANTIC MODELS - REQUEST/RESPONSE
# ============================================================================

class GigCreateRequest(BaseModel):
    title: str = Field(..., min_length=5, max_length=100)
    description: str = Field(..., min_length=20, max_length=5000)
    category: GigCategory
    budget: float = Field(..., gt=0)
    deadline: datetime
    attachments: Optional[List[str]] = []
    requirements: Optional[str] = Field(None, max_length=2000)
    target_audience: Optional[str] = Field(None, max_length=500)
    skills_required: Optional[List[str]] = []

    @validator('deadline')
    def deadline_must_be_future(cls, v):
        if v <= datetime.now(timezone.utc):
            raise ValueError('Deadline must be in the future')
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Create Instagram Reels",
                "description": "Create engaging Instagram reels for our fashion brand. Must include product shots.",
                "category": "social_media",
                "budget": 500,
                "deadline": "2026-06-20T23:59:59Z",
                "attachments": ["https://example.com/image.jpg"],
                "requirements": "Must include product shots and trending music",
                "target_audience": "Women 18-35",
                "skills_required": ["Video Editing", "Creative Content"]
            }
        }

class GigResponse(BaseModel):
    id: str
    title: str
    description: str
    category: str
    budget: float
    deadline: str
    status: str
    creator_id: str
    creator_name: Optional[str] = None
    creator_email: Optional[str] = None
    public_creator_id: Optional[str] = None
    creator_avg_rating: Optional[float] = 0.0
    creator_total_reviews: Optional[int] = 0
    attachments: List[str]
    requirements: Optional[str]
    target_audience: Optional[str]
    skills_required: List[str]
    applications_count: int
    selected_creator_id: Optional[str] = None
    rejection_reason: Optional[str] = None
    created_at: str
    updated_at: str

class GigListResponse(BaseModel):
    data: List[GigResponse]
    pagination: Dict[str, Any]

class ApproveGigRequest(BaseModel):
    status: str = "approved"
    notes: Optional[str] = None

class RejectGigRequest(BaseModel):
    status: str = "rejected"
    rejection_reason: str = Field(..., min_length=10, max_length=1000)

class GigApprovalResponse(BaseModel):
    id: str
    status: str
    message: str
    approved_at: str
    approved_by: str

class GigRejectionResponse(BaseModel):
    id: str
    status: str
    message: str
    rejected_at: str
    rejected_by: str
    rejection_reason: str

# ============================================================================
# AUTHENTICATION HELPERS
# ============================================================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token and return user data"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id") or payload.get("id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = await db.users.find_one({"id": user_id}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(user: dict = Depends(get_current_user)) -> dict:
    """Verify user is admin"""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def normalize_gig_response(gig: dict, creator_info: dict = None) -> GigResponse:
    """Convert MongoDB gig to response format"""
    # Convert attachment URLs to use /api/image/ endpoint which has proper CORS
    attachments = []
    for attachment in (gig.get("attachments", []) or []):
        if attachment.startswith('http'):
            # Extract filename from full URL and convert to /api/image/ endpoint
            filename = attachment.split('/')[-1]
            attachments.append(f"{BASE_URL}/api/image/{filename}")
        else:
            # Already just filename
            attachments.append(f"{BASE_URL}/api/image/{attachment}")

    return GigResponse(
        id=gig.get("id"),
        title=gig.get("title"),
        description=gig.get("description"),
        category=gig.get("category"),
        budget=gig.get("budget"),
        deadline=gig.get("deadline"),
        status=gig.get("status"),
        creator_id=gig.get("creator_id"),
        creator_name=creator_info.get("name") if creator_info else None,
        creator_email=creator_info.get("email") if creator_info else None,
        public_creator_id=creator_info.get("public_creator_id") if creator_info else None,
        creator_avg_rating=float(creator_info.get("average_rating") or 0) if creator_info else 0.0,
        creator_total_reviews=int(creator_info.get("total_reviews") or 0) if creator_info else 0,
        attachments=attachments,
        requirements=gig.get("requirements"),
        target_audience=gig.get("target_audience"),
        skills_required=gig.get("skills_required", []),
        applications_count=gig.get("applications_count", 0),
        selected_creator_id=gig.get("selected_creator_id"),
        rejection_reason=gig.get("rejection_reason"),
        created_at=gig.get("created_at"),
        updated_at=gig.get("updated_at")
    )

# ============================================================================
# API ENDPOINTS
# ============================================================================

@gigs_router.post("/", response_model=GigResponse, status_code=201)
async def create_gig(
    gig_data: GigCreateRequest,
    current_user: dict = Depends(get_current_user)
) -> GigResponse:
    """
    Create a new gig (requires authentication).
    Creator submits gig with status set to pending_approval.

    Args:
        gig_data: Gig creation data
        current_user: Current authenticated user

    Returns:
        Created gig with PENDING_APPROVAL status
    """
    gig_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Store attachment URLs as-is (frontend expects full URLs)
    attachments = gig_data.attachments or []

    gig = {
        "id": gig_id,
        "title": gig_data.title,
        "description": gig_data.description,
        "category": gig_data.category.value,
        "budget": gig_data.budget,
        "deadline": gig_data.deadline.isoformat(),
        "status": GigStatus.PENDING_APPROVAL.value,
        "creator_id": current_user.get("id"),
        "attachments": attachments,
        "requirements": gig_data.requirements,
        "target_audience": gig_data.target_audience,
        "skills_required": gig_data.skills_required or [],
        "applications_count": 0,
        "selected_creator_id": None,
        "rejection_reason": None,
        "created_at": now,
        "updated_at": now
    }

    await db.gigs.insert_one(gig)

    return normalize_gig_response(gig, {
        "name": current_user.get("name"),
        "email": current_user.get("email")
    })

@gigs_router.get("/", response_model=GigListResponse)
async def list_gigs(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    creator_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None)
) -> GigListResponse:
    """
    List all gigs with filters.

    Args:
        status: Filter by gig status (pending_approval, approved, rejected, etc.)
        category: Filter by category
        creator_id: Filter by creator ID
        page: Page number (default: 1)
        limit: Results per page (default: 10, max: 100)
        search: Search in title and description

    Returns:
        Paginated list of gigs with metadata
    """
    # Build filter
    filter_dict = {}

    if status:
        filter_dict["status"] = status
    if category:
        filter_dict["category"] = category
    if creator_id:
        filter_dict["creator_id"] = creator_id

    if search:
        filter_dict["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]

    # Calculate pagination
    skip = (page - 1) * limit

    # Fetch gigs
    gigs_cursor = db.gigs.find(filter_dict).skip(skip).limit(limit).sort("created_at", -1)
    gigs = await gigs_cursor.to_list(length=limit)

    # Count total
    total = await db.gigs.count_documents(filter_dict)

    # Get creator info for each gig
    gig_responses = []
    for gig in gigs:
        creator = await db.users.find_one({"id": gig.get("creator_id")}, {"_id": 0, "name": 1, "email": 1, "public_creator_id": 1, "average_rating": 1, "total_reviews": 1})
        gig_responses.append(normalize_gig_response(gig, creator or {}))

    return GigListResponse(
        data=gig_responses,
        pagination={
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit
        }
    )

@gigs_router.get("/{gig_id}", response_model=GigResponse)
async def get_gig(gig_id: str) -> GigResponse:
    """
    Get single gig details.

    Args:
        gig_id: Gig ID

    Returns:
        Complete gig details with creator information
    """
    gig = await db.gigs.find_one({"id": gig_id}, {"_id": 0})

    if not gig:
        raise HTTPException(status_code=404, detail="Gig not found")

    # Get creator info
    creator = await db.users.find_one({"id": gig.get("creator_id")}, {"_id": 0, "name": 1, "email": 1, "public_creator_id": 1, "average_rating": 1, "total_reviews": 1})

    response = normalize_gig_response(gig, creator or {})

    # Debug: Print attachment URLs being returned
    print(f"[DEBUG] Gig {gig_id} returning attachments: {response.attachments}")

    return response

@gigs_router.patch("/{gig_id}", status_code=200)
async def update_gig_status(
    gig_id: str,
    action: str = Query(..., regex="^(approve|reject)$"),
    approval_data: Optional[ApproveGigRequest] = None,
    rejection_data: Optional[RejectGigRequest] = None,
    current_user: dict = Depends(get_admin_user)
) -> Dict[str, Any]:
    """
    Update gig status (Admin only).
    Approve or reject pending gigs.

    Args:
        gig_id: Gig ID to update
        action: Action type (approve or reject)
        approval_data: Data for approval
        rejection_data: Data for rejection (required for rejection)
        current_user: Admin user

    Returns:
        Updated gig with new status
    """
    # Find gig
    gig = await db.gigs.find_one({"id": gig_id}, {"_id": 0})

    if not gig:
        raise HTTPException(status_code=404, detail="Gig not found")

    # Check if gig is pending
    if gig.get("status") != GigStatus.PENDING_APPROVAL.value:
        raise HTTPException(
            status_code=400,
            detail=f"Can only update gigs with {GigStatus.PENDING_APPROVAL.value} status"
        )

    now = datetime.now(timezone.utc).isoformat()
    update_data = {"updated_at": now}

    if action == "approve":
        update_data["status"] = GigStatus.APPROVED.value
        update_data["approved_at"] = now
        update_data["approved_by"] = current_user.get("id")
        if approval_data and approval_data.notes:
            update_data["notes"] = approval_data.notes

        await db.gigs.update_one({"id": gig_id}, {"$set": update_data})

        updated_gig = await db.gigs.find_one({"id": gig_id}, {"_id": 0})

        return {
            "success": True,
            "message": "Gig approved successfully",
            "data": normalize_gig_response(updated_gig)
        }

    elif action == "reject":
        if not rejection_data or not rejection_data.rejection_reason:
            raise HTTPException(status_code=400, detail="Rejection reason is required")

        update_data["status"] = GigStatus.REJECTED.value
        update_data["rejected_at"] = now
        update_data["rejected_by"] = current_user.get("id")
        update_data["rejection_reason"] = rejection_data.rejection_reason

        await db.gigs.update_one({"id": gig_id}, {"$set": update_data})

        updated_gig = await db.gigs.find_one({"id": gig_id}, {"_id": 0})

        return {
            "success": True,
            "message": "Gig rejected successfully",
            "data": normalize_gig_response(updated_gig)
        }

@gigs_router.get("/creator/{creator_id}")
async def get_creator_gigs(
    creator_id: str,
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100)
) -> GigListResponse:
    """
    Get all gigs by a specific creator.

    Args:
        creator_id: Creator's user ID
        status: Optional status filter
        page: Page number
        limit: Results per page

    Returns:
        Paginated list of creator's gigs
    """
    # Build filter
    filter_dict = {"creator_id": creator_id}
    if status:
        filter_dict["status"] = status

    # Calculate pagination
    skip = (page - 1) * limit

    # Fetch gigs
    gigs_cursor = db.gigs.find(filter_dict).skip(skip).limit(limit).sort("created_at", -1)
    gigs = await gigs_cursor.to_list(length=limit)

    # Count total
    total = await db.gigs.count_documents(filter_dict)

    # Get creator info
    creator = await db.users.find_one({"id": creator_id}, {"_id": 0, "name": 1, "email": 1, "public_creator_id": 1, "average_rating": 1, "total_reviews": 1})

    gig_responses = [normalize_gig_response(gig, creator or {}) for gig in gigs]

    return GigListResponse(
        data=gig_responses,
        pagination={
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit
        }
    )
