"""
Extended Campaign Models for 5-step "Post a Brief" flow
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"


class IndustryType(str, Enum):
    SKINCARE = "skincare"
    FASHION = "fashion"
    SERVICES_BASED = "servicesBased"
    HEALTHCARE = "healthcare"
    ELECTRONICS = "electronics"
    FOOD_BEVERAGE = "foodBeverage"


# Step 1: Product Info
class ProductInfo(BaseModel):
    product_name: Optional[str] = None
    product_category: Optional[str] = None
    product_description: Optional[str] = None
    product_url: Optional[str] = None
    product_images: List[str] = []
    shipment_required: Optional[bool] = None
    shipment_notes: Optional[str] = None


# Step 2: Content Requirements
class ContentRequirements(BaseModel):
    brief_type: Optional[str] = None
    campaign_hook: Optional[str] = None
    key_message: Optional[str] = None
    what_not_to_do: Optional[str] = None
    tone_reference: Optional[str] = None
    tone_tags: List[str] = []


# Step 3: Deliverables
class Deliverables(BaseModel):
    video_format: Optional[str] = None
    aspect_ratio: Optional[str] = None
    duration_seconds: Optional[int] = None
    additional_deliverables: List[str] = []
    free_revisions: Optional[int] = None


# Step 4: Creator Requirements
class CreatorRequirements(BaseModel):
    creator_level: Optional[str] = None
    content_quality_tier: Optional[str] = None
    gender_preference: Optional[str] = None
    city_filter: Optional[str] = None
    creator_niche_tags: List[str] = []


# Step 5: Budget & Review
class BudgetReview(BaseModel):
    per_video_budget: Optional[float] = None
    total_budget: Optional[float] = None
    currency: str = "INR"


# Extended Campaign Create Model (supports both old and new fields)
class CampaignCreateExtended(BaseModel):
    # Legacy fields (backward compatibility)
    title: Optional[str] = None
    objectives: Optional[List[str]] = None
    budget_min: Optional[float] = None
    budget_max: Optional[float] = None
    brief_text: Optional[str] = None
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
    requires_shipment: Optional[bool] = None
    shipment_option: Optional[str] = 'no'
    shipment_checklist: Optional[Dict[str, Any]] = None
    
    # New extended fields
    # Step 1: Product Info
    product_name: Optional[str] = None
    product_category: Optional[str] = None
    product_description: Optional[str] = None
    product_url: Optional[str] = None
    product_images: List[str] = []
    shipment_required: Optional[bool] = None
    shipment_notes: Optional[str] = None
    
    # Step 2: Content Requirements
    brief_type: Optional[str] = None
    campaign_hook: Optional[str] = None
    key_message: Optional[str] = None
    what_not_to_do: Optional[str] = None
    tone_reference: Optional[str] = None
    tone_tags: List[str] = []
    
    # Step 3: Deliverables
    video_format: Optional[str] = None
    aspect_ratio: Optional[str] = None
    duration_seconds: Optional[int] = None
    additional_deliverables: List[str] = []
    free_revisions: Optional[int] = None
    
    # Step 4: Creator Requirements
    creator_level: Optional[str] = None
    content_quality_tier: Optional[str] = None
    gender_preference: Optional[str] = None
    city_filter: Optional[str] = None
    creator_niche_tags: List[str] = []
    
    # Step 5: Budget & Review
    per_video_budget: Optional[float] = None
    total_budget: Optional[float] = None
    currency: str = "INR"

    # Status
    status: Optional[str] = None

    # Brand & Image Info (denormalized from business profile)
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    brand_cover_image_url: Optional[str] = None
    business_verified: Optional[bool] = None
    product_image_url: Optional[str] = None

    # Industry classification
    industry_type: Optional[IndustryType] = None


class CampaignDraftCreate(BaseModel):
    """Model for creating draft campaigns - allows partial data"""
    # Any field can be optional for drafts
    title: Optional[str] = None
    objectives: Optional[List[str]] = None
    budget_min: Optional[float] = None
    budget_max: Optional[float] = None
    brief_text: Optional[str] = None

    # New fields
    product_name: Optional[str] = None
    product_category: Optional[str] = None
    product_description: Optional[str] = None
    product_url: Optional[str] = None
    product_images: List[str] = []
    shipment_required: Optional[bool] = None
    shipment_notes: Optional[str] = None

    brief_type: Optional[str] = None
    campaign_hook: Optional[str] = None
    key_message: Optional[str] = None
    what_not_to_do: Optional[str] = None
    tone_reference: Optional[str] = None
    tone_tags: List[str] = []

    video_format: Optional[str] = None
    aspect_ratio: Optional[str] = None
    duration_seconds: Optional[int] = None
    additional_deliverables: List[str] = []
    free_revisions: Optional[int] = None

    creator_level: Optional[str] = None
    content_quality_tier: Optional[str] = None
    gender_preference: Optional[str] = None
    city_filter: Optional[str] = None
    creator_niche_tags: List[str] = []

    per_video_budget: Optional[float] = None
    total_budget: Optional[float] = None
    currency: str = "INR"

    # Brand & Image Info
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    brand_cover_image_url: Optional[str] = None
    business_verified: Optional[bool] = None
    product_image_url: Optional[str] = None

    # Industry classification
    industry_type: Optional[IndustryType] = None


class CampaignUpdate(BaseModel):
    """Model for updating existing campaigns"""
    title: Optional[str] = None
    objectives: Optional[List[str]] = None
    budget_min: Optional[float] = None
    budget_max: Optional[float] = None
    brief_text: Optional[str] = None
    deadline: Optional[str] = None
    due_date: Optional[str] = None

    # New fields
    product_name: Optional[str] = None
    product_category: Optional[str] = None
    product_description: Optional[str] = None
    product_url: Optional[str] = None
    product_images: Optional[List[str]] = None
    shipment_required: Optional[bool] = None
    shipment_notes: Optional[str] = None

    brief_type: Optional[str] = None
    campaign_hook: Optional[str] = None
    key_message: Optional[str] = None
    what_not_to_do: Optional[str] = None
    tone_reference: Optional[str] = None
    tone_tags: Optional[List[str]] = None

    video_format: Optional[str] = None
    aspect_ratio: Optional[str] = None
    duration_seconds: Optional[int] = None
    additional_deliverables: Optional[List[str]] = None
    free_revisions: Optional[int] = None

    creator_level: Optional[str] = None
    content_quality_tier: Optional[str] = None
    gender_preference: Optional[str] = None
    city_filter: Optional[str] = None
    creator_niche_tags: Optional[List[str]] = None

    per_video_budget: Optional[float] = None
    total_budget: Optional[float] = None
    currency: Optional[str] = None

    # Brand & Image Info
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    brand_cover_image_url: Optional[str] = None
    business_verified: Optional[bool] = None
    product_image_url: Optional[str] = None

    # Industry classification
    industry_type: Optional[IndustryType] = None

    # Legacy fields
    requires_shipment: Optional[bool] = None
    shipment_option: Optional[str] = None
    content_requirements: Optional[Dict[str, bool]] = None
    revision_limit: Optional[int] = None
