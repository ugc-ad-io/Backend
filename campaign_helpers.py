"""
Campaign Helper Functions for validation and backward compatibility
"""
from typing import Dict, Any, List, Optional
from fastapi import HTTPException


def validate_campaign_for_submission(campaign_data: Dict[str, Any]) -> None:
    """
    Validate that a campaign has all required fields for submission.
    Raises HTTPException if validation fails.
    """
    errors = []
    
    # Product Info validation
    if not campaign_data.get('product_name'):
        errors.append("Product name is required")
    if not campaign_data.get('product_category'):
        errors.append("Product category is required")
    if not campaign_data.get('product_description'):
        errors.append("Product description is required")
    
    # Content Requirements validation
    if not campaign_data.get('campaign_hook'):
        errors.append("Campaign hook is required")
    if not campaign_data.get('key_message'):
        errors.append("Key message is required")
    
    # Deliverables validation
    if not campaign_data.get('video_format'):
        errors.append("Video format is required")
    if not campaign_data.get('aspect_ratio'):
        errors.append("Aspect ratio is required")
    if not campaign_data.get('duration_seconds'):
        errors.append("Video duration is required")
    
    # Creator Requirements validation
    if not campaign_data.get('creator_level'):
        errors.append("Creator level is required")
    
    # Budget validation
    if not campaign_data.get('per_video_budget'):
        errors.append("Per video budget is required")
    
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"Campaign validation failed: {'; '.join(errors)}"
        )


def map_legacy_to_new_fields(campaign_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map legacy campaign fields to new extended fields for backward compatibility.
    """
    # Map title to product_name if product_name is missing
    if not campaign_data.get('product_name') and campaign_data.get('title'):
        campaign_data['product_name'] = campaign_data['title']
    
    # Generate brief_text from new fields if missing
    if not campaign_data.get('brief_text'):
        parts = []
        if campaign_data.get('campaign_hook'):
            parts.append(f"Hook: {campaign_data['campaign_hook']}")
        if campaign_data.get('key_message'):
            parts.append(f"Key Message: {campaign_data['key_message']}")
        if campaign_data.get('product_description'):
            parts.append(f"Product: {campaign_data['product_description']}")
        if parts:
            campaign_data['brief_text'] = '\n\n'.join(parts)
    
    # Map per_video_budget to budget_min/budget_max if missing
    if campaign_data.get('per_video_budget'):
        if not campaign_data.get('budget_min'):
            campaign_data['budget_min'] = campaign_data['per_video_budget']
        if not campaign_data.get('budget_max'):
            campaign_data['budget_max'] = campaign_data.get('total_budget') or campaign_data['per_video_budget']
    
    # Map budget_min/budget_max to per_video_budget if missing
    if not campaign_data.get('per_video_budget'):
        if campaign_data.get('budget_min'):
            campaign_data['per_video_budget'] = campaign_data['budget_min']
        elif campaign_data.get('budget_max'):
            campaign_data['per_video_budget'] = campaign_data['budget_max']
    
    # Map shipment fields
    if campaign_data.get('shipment_required') is not None:
        campaign_data['requires_shipment'] = campaign_data['shipment_required']
    elif campaign_data.get('requires_shipment') is not None:
        campaign_data['shipment_required'] = campaign_data['requires_shipment']
    
    # Map free_revisions to revision_limit
    if campaign_data.get('free_revisions') is not None and not campaign_data.get('revision_limit'):
        campaign_data['revision_limit'] = campaign_data['free_revisions']
    elif campaign_data.get('revision_limit') is not None and campaign_data.get('free_revisions') is None:
        campaign_data['free_revisions'] = campaign_data['revision_limit']
    
    # Ensure title exists (required for legacy compatibility)
    if not campaign_data.get('title'):
        campaign_data['title'] = campaign_data.get('product_name') or 'Untitled Campaign'
    
    return campaign_data


def normalize_campaign_response(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize campaign data for API responses, ensuring both old and new fields are present.
    """
    # Apply legacy mapping
    campaign = map_legacy_to_new_fields(campaign)
    
    # Ensure default values for lists
    campaign.setdefault('product_images', [])
    campaign.setdefault('tone_tags', [])
    campaign.setdefault('additional_deliverables', [])
    campaign.setdefault('creator_niche_tags', [])
    campaign.setdefault('objectives', [])
    campaign.setdefault('brief_attachments', [])
    
    # Ensure currency default
    campaign.setdefault('currency', 'INR')
    
    return campaign


def prepare_campaign_for_storage(campaign_data: Dict[str, Any], status: str = 'draft') -> Dict[str, Any]:
    """
    Prepare campaign data for database storage.
    """
    # Apply backward compatibility mapping
    campaign_data = map_legacy_to_new_fields(campaign_data)
    
    # Set status
    campaign_data['status'] = status
    
    # Initialize empty lists if not present
    campaign_data.setdefault('product_images', [])
    campaign_data.setdefault('tone_tags', [])
    campaign_data.setdefault('additional_deliverables', [])
    campaign_data.setdefault('creator_niche_tags', [])
    campaign_data.setdefault('objectives', [])
    campaign_data.setdefault('brief_attachments', [])
    campaign_data.setdefault('bids', [])
    
    # Set defaults
    campaign_data.setdefault('currency', 'INR')
    campaign_data.setdefault('selected_creator', None)
    campaign_data.setdefault('revision_limit', 2)
    
    return campaign_data


def is_draft_campaign(campaign: Dict[str, Any]) -> bool:
    """Check if a campaign is in draft status"""
    return campaign.get('status') == 'draft'


def can_edit_campaign(campaign: Dict[str, Any]) -> bool:
    """Check if a campaign can be edited"""
    return campaign.get('status') in ['draft', 'rejected']


def get_campaign_completion_percentage(campaign: Dict[str, Any]) -> int:
    """
    Calculate the completion percentage of a campaign based on filled fields.
    """
    total_fields = 0
    filled_fields = 0
    
    # Step 1: Product Info (7 fields, but 4 required)
    product_fields = ['product_name', 'product_category', 'product_description', 'product_url']
    for field in product_fields:
        total_fields += 1
        if campaign.get(field):
            filled_fields += 1
    
    # Step 2: Content Requirements (6 fields, but 2 required)
    content_fields = ['campaign_hook', 'key_message', 'what_not_to_do', 'brief_type']
    for field in content_fields:
        total_fields += 1
        if campaign.get(field):
            filled_fields += 1
    
    # Step 3: Deliverables (5 fields, but 3 required)
    deliverable_fields = ['video_format', 'aspect_ratio', 'duration_seconds', 'free_revisions']
    for field in deliverable_fields:
        total_fields += 1
        if campaign.get(field):
            filled_fields += 1
    
    # Step 4: Creator Requirements (5 fields, but 1 required)
    creator_fields = ['creator_level', 'content_quality_tier', 'gender_preference']
    for field in creator_fields:
        total_fields += 1
        if campaign.get(field):
            filled_fields += 1
    
    # Step 5: Budget (1 required field)
    total_fields += 1
    if campaign.get('per_video_budget'):
        filled_fields += 1
    
    return int((filled_fields / total_fields) * 100) if total_fields > 0 else 0
