"""
Campaign Helper Functions for validation and backward compatibility
"""
from typing import Dict, Any, List, Optional
from fastapi import HTTPException
import urllib.parse


def is_valid_url(url: str) -> bool:
    """Validate that a URL has proper HTTP/HTTPS scheme and netloc."""
    try:
        result = urllib.parse.urlparse(url)
        return result.scheme in ('http', 'https') and bool(result.netloc)
    except Exception:
        return False


def _has_value(value: Any) -> bool:
    """Treat blank strings and empty collections as missing."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def validate_campaign_for_submission(campaign_data: Dict[str, Any]) -> None:
    """
    Validate that a campaign has all required fields for submission.
    Raises HTTPException if validation fails.
    """
    required_fields = {
        'title': 'Title is required',
        'product_name': 'Product name is required',
        'product_category': 'Product category is required',
        'product_description': 'Product description is required',
        'campaign_hook': 'Campaign hook is required',
        'key_message': 'Key message is required',
        'video_format': 'Video format is required',
        'aspect_ratio': 'Aspect ratio is required',
        'duration_seconds': 'Video duration is required',
        'creator_level': 'Creator level is required',
        'brief_text': 'Brief text is required',
    }

    field_errors = {
        field: message
        for field, message in required_fields.items()
        if not _has_value(campaign_data.get(field))
    }

    if not (
        _has_value(campaign_data.get('per_video_budget'))
        or _has_value(campaign_data.get('budget_max'))
    ):
        field_errors['per_video_budget'] = 'Per video budget or budget max is required'

    if field_errors:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Campaign validation failed",
                "fields": field_errors,
            }
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

    # Map brand_name fallback: brand_name → business_nickname
    if not campaign_data.get('brand_name') and campaign_data.get('business_nickname'):
        campaign_data['brand_name'] = campaign_data['business_nickname']

    # Map product_image_url from product_images list
    if not campaign_data.get('product_image_url') and campaign_data.get('product_images'):
        images = campaign_data['product_images']
        if images:
            campaign_data['product_image_url'] = images[0]

    # Map cover_image fallback: cover → product_image
    if not campaign_data.get('brand_cover_image_url') and campaign_data.get('product_image_url'):
        campaign_data['brand_cover_image_url'] = campaign_data['product_image_url']

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
    # Structured brief section lists
    campaign.setdefault('deliverable_items', [])
    campaign.setdefault('required_phrases', [])
    campaign.setdefault('required_shots', [])
    campaign.setdefault('reference_videos', [])
    campaign.setdefault('mood_images', [])
    campaign.setdefault('usage_platforms', [])

    # Ensure currency default
    campaign.setdefault('currency', 'INR')

    # Add response-facing aliases for brand/image fields
    campaign['brand_logo'] = campaign.get('brand_logo_url') or ''
    campaign['cover_image'] = campaign.get('brand_cover_image_url') or campaign.get('product_image_url') or ''
    campaign['product_image'] = campaign.get('product_image_url') or ''
    campaign['brand_handle'] = f"@{campaign['business_nickname']}" if campaign.get('business_nickname') else ''
    campaign.setdefault('business_verified', False)
    campaign.setdefault('brand_name', campaign.get('business_nickname', ''))

    # Ensure brief_text fallback
    if not campaign.get('brief_text'):
        campaign['brief_text'] = 'No brief description provided.'

    # Default industry_type to null if not set
    campaign.setdefault('industry_type', None)

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
    # Structured brief section lists
    campaign_data.setdefault('deliverable_items', [])
    campaign_data.setdefault('required_phrases', [])
    campaign_data.setdefault('required_shots', [])
    campaign_data.setdefault('reference_videos', [])
    campaign_data.setdefault('mood_images', [])
    campaign_data.setdefault('usage_platforms', [])
    
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
    Calculate the completion percentage of a brief across the 8 sections of the
    "Post a Brief" template. Each section is weighted equally (one section = one
    point) and a section counts as complete when its key fields are present.
    """
    sections_complete = 0
    total_sections = 8

    # Section 1: Campaign Basics
    if all(campaign.get(f) for f in ['title', 'product_name', 'product_description', 'campaign_hook', 'key_message', 'product_category']) and campaign.get('objectives') and campaign.get('target_audience'):
        sections_complete += 1

    # Section 2: Deliverables
    if campaign.get('deliverable_items') or (campaign.get('video_format') and campaign.get('aspect_ratio')):
        sections_complete += 1

    # Section 3: Must-Include
    if campaign.get('call_to_action'):
        sections_complete += 1

    # Section 4: Must-Avoid (guidance section; complete once any avoid rule or text is set)
    if any(campaign.get(f) for f in ['no_competitors', 'no_other_products', 'no_profanity', 'no_political', 'avoid_filters', 'avoid_text', 'what_not_to_do']):
        sections_complete += 1

    # Section 5: Style Guidance
    if campaign.get('tone_tags') and (campaign.get('pacing') or campaign.get('tone_reference')):
        sections_complete += 1

    # Section 6: Usage Rights
    if campaign.get('usage_platforms') and campaign.get('rights_duration') and campaign.get('exclusivity') and campaign.get('modification_rights'):
        sections_complete += 1

    # Section 7: Timeline & Budget
    if (campaign.get('per_video_budget') or campaign.get('budget_max')) and campaign.get('creator_level') and campaign.get('final_delivery_by'):
        sections_complete += 1

    # Section 8: Review & Publish (complete once the brief has been submitted out of draft)
    if campaign.get('status') and campaign.get('status') != 'draft':
        sections_complete += 1

    return int((sections_complete / total_sections) * 100) if total_sections > 0 else 0
