# Backend Development Prompt - Gig Approval System

## Overview
Implement a creator gig submission and admin approval system. Creators can create gigs that require admin approval before going live.

## Database Requirements

### Create `gigs` table with these fields:
```
- id (VARCHAR 50, PRIMARY KEY)
- creator_id (VARCHAR 50, FOREIGN KEY to users)
- title (VARCHAR 255) - Gig title
- description (TEXT) - Full description
- category (VARCHAR 100) - e.g., ugc-videos, product-reviews
- price (DECIMAL 10,2) - Base price in INR
- deliveryTime (VARCHAR 50) - e.g., "7" for 7 days
- gender (VARCHAR 50) - male, female, non-binary, prefer-not-to-say
- nativeLanguage (VARCHAR 100) - Creator's native language
- ageRange (VARCHAR 50) - e.g., 18-25, 26-35, 36-45, 46+
- city (VARCHAR 100) - Creator's city
- niche (VARCHAR 100) - e.g., Beauty, Tech, Fashion
- averageResponseTime (VARCHAR 50) - 1-hour, 2-hour, 4-hour, 24-hour
- videoStyles (JSON) - Array of styles: Professional, Casual, Energetic, etc.
- filmingStyle (JSON) - Array: Smartphone, DSLR, Professional Camera, etc.
- platforms (JSON) - Array: YouTube, Instagram, TikTok, Facebook, LinkedIn, Twitter, Snapchat
- media (JSON) - Array of media URLs (images/videos)
- status (ENUM: pending_approval, approved, rejected) - DEFAULT pending_approval
- rejection_reason (TEXT, nullable) - Reason if rejected
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

### Create indexes on:
- creator_id
- status
- created_at (DESC)
- category

---

## API Endpoints Required

### 1. POST /api/gigs (Create Gig)
**Authentication:** Required (Creator role)

**Request Body:**
```json
{
  "title": "I will create professional UGC videos for your brand",
  "category": "ugc-videos",
  "description": "Detailed description of what I offer...",
  "price": 5000,
  "deliveryTime": "7",
  "gender": "female",
  "nativeLanguage": "English",
  "ageRange": "26-35",
  "city": "Mumbai",
  "niche": "Beauty",
  "averageResponseTime": "4-hour",
  "videoStyles": ["Professional", "Casual"],
  "filmingStyle": ["DSLR", "Smartphone"],
  "platforms": ["YouTube", "Instagram", "TikTok"],
  "media": ["https://example.com/video1.mp4", "https://example.com/image1.jpg"]
}
```

**Response (201):**
```json
{
  "id": "gig_123456",
  "creator_id": "user_789",
  "title": "I will create professional UGC videos for your brand",
  "status": "pending_approval",
  "created_at": "2026-05-20T10:30:00Z"
}
```

**Validation:**
- All fields required except rejection_reason
- price must be > 0
- media array must have at least 1 item
- deliveryTime must be valid (1, 3, 7, 14, 30)
- Status must be set to "pending_approval"

---

### 2. GET /api/gigs (List Gigs)
**Authentication:** Required (Admin sees all, Creator sees own)

**Query Parameters:**
- `status` - Filter: pending_approval, approved, rejected, or blank for all
- `creator_id` - Filter by creator
- `category` - Filter by category
- `limit` - Items per page (default 50)
- `offset` - Pagination offset (default 0)

**Example:** `/api/gigs?status=pending_approval&limit=20`

**Response (200):**
```json
{
  "data": [
    {
      "id": "gig_123456",
      "creator_id": "user_789",
      "creator_name": "Priya Singh",
      "creator_email": "priya@example.com",
      "title": "I will create professional UGC videos",
      "category": "ugc-videos",
      "price": 5000,
      "status": "pending_approval",
      "created_at": "2026-05-20T10:30:00Z"
    }
  ],
  "total": 15,
  "limit": 20,
  "offset": 0
}
```

---

### 3. GET /api/gigs/{id} (Get Single Gig)
**Authentication:** Required

**Response (200):**
```json
{
  "id": "gig_123456",
  "creator_id": "user_789",
  "creator_name": "Priya Singh",
  "creator_email": "priya@example.com",
  "title": "I will create professional UGC videos",
  "description": "Detailed description...",
  "category": "ugc-videos",
  "price": 5000,
  "deliveryTime": "7",
  "gender": "female",
  "nativeLanguage": "English",
  "ageRange": "26-35",
  "city": "Mumbai",
  "niche": "Beauty",
  "averageResponseTime": "4-hour",
  "videoStyles": ["Professional", "Casual"],
  "filmingStyle": ["DSLR", "Smartphone"],
  "platforms": ["YouTube", "Instagram", "TikTok"],
  "media": ["https://...", "https://..."],
  "status": "pending_approval",
  "rejection_reason": null,
  "created_at": "2026-05-20T10:30:00Z",
  "updated_at": "2026-05-20T10:30:00Z"
}
```

---

### 4. PATCH /api/gigs/{id} (Approve/Reject Gig)
**Authentication:** Required (Admin only)

**To Approve:**
```json
{
  "status": "approved"
}
```

**To Reject:**
```json
{
  "status": "rejected",
  "rejection_reason": "Please provide better quality videos and update description with more details"
}
```

**Response (200):**
```json
{
  "id": "gig_123456",
  "status": "approved",
  "rejection_reason": null,
  "updated_at": "2026-05-20T11:00:00Z"
}
```

**Rules:**
- rejection_reason is REQUIRED when status is "rejected"
- Only admin/campaign_manager/support_staff can approve/reject
- Once approved, gig becomes visible to brands
- Rejection reason should be returned to creator

---

## Update Existing Endpoint

### GET /api/campaigns?status=completed&creator_id={user_id}
**Purpose:** Get completed works count for creator level system

**Requirements:**
- Filter campaigns by `status=completed` 
- Filter by `creator_id`
- Used to calculate creator level:
  - New Creator: 0-9 works
  - L1 (Rising): 10-19 works
  - L2 (Pro): 20+ works

**Response should include list of completed campaigns**

---

## Error Handling

Return appropriate HTTP status codes:

- **400 Bad Request** - Validation failed (missing fields, invalid data)
- **401 Unauthorized** - Authentication required
- **403 Forbidden** - Insufficient permissions (e.g., non-admin trying to approve)
- **404 Not Found** - Gig not found
- **500 Internal Server Error** - Server error

**Error Response Format:**
```json
{
  "error": "Error message",
  "details": {
    "field_name": "specific error for field"
  }
}
```

---

## Business Logic

### Gig Status Flow:
1. Creator submits gig → Status: `pending_approval` (not visible to brands)
2. Admin reviews gig details
3. Admin clicks "Approve" → Status: `approved` (gig goes live, visible to brands)
4. OR Admin clicks "Reject" with reason → Status: `rejected` (creator gets feedback)

### Permissions:
- **Creator:** Can create gigs, view own gigs only
- **Admin/Campaign Manager/Support Staff:** Can view all gigs, approve/reject
- **Brand:** Cannot access these endpoints

### Creator Name & Email:
- Join with `users` table to get creator_name and creator_email in list/get responses

---

## Implementation Notes:
- All timestamps should be ISO 8601 format
- Validate creator_id is valid user with creator role
- Consider adding audit log for approval actions (who approved/rejected and when)
- Soft delete is optional (can add deleted_at field)
- Media URLs should be validated as proper URLs
- Use transactions for approval to ensure consistency

---

## Frontend Integration Ready ✓
- Frontend is ready with:
  - Creator Gig creation form (submits to POST /api/gigs)
  - Admin Gig management panel (uses all 4 endpoints above)
  - Creator level system based on completed works count
  - Dynamic badge system (L1 at 10 works, L2 at 20 works)

Once backend is ready, integration will be plug-and-play.
