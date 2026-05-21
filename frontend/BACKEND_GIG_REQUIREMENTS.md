# Backend Requirements - Gig Approval System

## Database Schema

### Gigs Table
```sql
CREATE TABLE gigs (
  id VARCHAR(50) PRIMARY KEY,
  creator_id VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  category VARCHAR(100),
  price DECIMAL(10, 2),
  deliveryTime VARCHAR(50),
  
  -- Personal Info
  gender VARCHAR(50),
  nativeLanguage VARCHAR(100),
  ageRange VARCHAR(50),
  city VARCHAR(100),
  niche VARCHAR(100),
  averageResponseTime VARCHAR(50),
  
  -- Content Details (JSON arrays)
  videoStyles JSON,
  filmingStyle JSON,
  platforms JSON,
  
  -- Media
  media JSON,
  
  -- Status & Approval
  status ENUM('pending_approval', 'approved', 'rejected') DEFAULT 'pending_approval',
  rejection_reason TEXT,
  
  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_creator_id (creator_id),
  INDEX idx_status (status),
  INDEX idx_created_at (created_at)
);
```

## API Endpoints

### 1. Create Gig
**Endpoint:** `POST /api/gigs`  
**Auth:** Required (Creator only)  
**Request Body:**
```json
{
  "title": "I will create professional UGC videos",
  "category": "ugc-videos",
  "description": "Create high-quality UGC content...",
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
  "media": ["https://...", "https://..."]
}
```
**Response:**
```json
{
  "id": "gig_123456",
  "creator_id": "user_789",
  "title": "I will create professional UGC videos",
  "status": "pending_approval",
  "created_at": "2026-05-20T10:30:00Z"
}
```
**Status:** 201 Created

---

### 2. Get All Gigs (with filters)
**Endpoint:** `GET /api/gigs`  
**Auth:** Optional (Admin can see all, Creator sees own)  
**Query Parameters:**
- `status` - Filter by status (pending_approval, approved, rejected)
- `creator_id` - Filter by creator
- `category` - Filter by category
- `limit` - Results per page (default: 50)
- `offset` - Pagination offset (default: 0)

**Example:** `GET /api/gigs?status=pending_approval`

**Response:**
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
  "limit": 50,
  "offset": 0
}
```

---

### 3. Get Single Gig
**Endpoint:** `GET /api/gigs/{id}`  
**Auth:** Required  
**Response:**
```json
{
  "id": "gig_123456",
  "creator_id": "user_789",
  "creator_name": "Priya Singh",
  "creator_email": "priya@example.com",
  "title": "I will create professional UGC videos",
  "description": "Create high-quality UGC content...",
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

### 4. Approve/Reject Gig
**Endpoint:** `PATCH /api/gigs/{id}`  
**Auth:** Required (Admin only)  
**Request Body (Approve):**
```json
{
  "status": "approved"
}
```

**Request Body (Reject):**
```json
{
  "status": "rejected",
  "rejection_reason": "Please provide better quality videos and update your description"
}
```

**Response:**
```json
{
  "id": "gig_123456",
  "status": "approved",
  "updated_at": "2026-05-20T11:00:00Z"
}
```

---

## Existing Endpoints to Update

### Get Campaigns (for Level System)
**Endpoint:** `GET /api/campaigns?status=completed&creator_id={user_id}`  
**Purpose:** Get count of completed works for creator level calculation  
**Required:** Filter by status='completed' and creator_id

**Response should include:**
```json
[
  {
    "id": "campaign_123",
    "title": "UGC Video for Product",
    "status": "completed",
    "selected_creator": "user_789"
  },
  // ... more completed campaigns
]
```

---

## Business Logic

### Status Flow:
1. Creator submits gig → Status: `pending_approval`
2. Admin reviews gig
3. If approved → Status: `approved` (gig goes live)
4. If rejected → Status: `rejected` + `rejection_reason` sent to creator

### Validation Rules:
- All required fields must be provided during creation
- Price must be > 0
- Delivery time must be valid (1, 3, 7, 14, 30)
- Media array must have at least 1 item
- Status can only be changed by admin
- Rejection reason is required when rejecting

### Permissions:
- **Creator:** Can create gigs, view own gigs
- **Admin:** Can view all gigs, approve/reject any gig
- **Brand/Other:** Cannot access gig creation/approval endpoints

---

## Database Indexes Needed:
```sql
CREATE INDEX idx_gigs_creator_id ON gigs(creator_id);
CREATE INDEX idx_gigs_status ON gigs(status);
CREATE INDEX idx_gigs_created_at ON gigs(created_at DESC);
CREATE INDEX idx_gigs_category ON gigs(category);
```

---

## Error Responses:

### 400 Bad Request
```json
{
  "error": "Validation failed",
  "details": {
    "title": "Title is required",
    "media": "At least 1 image/video required"
  }
}
```

### 401 Unauthorized
```json
{
  "error": "Authentication required"
}
```

### 403 Forbidden
```json
{
  "error": "Only admin can approve gigs"
}
```

### 404 Not Found
```json
{
  "error": "Gig not found"
}
```

---

## Notes:
- All timestamps should be ISO 8601 format
- Creator name and email should be fetched from users table in responses
- Media URLs should be validated URLs
- Soft delete is optional (can add deleted_at field)
- Consider adding audit log for all approval actions
