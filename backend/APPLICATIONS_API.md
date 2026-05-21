# Applications Management API Documentation

## Overview

The Applications Management API provides admin endpoints for reviewing and acting on creator and brand applications with comprehensive filtering, pagination, KYC verification, GST validation, and approval workflows.

## New File: `applications.py`

A self-contained FastAPI module that implements all application management endpoints. Includes:
- 7 REST endpoints for CRUD and approval operations
- Pydantic models for request/response validation
- Helper functions for business logic (SLA, GST validation, PAN masking, handle flagging)
- MongoDB integration via Motor
- JWT authentication and admin authorization

## API Endpoints

### Creator Applications

#### GET `/api/admin/applications/creators`

List all creator applications with filtering and pagination.

**Query Parameters:**
- `status` (optional): `pending`, `more_info`, `approved`, `rejected`
- `category` (optional): Creator category (e.g., `fashion`, `tech`, `food`)
- `submitted_date_from` (optional): ISO date string (filter from)
- `submitted_date_to` (optional): ISO date string (filter to)
- `sort` (optional): Sort field, default `submitted_date`
- `page` (optional, default 1): Page number (1-indexed)
- `limit` (optional, default 20): Results per page (1-100)

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "nickname": "@creator_handle",
      "email": "creator@example.com",
      "status": "pending",
      "submitted_date": "2024-01-15T10:30:00+00:00",
      "sla_remaining_days": 7,
      "kyc_documents": {
        "pan": {
          "number": "XXXXXX234F"  // Masked in list view
        }
      }
    }
  ],
  "total": 150,
  "page": 1,
  "limit": 20
}
```

**PII Masking:** PAN numbers are masked to last 4 digits in list view.

---

#### GET `/api/admin/applications/creators/{id}`

Get full details of a creator application.

**Response:** Full creator application document (same schema as detail response in spec).

**Note:** PAN is NOT masked in detail view (full admin access).

---

### Brand Applications

#### GET `/api/admin/applications/brands`

List all brand applications with filtering and pagination.

**Query Parameters:**
- `status` (optional): `pending`, `more_info`, `approved`, `rejected`
- `category` (optional): Brand category
- `gst_verification_status` (optional): `verified`, `pending`, `failed`
- `submitted_date_from` (optional): ISO date string
- `submitted_date_to` (optional): ISO date string
- `flagged` (optional, boolean): Filter by any flag being true
- `sort` (optional): Sort field, default `submitted_date`
- `page` (optional, default 1): Page number
- `limit` (optional, default 20): Results per page

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "business_name": "Brand Name",
      "status": "pending",
      "gst_verification_status": "verified",
      "sla_remaining_days": 7,
      "flags": {
        "free_email_domain": false,
        "restricted_category": false,
        "agency_rep": false
      }
    }
  ],
  "total": 100,
  "page": 1,
  "limit": 20
}
```

---

#### GET `/api/admin/applications/brands/{id}`

Get full details of a brand application.

---

### Approval Workflow

#### POST `/api/admin/applications/{id}/request-more-info`

Request additional information from applicant.

**Request Body:**
```json
{
  "request_type": "document|clarification|verification",
  "message": "Please provide clearer PAN document",
  "required_fields": ["kyc_documents.pan", "social_handles.instagram"],
  "deadline_days": 3,
  "priority": "high|medium|low"
}
```

**Response:**
```json
{
  "id": "uuid",
  "application_id": "uuid",
  "status": "pending",
  "message": "...",
  "required_fields": [...],
  "deadline": "2024-01-25T10:30:00+00:00",
  "created_at": "2024-01-22T10:30:00+00:00",
  "notification_sent": true
}
```

**Side Effects:**
- Application status → `more_info`
- In-app notification sent to applicant
- Request record appended to `previous_requests` array
- `updated_at` timestamp updated

---

#### POST `/api/admin/applications/{id}/approve`

Approve an application.

**Request Body:**
```json
{
  "notes": "All documents verified, KYC complete",
  "approved_by": "admin_user_id"
}
```

**Response:**
```json
{
  "id": "uuid",
  "status": "approved",
  "approved_at": "2024-01-22T10:30:00+00:00",
  "approved_by": "admin_user_id",
  "message": "Application approved successfully"
}
```

**Side Effects:**
- Application status → `approved`
- `db.users.approval_status` → `approved` (synced to user)
- For creators: `creator_directory_visible` → `true`
- In-app notification sent to applicant
- Decision record appended to `decision_history` array

---

#### POST `/api/admin/applications/{id}/reject`

Reject an application.

**Request Body:**
```json
{
  "reason_code": "invalid_documents|incomplete_kyc|restricted_category|fraud_detected|other",
  "reason_details": "Detailed reason for rejection",
  "rejected_by": "admin_user_id"
}
```

**Response:**
```json
{
  "id": "uuid",
  "status": "rejected",
  "rejected_at": "2024-01-22T10:30:00+00:00",
  "rejected_by": "admin_user_id",
  "reason_code": "invalid_documents",
  "message": "Application rejected successfully"
}
```

**Side Effects:**
- Application status → `rejected`
- `db.users.approval_status` → `rejected` (synced to user)
- In-app notification sent to applicant
- Decision record appended to `decision_history` array with `reason_code`

---

## Business Logic

### Status Workflow

Valid status transitions:
```
pending → more_info → pending → approved/rejected
       ↘ rejected (directly)

approved  (terminal)
rejected  (terminal)
```

Attempting invalid transitions returns **409 Conflict**.

### SLA Management

- **Default SLA:** 7 days from `submitted_date`
- **Remaining:** `max(0, 7 - days_since_submission)`
- **Computed on query** (not stored separately)
- **Warning:** < 2 days remaining should show warning in UI
- **Breach alert:** If no decision after 7 days, flag as "SLA Breach"

### Handle Flagging (Creators)

Detects if creator nickname looks like a real name:
- **Pattern:** `^[A-Z][a-z]+ [A-Z][a-z]+$` (e.g., "John Smith")
- **Stored:** `handle_flagged_as_real_name: bool` + `flag_reason: string`
- **Overrideable:** Admin can manually override the flag

### GST Verification (Brands)

**Format Validation:**
- Regex: `^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$`
- Example: `27AABCT1234F1Z0`

**Verification Status:**
- `verified` (Green badge)
- `pending` (Yellow badge)
- `failed` (Red badge)

**Mock Implementation:**
- Validates GST format via regex
- Returns mock API response with state from state codes
- Stores response in `gst_verification_details` for 30-day cache
- Real GST API can be wired in later

**State Codes:**
- 27 = Maharashtra
- 29 = Karnataka
- 33 = Tamil Nadu
- etc. (See applications.py for full list)

### PII Masking & Security

**PAN (Personal Account Number):**
- List views: Masked to last 4 chars (e.g., `XXXXXX234F`)
- Detail views: Full number shown (admin access only)

**Aadhaar:**
- Stored as `last_4_digits` only (never full number)

**Admin-Only Endpoints:**
- All endpoints require `role: admin` or `role: campaign_manager`
- 403 Forbidden returned if unauthorized

**Audit Trail:**
- All decisions logged in `decision_history` with `decided_by` (admin ID) + `decided_at`
- All info requests logged in `previous_requests` array

### Notifications

When status changes, in-app notification created:

**More Info Requested:**
- Type: `application_more_info`
- Title: "More Information Requested"
- Message: Custom message from admin request

**Approved:**
- Type: `application_approved`
- Title: "Application Approved"
- Message: "Congratulations! Your application has been approved."

**Rejected:**
- Type: `application_rejected`
- Title: "Application Rejected"
- Message: "Your application has been rejected. Reason: {details}"

---

## MongoDB Collections

### creator_applications

```
{
  id: uuid string,
  user_id: uuid string,                    // ref to db.users
  nickname: string,
  email: string,
  phone: string,
  status: "pending|more_info|approved|rejected",
  submitted_date: ISO string,
  category: string,
  languages: [string],
  location: string,
  bio: string,
  profile_picture: url string,
  rate_card: { video_30s, video_60s, photo_post, ... },
  portfolio_videos: [{ id, url, title, duration, thumbnail, views }],
  kyc_documents: {
    pan: { id, url, number, name, verified, verified_at, verification_details },
    aadhaar: { id, url, last_4_digits, verified, verified_at },
    selfie_with_id: { id, url, verified, verified_at, liveness_score }
  },
  social_handles: {
    instagram: { handle, followers, verified, profile_url },
    youtube: { channel_url, subscribers, verified },
    tiktok: { handle, followers, verified },
    twitter: { handle, followers, verified }
  },
  handle_flagged_as_real_name: bool,
  flag_reason: string|null,
  tags: [string],
  sla_due_date: ISO string,
  previous_requests: [{ id, type, message, required_fields, deadline, priority, created_at, resolved_at }],
  decision_history: [{ id, action, reason, reason_code, decided_by, decided_at }],
  created_at: ISO string,
  updated_at: ISO string
}
```

### brand_applications

```
{
  id: uuid string,
  user_id: uuid string,
  business_name: string,
  business_email: string,
  phone: string,
  status: "pending|more_info|approved|rejected",
  submitted_date: ISO string,
  category: string,
  gst_number: string,
  gst_verification_status: "verified|pending|failed",
  gst_verified_at: ISO string|null,
  business_type: string,
  business_description: string,
  industry: string,
  product_type: string,
  website: string,
  website_preview: string|null,
  founded_year: int|null,
  employee_count: string|null,
  flags: { free_email_domain, restricted_category, agency_rep, low_trust_indicators },
  address: { street, city, state, postal_code, country },
  social_media: {
    instagram: { url, followers, verified },
    facebook: { url, followers },
    twitter: { url, followers },
    linkedin: { url, followers }
  },
  gst_verification_details: {},            // mock API response cached
  previous_requests: [...],
  decision_history: [...],
  sla_due_date: ISO string,
  created_at: ISO string,
  updated_at: ISO string
}
```

---

## Error Handling

| Status | Error | Reason |
|--------|-------|--------|
| 400 | Invalid query parameters | Validation error |
| 401 | User not found / Token expired | Authentication failed |
| 403 | Admin access required | Not authorized (insufficient role) |
| 404 | Application not found | Invalid application ID |
| 409 | Cannot transition from X to Y | Invalid status transition |
| 500 | Internal server error | Unhandled exception |

---

## Authentication

All endpoints require a valid JWT bearer token with claims:
- `user_id`: UUID of the user
- `role`: Must be `admin` or `campaign_manager`

**Header:**
```
Authorization: Bearer <jwt_token>
```

Token validation happens in `get_current_user()` dependency, which decodes JWT and fetches full user from `db.users`.

---

## Testing

Run the test suite:
```bash
python test_applications_api.py
```

Tests verify:
- SLA calculation
- Handle real name detection
- PAN masking
- GST number validation
- Status transition validation
- Test data seeding in MongoDB

To manually test endpoints:
1. Start server: `uvicorn server:app --reload`
2. Use Postman/curl with JWT token in Authorization header
3. Example:
   ```
   GET /api/admin/applications/creators?status=pending&page=1&limit=20
   Authorization: Bearer <admin_jwt_token>
   ```

---

## Integration with Existing System

- Leverages existing `db.in_app_notifications` for notifications
- Syncs decisions to `db.users.approval_status` for backward compatibility
- Reuses JWT auth patterns from server.py
- No breaking changes to existing APIs

---

## Future Enhancements

- [ ] Real GST verification API integration
- [ ] Email/SMS notifications in addition to in-app
- [ ] Bulk approval/rejection operations
- [ ] Custom SLA durations per category
- [ ] Document AI for KYC verification
- [ ] Audit log export/reporting
- [ ] Application form customization
