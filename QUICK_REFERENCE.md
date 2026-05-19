# Applications API - Quick Reference Guide

## Endpoint Cheat Sheet

### Get All Creator Applications (Pending)
```
GET /api/admin/applications/creators?status=pending&page=1&limit=20
Authorization: Bearer <jwt_token>
```
Returns paginated list of pending creator applications with SLA remaining.

### Get All Brand Applications (Flagged)
```
GET /api/admin/applications/brands?flagged=true&page=1
Authorization: Bearer <jwt_token>
```
Returns flagged brands (free email, restricted category, or low trust).

### Get Creator Application Details
```
GET /api/admin/applications/creators/{application_id}
Authorization: Bearer <jwt_token>
```
Returns full application with unmasked PAN, decision history, all documents.

### Request More Information
```
POST /api/admin/applications/{application_id}/request-more-info
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "request_type": "document",
  "message": "Please provide a clearer photo of your PAN card",
  "required_fields": ["kyc_documents.pan", "social_handles.instagram"],
  "deadline_days": 3,
  "priority": "high"
}
```
Response: 200 OK with request_id and notification_sent: true

### Approve Application
```
POST /api/admin/applications/{application_id}/approve
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "notes": "All KYC documents verified. Social handles confirmed. Ready to onboard.",
  "approved_by": "admin_user_id"
}
```
Response: 200 OK with status: approved, approved_at, message

### Reject Application
```
POST /api/admin/applications/{application_id}/reject
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "reason_code": "fraud_detected",
  "reason_details": "Multiple fake social media accounts detected. Unable to verify authenticity.",
  "rejected_by": "admin_user_id"
}
```
Response: 200 OK with status: rejected, reason_code, message

---

## Query Parameter Examples

### Filter by Date Range
```
GET /api/admin/applications/creators
  ?submitted_date_from=2024-01-01T00:00:00Z
  &submitted_date_to=2024-01-31T23:59:59Z
```

### Filter by Status + Category
```
GET /api/admin/applications/creators
  ?status=pending
  &category=fashion
  &limit=50
```

### Get Page 2 of Results
```
GET /api/admin/applications/brands
  ?page=2
  &limit=20
```

---

## Common Error Responses

### 401 Unauthorized (No Token)
```json
{
  "detail": "Not authenticated"
}
```
**Fix:** Add `Authorization: Bearer <jwt_token>` header

### 403 Forbidden (Insufficient Role)
```json
{
  "detail": "Admin access required"
}
```
**Fix:** Use JWT token with role = "admin" or "campaign_manager"

### 404 Not Found
```json
{
  "detail": "Application not found"
}
```
**Fix:** Verify application_id is correct and exists in MongoDB

### 409 Conflict (Invalid Status Transition)
```json
{
  "detail": "Cannot transition from 'approved' to 'rejected'"
}
```
**Fix:** Check valid transitions:
- pending → more_info, approved, rejected
- more_info → pending, rejected
- approved (terminal - cannot change)
- rejected (terminal - cannot change)

---

## Response Fields Reference

### Creator Application
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "nickname": "@handle",
  "email": "creator@example.com",
  "phone": "+91-9876543210",
  "status": "pending|more_info|approved|rejected",
  "submitted_date": "2024-01-15T10:30:00+00:00",
  "sla_remaining_days": 7,
  "sla_due_date": "2024-01-22T10:30:00+00:00",
  "category": "fashion",
  "location": "Mumbai",
  "rate_card": {
    "video_30s": 5000,
    "video_60s": 8000,
    "photo_post": 2000
  },
  "kyc_documents": {
    "pan": {
      "number": "XXXXXX234F",        // Masked in list view
      "verified": true,
      "verified_at": "2024-01-20T10:30:00+00:00"
    }
  },
  "social_handles": {
    "instagram": {
      "followers": 50000,
      "verified": true
    }
  },
  "handle_flagged_as_real_name": false,
  "previous_requests": [
    {
      "type": "document",
      "message": "...",
      "deadline": "2024-01-25T10:30:00+00:00",
      "priority": "high"
    }
  ],
  "decision_history": [
    {
      "action": "pending",
      "decided_by": "admin_id",
      "decided_at": "2024-01-15T10:30:00+00:00"
    }
  ]
}
```

### Brand Application
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "business_name": "Fashion Brand Inc",
  "business_email": "brand@company.com",
  "status": "pending|more_info|approved|rejected",
  "submitted_date": "2024-01-15T10:30:00+00:00",
  "sla_remaining_days": 7,
  "category": "fashion",
  "gst_number": "27AABCT1234F1Z0",
  "gst_verification_status": "verified|pending|failed",
  "flags": {
    "free_email_domain": false,
    "restricted_category": false,
    "agency_rep": false,
    "low_trust_indicators": []
  }
}
```

---

## Common Workflows

### Workflow 1: New Application Arrives
1. Admin sees pending application: `GET /creators?status=pending`
2. Admin views details: `GET /creators/{id}`
3. Admin reviews KYC documents, rate card, social handles
4. If complete → `POST /approve` with notes
5. If incomplete → `POST /request-more-info` with deadline

### Workflow 2: Follow Up on More Info Request
1. Applicant resubmits documents after deadline passes
2. Admin views updated application: `GET /creators/{id}`
3. Admin verifies new documents were provided
4. Admin approves: `POST /approve`
   OR requests again: `POST /request-more-info` with new deadline

### Workflow 3: Reject Suspicious Application
1. Admin suspects fraud: `GET /brands/{id}`
2. Admin reviews social media followers and flags
3. Admin rejects: `POST /reject` with reason_code: "fraud_detected"
4. System syncs rejection to db.users.approval_status = "rejected"
5. Applicant receives in-app notification

### Workflow 4: Bulk Review (Via UI Loop)
1. Get pending applications: `GET /creators?status=pending&limit=50`
2. Loop through each application ID
3. For each:
   - `GET /creators/{id}` to review details
   - `POST /approve` or `POST /request-more-info` or `POST /reject`

---

## Testing with curl

### Get Pending Creators
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  "http://localhost:8000/api/admin/applications/creators?status=pending"
```

### Get Single Application
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  "http://localhost:8000/api/admin/applications/creators/110ebea6-1dde-44e4-9839-0141dfb533d8"
```

### Approve Application
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "notes": "Verified and ready",
    "approved_by": "admin_123"
  }' \
  "http://localhost:8000/api/admin/applications/110ebea6-1dde-44e4-9839-0141dfb533d8/approve"
```

### Request More Info
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "document",
    "message": "Clearer PAN required",
    "required_fields": ["kyc_documents.pan"],
    "deadline_days": 5,
    "priority": "medium"
  }' \
  "http://localhost:8000/api/admin/applications/110ebea6-1dde-44e4-9839-0141dfb533d8/request-more-info"
```

---

## Important Notes

1. **PII Protection:**
   - PAN is masked (XXXXXX234F) in list view
   - PAN is shown in full only in detail view
   - Aadhaar stored as last_4_digits only

2. **Sync to Users:**
   - When you approve/reject an application, `db.users.approval_status` is automatically updated
   - For creators, `creator_directory_visible` is set to `true` on approval

3. **Notifications:**
   - All status changes trigger in-app notification
   - Notifications appear in `db.in_app_notifications`
   - Email/SMS can be added later

4. **SLA:**
   - Automatically calculated as 7 days from submission
   - Returned in every response as `sla_remaining_days`
   - No need to manually track or calculate

5. **Status Immutability:**
   - Once approved or rejected, cannot change status
   - Use `more_info` state for back-and-forth iterations
