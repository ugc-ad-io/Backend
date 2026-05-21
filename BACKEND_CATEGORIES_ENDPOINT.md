# Backend Implementation: Categories Endpoint

## Overview
Implement a categories endpoint for the UGCad brand platform. Categories represent different types of UGC content/services that brands can request from creators (e.g., UGC Videos, Product Reviews, Testimonials, etc.).

## Endpoint Details

### 1. GET All Categories (Public/Protected)
```
Method: GET
Path: /api/categories
Authentication: Optional (Bearer Token)
```

**Response Format:**
```json
[
  {
    "id": "ugc-videos",
    "name": "UGC Videos",
    "description": "Professional user-generated content videos for your products",
    "icon": "video",
    "active": true,
    "order": 1
  },
  {
    "id": "product-reviews",
    "name": "Product Reviews",
    "description": "Authentic product review videos and testimonials",
    "icon": "star",
    "active": true,
    "order": 2
  },
  {
    "id": "unboxing",
    "name": "Unboxing Videos",
    "description": "Unboxing and first impression videos",
    "icon": "gift",
    "active": true,
    "order": 3
  },
  {
    "id": "testimonials",
    "name": "Testimonials",
    "description": "Customer testimonial and success stories",
    "icon": "message-circle",
    "active": true,
    "order": 4
  },
  {
    "id": "demo-videos",
    "name": "Demo Videos",
    "description": "Product demonstration and how-to videos",
    "icon": "play-circle",
    "active": true,
    "order": 5
  },
  {
    "id": "social-content",
    "name": "Social Media Content",
    "description": "Short-form content for Instagram, TikTok, Reels",
    "icon": "share-2",
    "active": true,
    "order": 6
  },
  {
    "id": "lifestyle",
    "name": "Lifestyle Content",
    "description": "Lifestyle integration and day-to-day usage videos",
    "icon": "heart",
    "active": true,
    "order": 7
  },
  {
    "id": "comparison",
    "name": "Product Comparison",
    "description": "Comparison videos with competitor products",
    "icon": "trending-up",
    "active": true,
    "order": 8
  },
  {
    "id": "tutorials",
    "name": "Tutorials & Tips",
    "description": "Tutorial videos and pro tips for your product",
    "icon": "book",
    "active": true,
    "order": 9
  },
  {
    "id": "behind-scenes",
    "name": "Behind the Scenes",
    "description": "Behind-the-scenes and manufacturing process videos",
    "icon": "camera",
    "active": true,
    "order": 10
  }
]
```

### 2. Database Schema (Suggested)
```sql
CREATE TABLE categories (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  description TEXT,
  icon VARCHAR(100),
  active BOOLEAN DEFAULT true,
  order INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### 3. Initial Data to Seed
```sql
INSERT INTO categories (id, name, description, icon, active, order) VALUES
('ugc-videos', 'UGC Videos', 'Professional user-generated content videos for your products', 'video', true, 1),
('product-reviews', 'Product Reviews', 'Authentic product review videos and testimonials', 'star', true, 2),
('unboxing', 'Unboxing Videos', 'Unboxing and first impression videos', 'gift', true, 3),
('testimonials', 'Testimonials', 'Customer testimonial and success stories', 'message-circle', true, 4),
('demo-videos', 'Demo Videos', 'Product demonstration and how-to videos', 'play-circle', true, 5),
('social-content', 'Social Media Content', 'Short-form content for Instagram, TikTok, Reels', 'share-2', true, 6),
('lifestyle', 'Lifestyle Content', 'Lifestyle integration and day-to-day usage videos', 'heart', true, 7),
('comparison', 'Product Comparison', 'Comparison videos with competitor products', 'trending-up', true, 8),
('tutorials', 'Tutorials & Tips', 'Tutorial videos and pro tips for your product', 'book', true, 9),
('behind-scenes', 'Behind the Scenes', 'Behind-the-scenes and manufacturing process videos', 'camera', true, 10);
```

## Frontend Integration

### Expected Response from API
The frontend expects an array of category objects with at minimum:
- `id` (string) - Unique identifier
- `name` (string) - Display name
- `label` (string) - Alternative display name (optional, will use `name` if not provided)
- `description` (string) - Category description (optional)

### Frontend will:
1. Fetch from `GET /api/categories`
2. Add `{ id: "all", label: "All" }` at the beginning
3. Display in a horizontal scrollable categories bar below the header
4. Show each category as a clickable button
5. Allow filtering by selected category (to be implemented later)

## Additional Features (Optional but Recommended)

### GET Category by ID
```
Method: GET
Path: /api/categories/:id
Response: Single category object
```

### Admin Endpoints (for future management)
```
POST /api/admin/categories - Create new category
PUT /api/admin/categories/:id - Update category
DELETE /api/admin/categories/:id - Soft delete category
```

## Notes
- Categories should be sorted by `order` field (ascending)
- Only return `active: true` categories
- Consider caching these categories (they don't change often)
- No authentication required for GET /api/categories (it's for all users)
- Use consistent naming convention for category IDs (kebab-case)
- Icon field should reference lucide-react icon names (used in frontend)

## Testing
Test the endpoint with:
```bash
curl -X GET http://localhost:8000/api/categories \
  -H "Content-Type: application/json"
```

Expected: Array of 10 category objects sorted by order
