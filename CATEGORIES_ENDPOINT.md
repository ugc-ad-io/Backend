# Categories Endpoint Documentation

## Overview

The Categories endpoint provides a public API for retrieving UGC content categories. This endpoint is used to power category filters in the brand homepage and other UI components.

## Endpoint

### GET `/api/categories`

Returns an array of all active categories sorted by order.

**Authentication:** Not required (public endpoint)

**Response Code:** 200 OK

### Response Schema

```json
[
  {
    "id": "string (kebab-case)",
    "name": "string",
    "description": "string",
    "icon": "string (icon name)",
    "active": boolean,
    "order": integer
  },
  ...
]
```

### Example Request

```bash
curl http://localhost:8000/api/categories
```

### Example Response

```json
[
  {
    "id": "ugc-videos",
    "name": "UGC Videos",
    "description": "Original user-generated video content",
    "icon": "video-camera",
    "active": true,
    "order": 1
  },
  {
    "id": "product-reviews",
    "name": "Product Reviews",
    "description": "Detailed reviews and honest opinions on products",
    "icon": "star-review",
    "active": true,
    "order": 2
  },
  {
    "id": "unboxing",
    "name": "Unboxing",
    "description": "Unboxing and first impressions of products",
    "icon": "package-open",
    "active": true,
    "order": 3
  },
  {
    "id": "testimonials",
    "name": "Testimonials",
    "description": "Customer testimonials and success stories",
    "icon": "message-quote",
    "active": true,
    "order": 4
  },
  {
    "id": "demo-videos",
    "name": "Demo Videos",
    "description": "Product demonstrations and how-to videos",
    "icon": "play-circle",
    "active": true,
    "order": 5
  },
  {
    "id": "social-media-content",
    "name": "Social Media Content",
    "description": "Short-form content for Instagram, TikTok, Reels",
    "icon": "share-2",
    "active": true,
    "order": 6
  },
  {
    "id": "lifestyle-content",
    "name": "Lifestyle Content",
    "description": "Lifestyle and day-in-the-life content featuring products",
    "icon": "heart",
    "active": true,
    "order": 7
  },
  {
    "id": "product-comparison",
    "name": "Product Comparison",
    "description": "Side-by-side comparisons of products or alternatives",
    "icon": "scale",
    "active": true,
    "order": 8
  },
  {
    "id": "tutorials",
    "name": "Tutorials",
    "description": "Step-by-step guides and tutorial content",
    "icon": "book-open",
    "active": true,
    "order": 9
  },
  {
    "id": "behind-the-scenes",
    "name": "Behind the Scenes",
    "description": "Behind-the-scenes and creator workspace content",
    "icon": "camera",
    "active": true,
    "order": 10
  }
]
```

## Field Details

| Field | Type | Description |
|-------|------|-------------|
| `id` | String | Unique identifier in kebab-case format (e.g., `ugc-videos`) |
| `name` | String | Display name of the category |
| `description` | String | Detailed description of the category |
| `icon` | String | Icon name/identifier for UI rendering |
| `active` | Boolean | Whether the category is currently active (only active=true returned) |
| `order` | Integer | Sort order for displaying categories (1-10) |

## Database Schema

### Collection: `categories`

```
{
  "id": "string (unique, kebab-case)",
  "name": "string",
  "description": "string",
  "icon": "string",
  "active": boolean,
  "order": integer
}
```

### MongoDB Indexes

```javascript
db.categories.createIndex({ "order": 1, "active": 1 })
db.categories.createIndex({ "id": 1 }, { unique: true })
```

## Available Categories

| ID | Name | Icon |
|----|------|------|
| `ugc-videos` | UGC Videos | video-camera |
| `product-reviews` | Product Reviews | star-review |
| `unboxing` | Unboxing | package-open |
| `testimonials` | Testimonials | message-quote |
| `demo-videos` | Demo Videos | play-circle |
| `social-media-content` | Social Media Content | share-2 |
| `lifestyle-content` | Lifestyle Content | heart |
| `product-comparison` | Product Comparison | scale |
| `tutorials` | Tutorials | book-open |
| `behind-the-scenes` | Behind the Scenes | camera |

## Implementation Details

### Auto-Initialization

Categories are automatically seeded to MongoDB on application startup via the `seed_categories()` function called in the startup event. This ensures the categories collection is always populated on first run.

### Caching Recommendation

For optimal performance, cache the categories response on the frontend with a TTL of 1-24 hours, as categories rarely change.

### Sorting

Categories are always returned sorted by the `order` field in ascending order (1-10).

### Filtering

Only categories with `active: true` are returned. Inactive categories can be retrieved via the admin endpoint.

## Admin Endpoint (Optional)

### GET `/api/admin/categories`

Returns all categories including inactive ones (for admin panel management).

**Requires:** Admin authentication

```bash
curl -H "Authorization: Bearer <jwt_token>" \
  http://localhost:8000/api/admin/categories
```

## Usage Examples

### React Frontend

```javascript
// Fetch categories on component mount
useEffect(() => {
  fetch('/api/categories')
    .then(res => res.json())
    .then(data => setCategories(data))
    .catch(err => console.error(err));
}, []);

// Render as filter options
<select name="category">
  <option value="">All Categories</option>
  {categories.map(cat => (
    <option key={cat.id} value={cat.id}>
      {cat.name}
    </option>
  ))}
</select>
```

### Vue Frontend

```vue
<template>
  <select v-model="selectedCategory">
    <option value="">All Categories</option>
    <option v-for="cat in categories" :key="cat.id" :value="cat.id">
      {{ cat.name }}
    </option>
  </select>
</template>

<script>
export default {
  data() {
    return {
      categories: [],
      selectedCategory: ''
    }
  },
  mounted() {
    fetch('/api/categories')
      .then(res => res.json())
      .then(data => {
        this.categories = data;
      });
  }
}
</script>
```

### Raw Fetch

```javascript
const categories = await fetch('/api/categories').then(r => r.json());
console.log(categories);
```

## Response Times

- **First Request:** ~50-100ms (from MongoDB)
- **Cached Request:** <5ms (frontend cache)
- **Response Size:** ~2-3 KB

## Error Handling

### 500 Internal Server Error

If MongoDB is unreachable or there's a server error:

```json
{
  "detail": "Internal server error"
}
```

## Files

| File | Purpose |
|------|---------|
| `categories.py` | Endpoint implementation and seeding logic |
| `test_categories.py` | Test script to verify endpoint functionality |
| `CATEGORIES_ENDPOINT.md` | This documentation |

## Testing

Run the test script to verify everything is working:

```bash
python test_categories.py
```

Expected output:
- All 10 categories loaded
- All categories are active
- Categories sorted by order
- Sample JSON response shown

## Future Enhancements

- [ ] Add category-specific icons/images storage
- [ ] Add category subcategories
- [ ] Add category statistics (number of campaigns, content pieces)
- [ ] Add category trending/popularity metrics
- [ ] Add admin CRUD endpoints for category management
- [ ] Add category search/filter capability

## Integration Points

- ✅ Used by brand homepage category filter
- ✅ Used by campaign creation flow to tag campaigns
- ✅ Used by creator directory to filter creators by expertise
- ✅ Used by content search and discovery features
