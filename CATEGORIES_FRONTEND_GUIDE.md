# Categories Endpoint - Frontend Integration Guide

## Quick Integration

### 1. Fetch Categories

```javascript
// Simple fetch
const fetchCategories = async () => {
  const response = await fetch('/api/categories');
  const categories = await response.json();
  return categories;
};
```

### 2. React Hook Example

```javascript
import { useState, useEffect } from 'react';

export const useCategories = () => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('/api/categories')
      .then(res => res.json())
      .then(data => {
        setCategories(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err);
        setLoading(false);
      });
  }, []);

  return { categories, loading, error };
};

// Usage in component
export const CategoryFilter = () => {
  const { categories, loading, error } = useCategories();

  if (loading) return <div>Loading categories...</div>;
  if (error) return <div>Error loading categories</div>;

  return (
    <select name="category">
      <option value="">All Categories</option>
      {categories.map(cat => (
        <option key={cat.id} value={cat.id}>
          {cat.name}
        </option>
      ))}
    </select>
  );
};
```

## Common UI Patterns

### Pattern 1: Filter Dropdown

```jsx
<div className="filter-section">
  <label htmlFor="category">Category</label>
  <select 
    id="category"
    name="category"
    value={selectedCategory}
    onChange={(e) => setSelectedCategory(e.target.value)}
  >
    <option value="">All Categories</option>
    {categories.map(cat => (
      <option key={cat.id} value={cat.id}>
        {cat.name}
      </option>
    ))}
  </select>
</div>
```

### Pattern 2: Filter Chips/Buttons

```jsx
<div className="category-filters">
  <button 
    className={selectedCategory === '' ? 'active' : ''}
    onClick={() => setSelectedCategory('')}
  >
    All
  </button>
  {categories.map(cat => (
    <button
      key={cat.id}
      className={selectedCategory === cat.id ? 'active' : ''}
      onClick={() => setSelectedCategory(cat.id)}
    >
      <span className="icon">{cat.icon}</span>
      {cat.name}
    </button>
  ))}
</div>
```

### Pattern 3: Grid/Cards Display

```jsx
<div className="category-grid">
  {categories.map(cat => (
    <div
      key={cat.id}
      className="category-card"
      onClick={() => filterByCategory(cat.id)}
    >
      <div className="icon-container">
        <Icon name={cat.icon} size="large" />
      </div>
      <h3>{cat.name}</h3>
      <p>{cat.description}</p>
    </div>
  ))}
</div>
```

### Pattern 4: Select Component (Material-UI)

```jsx
import { Select, MenuItem, FormControl, InputLabel } from '@mui/material';

<FormControl fullWidth>
  <InputLabel>Category</InputLabel>
  <Select
    value={selectedCategory}
    label="Category"
    onChange={(e) => setSelectedCategory(e.target.value)}
  >
    <MenuItem value="">
      <em>All Categories</em>
    </MenuItem>
    {categories.map(cat => (
      <MenuItem key={cat.id} value={cat.id}>
        {cat.name}
      </MenuItem>
    ))}
  </Select>
</FormControl>
```

## Styling Examples

### CSS Grid Layout

```css
.category-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 20px;
  padding: 20px;
}

.category-card {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 20px;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s ease;
}

.category-card:hover {
  border-color: #1976d2;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  transform: translateY(-4px);
}

.category-card .icon-container {
  font-size: 40px;
  margin-bottom: 12px;
  color: #1976d2;
}

.category-card h3 {
  margin: 12px 0;
  font-size: 16px;
  font-weight: 600;
}

.category-card p {
  font-size: 14px;
  color: #666;
  margin: 0;
}
```

### Chip/Button Layout

```css
.category-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  padding: 15px 0;
}

.category-filters button {
  padding: 8px 16px;
  border: 1px solid #ddd;
  border-radius: 20px;
  background: white;
  cursor: pointer;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
}

.category-filters button:hover {
  border-color: #1976d2;
  color: #1976d2;
}

.category-filters button.active {
  background: #1976d2;
  color: white;
  border-color: #1976d2;
}

.category-filters .icon {
  font-size: 16px;
}
```

## Data Management

### Cache Categories with Context API

```javascript
// CategoryContext.js
import { createContext, useContext, useState, useEffect } from 'react';

const CategoryContext = createContext();

export const CategoryProvider = ({ children }) => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/categories')
      .then(res => res.json())
      .then(data => {
        setCategories(data);
        setLoading(false);
      });
  }, []);

  return (
    <CategoryContext.Provider value={{ categories, loading }}>
      {children}
    </CategoryContext.Provider>
  );
};

export const useCategories = () => {
  const context = useContext(CategoryContext);
  if (!context) {
    throw new Error('useCategories must be used within CategoryProvider');
  }
  return context;
};
```

### Cache Categories with Redux

```javascript
// categoriesSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

export const fetchCategories = createAsyncThunk(
  'categories/fetchCategories',
  async () => {
    const response = await fetch('/api/categories');
    return response.json();
  }
);

const categoriesSlice = createSlice({
  name: 'categories',
  initialState: {
    items: [],
    loading: false,
    error: null,
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchCategories.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchCategories.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchCategories.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      });
  },
});

export default categoriesSlice.reducer;
```

## API Call Patterns

### Pattern 1: With Error Handling

```javascript
const loadCategories = async () => {
  try {
    const response = await fetch('/api/categories');
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const categories = await response.json();
    setCategories(categories);
  } catch (error) {
    console.error('Failed to load categories:', error);
    setError('Unable to load categories. Please try again.');
  } finally {
    setLoading(false);
  }
};
```

### Pattern 2: With Retry Logic

```javascript
const fetchCategoriesWithRetry = async (maxRetries = 3) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch('/api/categories');
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
    }
  }
};
```

### Pattern 3: With Caching

```javascript
const categoryCache = {
  data: null,
  lastFetch: null,
  ttl: 24 * 60 * 60 * 1000, // 24 hours

  async get() {
    const now = Date.now();
    if (this.data && (now - this.lastFetch) < this.ttl) {
      return this.data;
    }

    const response = await fetch('/api/categories');
    this.data = await response.json();
    this.lastFetch = now;
    return this.data;
  },

  clear() {
    this.data = null;
    this.lastFetch = null;
  }
};
```

## TypeScript Integration

```typescript
interface Category {
  id: string;
  name: string;
  description: string;
  icon: string;
  active: boolean;
  order: number;
}

const fetchCategories = async (): Promise<Category[]> => {
  const response = await fetch('/api/categories');
  if (!response.ok) {
    throw new Error('Failed to fetch categories');
  }
  return response.json();
};

const useCategories = (): {
  categories: Category[];
  loading: boolean;
  error: Error | null;
} => {
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    fetchCategories()
      .then(setCategories)
      .catch(setError)
      .finally(() => setLoading(false));
  }, []);

  return { categories, loading, error };
};
```

## Testing Examples

### Jest Unit Test

```javascript
describe('useCategories', () => {
  it('should fetch and return categories', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve([
          { id: 'ugc-videos', name: 'UGC Videos', order: 1 }
        ])
      })
    );

    const { result, waitForNextUpdate } = renderHook(() => useCategories());

    expect(result.current.loading).toBe(true);

    await waitForNextUpdate();

    expect(result.current.categories).toHaveLength(1);
    expect(result.current.categories[0].id).toBe('ugc-videos');
    expect(result.current.loading).toBe(false);
  });
});
```

## Performance Tips

1. **Cache the response** - Store in localStorage or context for 24 hours
2. **Lazy load** - Load only when needed
3. **Use conditional rendering** - Show loading state while fetching
4. **Error boundaries** - Wrap in error boundary to gracefully handle failures
5. **Memoization** - Use `useMemo` to prevent unnecessary re-renders

## Browser Compatibility

- ✅ All modern browsers (Chrome, Firefox, Safari, Edge)
- ✅ Internet Explorer 11 (with Fetch polyfill)
- ✅ Mobile browsers

## CORS Note

The endpoint is configured to work with the existing CORS settings. Ensure your frontend domain is allowed.

---

**That's it!** 🎉 Your categories endpoint is ready to use in your frontend!
