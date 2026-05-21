const request = require('supertest');
const app = require('../server');
const Gig = require('../models/Gig');

describe('Gigs API', () => {
  beforeAll(async () => {
    // Connect to test database
  });

  afterAll(async () => {
    // Cleanup
  });

  describe('POST /api/gigs', () => {
    it('should create a new gig', async () => {
      const gigData = {
        title: 'Create Instagram Reels',
        description: 'Create engaging Instagram reels for our fashion brand',
        category: 'SOCIAL_MEDIA',
        budget: 500,
        deadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      };

      const response = await request(app)
        .post('/api/gigs')
        .send(gigData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe(gigData.title);
    });

    it('should fail with invalid data', async () => {
      const response = await request(app)
        .post('/api/gigs')
        .send({ title: 'Short' })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/gigs', () => {
    it('should list all gigs', async () => {
      const response = await request(app)
        .get('/api/gigs')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it('should filter by status', async () => {
      const response = await request(app)
        .get('/api/gigs?status=APPROVED')
        .expect(200);

      expect(response.body.data.every(g => g.status === 'APPROVED')).toBe(true);
    });
  });

  describe('GET /api/gigs/:id', () => {
    it('should get a single gig', async () => {
      const gig = await Gig.create({
        title: 'Test Gig',
        description: 'Test gig description for testing',
        category: 'OTHER',
        budget: 100,
        deadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        creator_id: '507f1f77bcf86cd799439012'
      });

      const response = await request(app)
        .get(`/api/gigs/${gig._id}`)
        .expect(200);

      expect(response.body.data._id).toBe(gig._id.toString());
    });

    it('should return 404 for non-existent gig', async () => {
      const response = await request(app)
        .get('/api/gigs/507f1f77bcf86cd799439999')
        .expect(404);

      expect(response.body.success).toBe(false);
    });
  });
});
