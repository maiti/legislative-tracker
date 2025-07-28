// routes/keywords.js
const express = require('express');
const { Keyword, Bill, BillKeyword } = require('../models');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();

// GET /api/keywords - Get all keywords
router.get('/', async (req, res) => {
  try {
    const { category, active = 'true' } = req.query;
    
    const where = {};
    if (category) where.category = category;
    if (active !== 'all') where.isActive = active === 'true';

    const keywords = await Keyword.findAll({
      where,
      include: [
        {
          model: Bill,
          through: { attributes: [] },
          attributes: ['id'],
          required: false
        }
      ],
      order: [['term', 'ASC']]
    });

    // Add bill count to each keyword
    const keywordsWithCount = keywords.map(keyword => ({
      ...keyword.toJSON(),
      billCount: keyword.Bills ? keyword.Bills.length : 0
    }));

    res.json({ keywords: keywordsWithCount });
  } catch (error) {
    console.error('Get keywords error:', error);
    res.status(500).json({ error: 'Failed to fetch keywords' });
  }
});

// POST /api/keywords - Create new keyword (Admin only)
router.post('/', requireAdmin, async (req, res) => {
  try {
    const { term, category, isActive = true } = req.body;

    if (!term || term.trim().length === 0) {
      return res.status(400).json({ error: 'Keyword term is required' });
    }

    // Check if keyword already exists
    const existing = await Keyword.findOne({
      where: { term: term.trim().toLowerCase() }
    });

    if (existing) {
      return res.status(409).json({ error: 'Keyword already exists' });
    }

    const keyword = await Keyword.create({
      term: term.trim(),
      category: category || 'general',
      isActive
    });

    res.status(201).json({
      message: 'Keyword created successfully',
      keyword
    });
  } catch (error) {
    console.error('Create keyword error:', error);
    res.status(500).json({ error: 'Failed to create keyword' });
  }
});

// PUT /api/keywords/:id - Update keyword (Admin only)
router.put('/:id', requireAdmin, async (req, res) => {
  try {
    const keyword = await Keyword.findByPk(req.params.id);
    if (!keyword) {
      return res.status(404).json({ error: 'Keyword not found' });
    }

    const { term, category, isActive } = req.body;
    
    await keyword.update({
      term: term || keyword.term,
      category: category || keyword.category,
      isActive: isActive !== undefined ? isActive : keyword.isActive
    });

    res.json({
      message: 'Keyword updated successfully',
      keyword
    });
  } catch (error) {
    console.error('Update keyword error:', error);
    res.status(500).json({ error: 'Failed to update keyword' });
  }
});

// DELETE /api/keywords/:id - Delete keyword (Admin only)
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const keyword = await Keyword.findByPk(req.params.id);
    if (!keyword) {
      return res.status(404).json({ error: 'Keyword not found' });
    }

    await keyword.destroy();
    res.json({ message: 'Keyword deleted successfully' });
  } catch (error) {
    console.error('Delete keyword error:', error);
    res.status(500).json({ error: 'Failed to delete keyword' });
  }
});

// GET /api/keywords/categories - Get all keyword categories
router.get('/categories', async (req, res) => {
  try {
    const categories = await Keyword.findAll({
      attributes: ['category'],
      group: ['category'],
      raw: true
    });

    const categoryList = categories.map(c => c.category).filter(Boolean);
    
    res.json({ categories: categoryList });
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// POST /api/keywords/bulk-create - Bulk create keywords (Admin only)
router.post('/bulk-create', requireAdmin, async (req, res) => {
  try {
    const { keywords } = req.body;

    if (!Array.isArray(keywords) || keywords.length === 0) {
      return res.status(400).json({ error: 'Keywords array is required' });
    }

    const created = [];
    const errors = [];

    for (const keywordData of keywords) {
      try {
        const { term, category = 'general' } = keywordData;
        
        if (!term || term.trim().length === 0) {
          errors.push({ term, error: 'Term is required' });
          continue;
        }

        // Check if exists
        const existing = await Keyword.findOne({
          where: { term: term.trim().toLowerCase() }
        });

        if (existing) {
          errors.push({ term, error: 'Already exists' });
          continue;
        }

        const keyword = await Keyword.create({
          term: term.trim(),
          category,
          isActive: true
        });

        created.push(keyword);
      } catch (error) {
        errors.push({ term: keywordData.term, error: error.message });
      }
    }

    res.json({
      message: `Created ${created.length} keywords`,
      created,
      errors
    });
  } catch (error) {
    console.error('Bulk create keywords error:', error);
    res.status(500).json({ error: 'Failed to bulk create keywords' });
  }
});

// GET /api/keywords/:id/bills - Get bills associated with a keyword
router.get('/:id/bills', async (req, res) => {
  try {
    const keyword = await Keyword.findByPk(req.params.id, {
      include: [
        {
          model: Bill,
          through: {
            attributes: ['relevanceScore']
          }
        }
      ]
    });

    if (!keyword) {
      return res.status(404).json({ error: 'Keyword not found' });
    }

    res.json({
      keyword: keyword.term,
      bills: keyword.Bills
    });
  } catch (error) {
    console.error('Get keyword bills error:', error);
    res.status(500).json({ error: 'Failed to fetch keyword bills' });
  }
});

// POST /api/keywords/search - Search bills by multiple keywords
router.post('/search', async (req, res) => {
  try {
    const { keywords, operator = 'OR' } = req.body;

    if (!Array.isArray(keywords) || keywords.length === 0) {
      return res.status(400).json({ error: 'Keywords array is required' });
    }

    let bills;
    
    if (operator === 'AND') {
      // Bills must have ALL keywords
      bills = await Bill.findAll({
        include: [
          {
            model: Keyword,
            where: { term: keywords },
            through: { attributes: ['relevanceScore'] },
            required: true
          }
        ],
        group: ['Bill.id'],
        having: Bill.sequelize.literal(`COUNT(DISTINCT "Keywords"."id") = ${keywords.length}`)
      });
    } else {
      // Bills with ANY of the keywords
      bills = await Bill.findAll({
        include: [
          {
            model: Keyword,
            where: { term: keywords },
            through: { attributes: ['relevanceScore'] },
            required: true
          }
        ]
      });
    }

    res.json({
      searchCriteria: { keywords, operator },
      results: bills
    });
  } catch (error) {
    console.error('Keyword search error:', error);
    res.status(500).json({ error: 'Failed to search bills by keywords' });
  }
});

// Initialize default keywords
const DEFAULT_KEYWORDS = [
  { term: 'Financial crimes', category: 'financial' },
  { term: 'Fraud investigation', category: 'financial' },
  { term: 'Anti-money laundering', category: 'financial' },
  { term: 'AML', category: 'financial' },
  { term: 'Economic crimes', category: 'financial' },
  { term: 'White-collar crime', category: 'financial' },
  { term: 'Asset forfeiture', category: 'financial' },
  { term: 'Illicit finance', category: 'financial' },
  { term: 'Investigative accounting', category: 'financial' },
  { term: 'Forensic auditing', category: 'financial' },
  { term: 'Financial intelligence', category: 'intelligence' },
  { term: 'Money laundering prevention', category: 'financial' },
  { term: 'Financial analysis training', category: 'training' },
  { term: 'Law enforcement training', category: 'training' },
  { term: 'Technical assistance', category: 'training' },
  { term: 'Capacity building', category: 'training' },
  { term: 'Justice assistance grants', category: 'funding' },
  { term: 'Training and technical assistance', category: 'training' },
  { term: 'TTA', category: 'training' },
  { term: 'Evidence-based practices', category: 'training' },
  { term: 'Criminal justice system improvement', category: 'system' },
  { term: 'Intelligence', category: 'intelligence' },
  { term: 'COPS grants', category: 'funding' },
  { term: 'Bureau of Justice Assistance', category: 'funding' },
  { term: 'BJA', category: 'funding' },
  { term: 'FinCEN', category: 'financial' },
  { term: 'Financial Crimes Enforcement Network', category: 'financial' },
  { term: 'Bank Secrecy Act', category: 'financial' },
  { term: 'Suspicious activity reporting', category: 'financial' },
  { term: 'Multi-jurisdictional task force', category: 'enforcement' },
  { term: 'Drug task force', category: 'enforcement' },
  { term: 'Intelligence sharing', category: 'intelligence' },
  { term: 'HIDTA', category: 'enforcement' },
  { term: 'High Intensity Drug Trafficking', category: 'enforcement' }
];

// POST /api/keywords/initialize - Initialize default keywords (Admin only)
router.post('/initialize', requireAdmin, async (req, res) => {
  try {
    const created = [];
    const existing = [];

    for (const keywordData of DEFAULT_KEYWORDS) {
      const [keyword, wasCreated] = await Keyword.findOrCreate({
        where: { term: keywordData.term },
        defaults: keywordData
      });

      if (wasCreated) {
        created.push(keyword);
      } else {
        existing.push(keyword);
      }
    }

    res.json({
      message: 'Keywords initialized',
      created: created.length,
      existing: existing.length,
      details: { created, existing }
    });
  } catch (error) {
    console.error('Initialize keywords error:', error);
    res.status(500).json({ error: 'Failed to initialize keywords' });
  }
});

module.exports = router;