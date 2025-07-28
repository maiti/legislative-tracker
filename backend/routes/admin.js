// routes/admin.js
const express = require('express');
const axios = require('axios');
const { Op } = require('sequelize');
const { User, Bill, Keyword, BillHistory } = require('../models');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();

// Apply admin middleware to all routes
router.use(requireAdmin);

// GET /api/admin/users/pending - Get pending user approvals
router.get('/users/pending', async (req, res) => {
  try {
    const pendingUsers = await User.findAll({
      where: { status: 'pending' },
      attributes: { exclude: ['passwordHash'] },
      order: [['createdAt', 'ASC']]
    });

    res.json({ users: pendingUsers });
  } catch (error) {
    console.error('Get pending users error:', error);
    res.status(500).json({ error: 'Failed to fetch pending users' });
  }
});

// POST /api/admin/users/:id/approve - Approve user account
router.post('/users/:id/approve', async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.status !== 'pending') {
      return res.status(400).json({ error: 'User not pending approval' });
    }

    await user.update({
      status: 'approved',
      approvedBy: req.user.id,
      approvedAt: new Date()
    });

    res.json({
      message: 'User approved successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Approve user error:', error);
    res.status(500).json({ error: 'Failed to approve user' });
  }
});

// POST /api/admin/users/:id/suspend - Suspend user account
router.post('/users/:id/suspend', async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.role === 'admin') {
      return res.status(403).json({ error: 'Cannot suspend admin users' });
    }

    await user.update({ status: 'suspended' });

    res.json({
      message: 'User suspended successfully',
      user: {
        id: user.id,
        email: user.email,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Suspend user error:', error);
    res.status(500).json({ error: 'Failed to suspend user' });
  }
});

// GET /api/admin/users - Get all users with filtering
router.get('/users', async (req, res) => {
  try {
    const { status, role, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    const where = {};

    if (status) where.status = status;
    if (role) where.role = role;

    const { count, rows } = await User.findAndCountAll({
      where,
      attributes: { exclude: ['passwordHash'] },
      include: [
        {
          model: User,
          as: 'ApprovedBy',
          attributes: ['firstName', 'lastName'],
          required: false
        }
      ],
      limit: parseInt(limit),
      offset: parseInt(offset),
      order: [['createdAt', 'DESC']]
    });

    res.json({
      users: rows,
      pagination: {
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(count / limit)
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /api/admin/dashboard/stats - Get dashboard statistics
router.get('/dashboard/stats', async (req, res) => {
  try {
    const [
      totalBills,
      activeBills,
      pendingUsers,
      totalUsers,
      recentBills,
      billsByState
    ] = await Promise.all([
      Bill.count(),
      Bill.count({
        where: {
          status: {
            [Op.not]: null,
            [Op.notILike]: '%passed%'
          }
        }
      }),
      User.count({ where: { status: 'pending' } }),
      User.count({ where: { status: 'approved' } }),
      Bill.findAll({
        limit: 5,
        order: [['createdAt', 'DESC']],
        attributes: ['id', 'title', 'stateCode', 'status', 'createdAt']
      }),
      Bill.findAll({
        attributes: [
          'stateCode',
          [Bill.sequelize.fn('COUNT', '*'), 'count']
        ],
        group: ['stateCode'],
        order: [[Bill.sequelize.fn('COUNT', '*'), 'DESC']],
        limit: 10
      })
    ]);

    res.json({
      stats: {
        totalBills,
        activeBills,
        pendingUsers,
        totalUsers
      },
      recentBills,
      billsByState
    });
  } catch (error) {
    console.error('Get dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// POST /api/admin/sync/legiscan - Sync with LegiScan API
router.post('/sync/legiscan', async (req, res) => {
  try {
    const { state, keywords } = req.body;
    
    if (!process.env.LEGISCAN_API_KEY) {
      return res.status(500).json({ error: 'LegiScan API key not configured' });
    }

    // Start background sync process
    const jobId = `sync_${Date.now()}`;
    
    // In a production app, you'd use a proper job queue here
    setImmediate(async () => {
      try {
        await syncWithLegiScan(state, keywords, req.user.id);
      } catch (error) {
        console.error('LegiScan sync error:', error);
      }
    });

    res.json({
      message: 'LegiScan sync started',
      jobId,
      estimatedCompletion: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    });
  } catch (error) {
    console.error('Start LegiScan sync error:', error);
    res.status(500).json({ error: 'Failed to start sync' });
  }
});

// Function to sync with LegiScan API
async function syncWithLegiScan(stateCode, searchKeywords, userId) {
  const baseUrl = 'https://api.legiscan.com/';
  const apiKey = process.env.LEGISCAN_API_KEY;
  
  try {
    // Get current session for the state
    const sessionResponse = await axios.get(`${baseUrl}?key=${apiKey}&op=getSessionList&state=${stateCode}`);
    
    if (!sessionResponse.data.status === 'OK') {
      throw new Error('Failed to get session list');
    }

    const currentSession = sessionResponse.data.sessions.find(s => s.session_name.includes('2025'));
    if (!currentSession) {
      console.log('No current session found for', stateCode);
      return;
    }

    // Search for bills with keywords
    for (const keyword of searchKeywords) {
      const searchResponse = await axios.get(
        `${baseUrl}?key=${apiKey}&op=search&state=${stateCode}&query=${encodeURIComponent(keyword)}`
      );

      if (searchResponse.data.status === 'OK' && searchResponse.data.searchresult) {
        for (const result of searchResponse.data.searchresult) {
          await processLegiScanBill(result, keyword, userId);
        }
      }

      // Rate limiting - LegiScan allows 30 requests per minute
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  } catch (error) {
    console.error('LegiScan sync error:', error);
    throw error;
  }
}

async function processLegiScanBill(billData, keyword, userId) {
  try {
    // Check if bill already exists
    const existingBill = await Bill.findOne({
      where: { legiscanId: billData.bill_id.toString() }
    });

    if (existingBill) {
      // Update existing bill if status changed
      if (existingBill.status !== billData.status_desc) {
        const previousStatus = existingBill.status;
        const previousProgress = existingBill.progressPercentage;
        
        await existingBill.update({
          status: billData.status_desc,
          lastActionDate: billData.last_action_date
        });

        // Create history entry
        await BillHistory.create({
          billId: existingBill.id,
          previousStatus,
          newStatus: billData.status_desc,
          previousProgress,
          newProgress: existingBill.progressPercentage,
          changeDescription: 'Updated from LegiScan API',
          changedBy: userId
        });
      }
      return;
    }

    // Create new bill
    const bill = await Bill.create({
      legiscanId: billData.bill_id.toString(),
      stateCode: billData.state,
      billNumber: billData.bill_number,
      title: billData.title,
      description: billData.description,
      status: billData.status_desc,
      introducedDate: billData.introduced_date,
      lastActionDate: billData.last_action_date,
      url: billData.state_link || billData.url,
      sourceType: 'legiscan',
      progressPercentage: calculateProgress(billData.status_desc)
    });

    // Add keyword association
    const [keywordObj] = await Keyword.findOrCreate({
      where: { term: keyword },
      defaults: { term: keyword, category: 'search' }
    });

    await bill.addKeyword(keywordObj, { through: { relevanceScore: 0.8 } });

    // Create history entry
    await BillHistory.create({
      billId: bill.id,
      newStatus: billData.status_desc,
      newProgress: bill.progressPercentage,
      changeDescription: 'Imported from LegiScan API',
      changedBy: userId
    });

    console.log(`Created bill: ${bill.billNumber} - ${bill.title}`);
  } catch (error) {
    console.error('Error processing LegiScan bill:', error);
  }
}

function calculateProgress(status) {
  const statusMap = {
    'Introduced': 10,
    'Committee': 25,
    'Second Reading': 40,
    'Third Reading': 60,
    'Passed House': 70,
    'Passed Senate': 80,
    'Enrolled': 90,
    'Signed': 100,
    'Vetoed': 95,
    'Failed': 0
  };

  for (const [key, value] of Object.entries(statusMap)) {
    if (status.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  return 15; // Default progress
}

// GET /api/admin/export/bills - Export bills data
router.get('/export/bills', async (req, res) => {
  try {
    const { format = 'json' } = req.query;
    
    const bills = await Bill.findAll({
      include: [
        { model: Keyword, through: { attributes: [] } }
      ]
    });

    if (format === 'csv') {
      // Simple CSV export
      const csvHeader = 'State,Bill Number,Title,Status,Progress,Introduced Date,Last Action Date,URL\n';
      const csvRows = bills.map(bill => 
        `"${bill.stateCode}","${bill.billNumber}","${bill.title}","${bill.status}","${bill.progressPercentage}","${bill.introducedDate}","${bill.lastActionDate}","${bill.url}"`
      ).join('\n');
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=bills_export.csv');
      res.send(csvHeader + csvRows);
    } else {
      res.json({ bills });
    }
  } catch (error) {
    console.error('Export bills error:', error);
    res.status(500).json({ error: 'Failed to export bills' });
  }
});

module.exports = router;