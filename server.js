const express = require('express');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes, Op } = require('sequelize');
const axios = require('axios');
const cron = require('node-cron');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Database setup with better error handling
const sequelize = new Sequelize(process.env.DATABASE_URL || 'sqlite::memory:', {
  dialect: process.env.DATABASE_URL ? 
    (process.env.DATABASE_URL.startsWith('postgres') ? 'postgres' : 'sqlite') : 
    'sqlite',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  dialectOptions: process.env.DATABASE_URL?.startsWith('postgres') ? {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  } : {}
});

// LegiScan API configuration
const LEGISCAN_API_KEY = process.env.LEGISCAN_API_KEY || '65c8d4470aa39a31e376e82db13f1e72';
const LEGISCAN_BASE_URL = 'https://api.legiscan.com';

// Keywords for tracking relevant legislation
const TRACKING_KEYWORDS = [
  'Financial crimes', 'Fraud investigation', 'Anti-money laundering', 'AML',
  'Economic crimes', 'White-collar crime', 'Asset forfeiture', 'Illicit finance',
  'Investigative accounting', 'Forensic auditing', 'Financial intelligence',
  'Money laundering prevention', 'Financial analysis training', 'Law enforcement training',
  'Technical assistance', 'Capacity building', 'Justice assistance grants',
  'Training and technical assistance', 'TTA', 'Evidence-based practices',
  'Criminal justice system improvement', 'Intelligence sharing',
  'Multi-jurisdictional task forces', 'Cybercrime', 'Digital forensics'
];

// Enhanced User Model
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  passwordHash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  organization: {
    type: DataTypes.STRING,
    allowNull: true
  },
  role: {
    type: DataTypes.ENUM('admin', 'user'),
    defaultValue: 'user'
  },
  status: {
    type: DataTypes.ENUM('pending', 'approved', 'suspended'),
    defaultValue: 'pending'
  }
});

// Enhanced Bill Model with LegiScan integration fields
const Bill = sequelize.define('Bill', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  legiscanId: {
    type: DataTypes.STRING,
    allowNull: true,
    unique: true
  },
  stateCode: {
    type: DataTypes.STRING(2),
    allowNull: false
  },
  billNumber: {
    type: DataTypes.STRING(50),
    allowNull: false
  },
  title: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  status: {
    type: DataTypes.STRING,
    allowNull: true
  },
  progressPercentage: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  introducedDate: {
    type: DataTypes.DATEONLY,
    allowNull: true
  },
  fundsAllocated: {
    type: DataTypes.STRING,
    allowNull: true
  },
  keywords: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  relevanceScore: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  lastSynced: {
    type: DataTypes.DATE,
    allowNull: true
  },
  legiscanUrl: {
    type: DataTypes.STRING,
    allowNull: true
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  sourceType: {
    type: DataTypes.ENUM('manual', 'legiscan'),
    defaultValue: 'manual'
  }
});

// Watchlist Model
const UserWatchlist = sequelize.define('UserWatchlist', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  notes: {
    type: DataTypes.TEXT,
    allowNull: true
  }
});

// Sync Status Model for tracking API sync operations
const SyncStatus = sequelize.define('SyncStatus', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  syncType: {
    type: DataTypes.STRING,
    allowNull: false
  },
  status: {
    type: DataTypes.ENUM('running', 'completed', 'failed'),
    allowNull: false
  },
  startTime: {
    type: DataTypes.DATE,
    allowNull: false
  },
  endTime: {
    type: DataTypes.DATE,
    allowNull: true
  },
  billsFound: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  billsAdded: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  billsUpdated: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  errorMessage: {
    type: DataTypes.TEXT,
    allowNull: true
  }
});

// Associations
User.hasMany(UserWatchlist);
UserWatchlist.belongsTo(User);
Bill.hasMany(UserWatchlist);
UserWatchlist.belongsTo(Bill);

// ===== LegiScan Service Class =====
class LegiScanService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = LEGISCAN_BASE_URL;
    this.requestDelay = 500;
  }

  async makeRequest(endpoint, params = {}) {
    try {
      const url = `${this.baseUrl}/?key=${this.apiKey}&${new URLSearchParams(params).toString()}`;
      
      await new Promise(resolve => setTimeout(resolve, this.requestDelay));
      
      const response = await axios.get(url, { timeout: 30000 });
      
      if (response.data.status === 'OK') {
        return response.data;
      } else {
        throw new Error(`LegiScan API Error: ${response.data.alert?.message || 'Unknown error'}`);
      }
    } catch (error) {
      if (error.response?.status === 429) {
        console.log('⏳ Rate limit hit, waiting 60 seconds...');
        await new Promise(resolve => setTimeout(resolve, 60000));
        return this.makeRequest(endpoint, params);
      }
      throw error;
    }
  }

  async searchBills(keyword, state = 'ALL', year = null) {
    try {
      const currentYear = year || new Date().getFullYear();
      console.log(`🔍 Searching LegiScan for: "${keyword}" in ${state} (${currentYear})`);
      
      const data = await this.makeRequest('search', {
        op: 'search',
        state: state,
        query: keyword,
        year: currentYear
      });
      
      if (data && data.searchresult) {
        if (Array.isArray(data.searchresult)) {
          return data.searchresult;
        } else if (data.searchresult && data.searchresult.summary) {
          console.log(`   Search returned summary data only for "${keyword}"`);
          return [];
        } else {
          console.log(`   Unexpected searchresult format for "${keyword}"`);
          return [];
        }
      }
      
      console.log(`   No results found for "${keyword}"`);
      return [];
    } catch (error) {
      console.error(`Error searching for "${keyword}":`, error.message);
      return [];
    }
  }

  async getBillDetails(billId) {
    try {
      const data = await this.makeRequest('getBill', {
        op: 'getBill',
        id: billId
      });
      
      return data.bill;
    } catch (error) {
      console.error(`Error fetching bill ${billId}:`, error.message);
      return null;
    }
  }

  analyzeRelevance(billTitle, billDescription, billText = '') {
    const content = `${billTitle} ${billDescription} ${billText}`.toLowerCase();
    const foundKeywords = [];
    let relevanceScore = 0;

    TRACKING_KEYWORDS.forEach(keyword => {
      if (content.includes(keyword.toLowerCase())) {
        foundKeywords.push(keyword);
        relevanceScore += 1;
      }
    });

    const highPriorityKeywords = ['money laundering', 'financial crimes', 'asset forfeiture', 'aml'];
    highPriorityKeywords.forEach(keyword => {
      if (content.includes(keyword)) {
        relevanceScore += 2;
      }
    });

    return {
      isRelevant: foundKeywords.length > 0,
      foundKeywords,
      relevanceScore,
      confidence: Math.min(relevanceScore * 10, 100)
    };
  }

  formatBillForDatabase(legiscanBill, relevanceAnalysis) {
    const status = this.mapStatus(legiscanBill.status);
    const progressPercentage = this.calculateProgress(legiscanBill.status, legiscanBill.history);

    return {
      legiscanId: legiscanBill.bill_id.toString(),
      stateCode: legiscanBill.state,
      billNumber: legiscanBill.bill_number,
      title: legiscanBill.title,
      description: legiscanBill.description || `${legiscanBill.title} - Introduced in ${legiscanBill.state}`,
      status: status,
      progressPercentage: progressPercentage,
      introducedDate: legiscanBill.introduced_date,
      fundsAllocated: this.extractFunding(legiscanBill),
      keywords: relevanceAnalysis.foundKeywords.join(', '),
      relevanceScore: relevanceAnalysis.relevanceScore,
      lastSynced: new Date(),
      legiscanUrl: `https://legiscan.com/${legiscanBill.state}/bill/${legiscanBill.bill_number}/${legiscanBill.session_id}`,
      sourceType: 'legiscan'
    };
  }

  mapStatus(legiscanStatus) {
    const statusMap = {
      1: 'Introduced',
      2: 'In Committee', 
      3: 'Committee Review',
      4: 'Passed Chamber',
      5: 'Passed Both Chambers',
      6: 'Signed/Enacted',
      7: 'Vetoed',
      8: 'Failed/Dead'
    };
    return statusMap[legiscanStatus] || 'Unknown';
  }

  calculateProgress(status, history = []) {
    const progressMap = {
      1: 10, 2: 25, 3: 40, 4: 70, 5: 90, 6: 100, 7: 0, 8: 0
    };
    return progressMap[status] || 0;
  }

  extractFunding(billData) {
    const text = (billData.title + ' ' + (billData.description || '')).toLowerCase();
    
    if (text.includes('appropriat')) return 'Appropriation Bill';
    if (text.includes('grant')) return 'Grant Program';
    if (text.includes('fund')) return 'Funding Specified';
    if (text.match(/\$[\d,]+/)) return 'Dollar Amount Specified';
    
    return 'Not specified';
  }
}

const legiScan = new LegiScanService(LEGISCAN_API_KEY);

// ===== COMPLETELY FIXED Bill Sync Function =====
async function syncRelevantBills() {
  let syncRecord;
  
  try {
    syncRecord = await SyncStatus.create({
      syncType: 'automatic',
      status: 'running',
      startTime: new Date()
    });

    console.log('🔄 Starting LegiScan synchronization...');
    
    let totalFound = 0;
    let totalAdded = 0;
    let totalUpdated = 0;

    const keywordBatches = [];
    for (let i = 0; i < TRACKING_KEYWORDS.length; i += 2) {
      keywordBatches.push(TRACKING_KEYWORDS.slice(i, i + 2));
    }

    for (const batch of keywordBatches) {
      for (const keyword of batch) {
        try {
          console.log(`🔍 Searching for: "${keyword}"`);
          
          const currentYear = new Date().getFullYear();
          const searchResults = await legiScan.searchBills(keyword, 'ALL', currentYear);
          
          const validResults = Array.isArray(searchResults) ? searchResults : [];
          
          if (validResults.length === 0) {
            console.log(`   No bills found for "${keyword}"`);
            continue;
          }

          totalFound += validResults.length;
          console.log(`   Found ${validResults.length} bills for "${keyword}"`);

          for (const result of validResults.slice(0, 2)) {
            try {
              if (!result || !result.bill_id) {
                console.log('   Skipping invalid result');
                continue;
              }

              const billDetails = await legiScan.getBillDetails(result.bill_id);
              if (!billDetails) {
                console.log(`   No details found for bill ${result.bill_id}`);
                continue;
              }

              const relevanceAnalysis = legiScan.analyzeRelevance(
                billDetails.title || '',
                billDetails.description || ''
              );

              if (relevanceAnalysis.relevanceScore < 1) {
                console.log(`   Low relevance score for bill ${result.bill_id}`);
                continue;
              }

              const formattedBill = legiScan.formatBillForDatabase(billDetails, relevanceAnalysis);

              const existingBill = await Bill.findOne({
                where: { legiscanId: formattedBill.legiscanId }
              });

              if (existingBill) {
                await existingBill.update({
                  ...formattedBill,
                  createdAt: existingBill.createdAt
                });
                totalUpdated++;
                console.log(`   ✅ Updated: ${formattedBill.billNumber}`);
              } else {
                await Bill.create(formattedBill);
                totalAdded++;
                console.log(`   ✨ Added: ${formattedBill.billNumber}`);
              }

            } catch (error) {
              console.error(`Error processing bill ${result.bill_id}:`, error.message);
            }
          }
        } catch (error) {
          console.error(`Error processing keyword "${keyword}":`, error.message);
        }
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    const safeTotal = isNaN(totalFound) ? 0 : totalFound;
    const safeAdded = isNaN(totalAdded) ? 0 : totalAdded;
    const safeUpdated = isNaN(totalUpdated) ? 0 : totalUpdated;

    if (syncRecord) {
      await syncRecord.update({
        status: 'completed',
        endTime: new Date(),
        billsFound: safeTotal,
        billsAdded: safeAdded,
        billsUpdated: safeUpdated
      });
    }

    console.log(`✅ Sync complete! Found: ${safeTotal}, Added: ${safeAdded}, Updated: ${safeUpdated}`);
    
    return {
      success: true,
      totalFound: safeTotal,
      totalAdded: safeAdded,
      totalUpdated: safeUpdated,
      timestamp: new Date()
    };

  } catch (error) {
    console.error('❌ Sync failed:', error);
    
    if (syncRecord) {
      try {
        await syncRecord.update({
          status: 'failed',
          endTime: new Date(),
          billsFound: 0,
          billsAdded: 0,
          billsUpdated: 0,
          errorMessage: error.message
        });
      } catch (updateError) {
        console.error('Failed to update sync record:', updateError);
      }
    }
    
    return { success: false, error: error.message };
  }
}

// Auth middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
    const user = await User.findByPk(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// ===== API ROUTES =====

app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

app.get('/api', (req, res) => {
  res.json({ 
    message: 'Legislative Tracker API with LegiScan Integration', 
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    features: ['User Management', 'Bill Tracking', 'LegiScan Integration', 'Automated Sync'],
    endpoints: [
      'POST /api/auth/register',
      'POST /api/auth/login', 
      'GET /api/auth/profile',
      'GET /api/bills',
      'GET /api/bills/:id',
      'POST /api/bills/:id/watch',
      'GET /api/bills/watchlist/mine',
      'GET /api/admin/users/pending',
      'POST /api/admin/users/:id/approve',
      'POST /api/admin/sync-bills',
      'GET /api/admin/sync-status'
    ]
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: 'connected',
    legiscan: 'active'
  });
});

// FIXED Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, organization } = req.body;

    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.create({
      email,
      passwordHash,
      firstName,
      lastName,
      organization,
      status: 'pending'
    });

    res.status(201).json({
      message: 'Registration successful. Account pending admin approval.',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    console.log(`🔐 Login attempt for: ${email}`);

    const user = await User.findOne({ where: { email } });
    if (!user) {
      console.log(`❌ User not found: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      console.log(`❌ Invalid password for: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.status !== 'approved') {
      const message = user.status === 'pending' 
        ? 'Account pending admin approval' 
        : 'Account suspended';
      console.log(`❌ Account not approved: ${email} - ${user.status}`);
      return res.status(403).json({ error: message });
    }

    const accessToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    console.log(`✅ Login successful for: ${email}`);

    res.json({
      message: 'Login successful',
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        status: user.status,
        organization: user.organization
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

app.get('/api/auth/profile', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Bills routes
app.get('/api/bills', authenticateToken, async (req, res) => {
  try {
    const { 
      search, state, status, minRelevance = 0, page = 1, limit = 20,
      sortBy = 'createdAt', sortOrder = 'DESC', source = 'all'
    } = req.query;

    const where = { isActive: true };
    
    if (search) {
      where[Op.or] = [
        { title: { [Op.iLike]: `%${search}%` } },
        { description: { [Op.iLike]: `%${search}%` } },
        { billNumber: { [Op.iLike]: `%${search}%` } },
        { keywords: { [Op.iLike]: `%${search}%` } }
      ];
    }

    if (state && state !== 'ALL') {
      where.stateCode = state;
    }

    if (status && status !== 'all') {
      where.status = { [Op.iLike]: `%${status}%` };
    }

    if (minRelevance > 0) {
      where.relevanceScore = { [Op.gte]: parseInt(minRelevance) };
    }

    if (source !== 'all') {
      where.sourceType = source;
    }

    const offset = (parseInt(page) - 1) * parseInt(limit);

    const bills = await Bill.findAndCountAll({
      where,
      order: [[sortBy, sortOrder.toUpperCase()]],
      limit: parseInt(limit),
      offset: offset
    });

    res.json({
      bills: bills.rows,
      pagination: {
        total: bills.count,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(bills.count / parseInt(limit))
      },
      filters: { search, state, status, minRelevance, source },
      stats: {
        totalBills: bills.count,
        legiscanBills: bills.rows.filter(b => b.sourceType === 'legiscan').length,
        manualBills: bills.rows.filter(b => b.sourceType === 'manual').length
      }
    });
  } catch (error) {
    console.error('Error fetching bills:', error);
    res.status(500).json({ error: 'Failed to fetch bills', details: error.message });
  }
});

app.get('/api/bills/:id', authenticateToken, async (req, res) => {
  try {
    const bill = await Bill.findByPk(req.params.id);
    if (!bill) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    const isWatched = await UserWatchlist.findOne({
      where: { userId: req.user.id, billId: bill.id }
    });

    res.json({
      ...bill.toJSON(),
      isWatched: !!isWatched
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch bill' });
  }
});

app.post('/api/bills/:id/watch', authenticateToken, async (req, res) => {
  try {
    const { notes } = req.body;

    const existing = await UserWatchlist.findOne({
      where: { userId: req.user.id, billId: req.params.id }
    });

    if (existing) {
      return res.status(409).json({ error: 'Bill already in watchlist' });
    }

    const watchItem = await UserWatchlist.create({
      userId: req.user.id,
      billId: req.params.id,
      notes
    });

    res.status(201).json({ message: 'Bill added to watchlist', watchItem });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add to watchlist' });
  }
});

app.get('/api/bills/watchlist/mine', authenticateToken, async (req, res) => {
  try {
    const watchlist = await UserWatchlist.findAll({
      where: { userId: req.user.id },
      include: [Bill]
    });

    res.json({ watchlist });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch watchlist' });
  }
});

// Admin routes
app.get('/api/admin/users/pending', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const pendingUsers = await User.findAll({
      where: { status: 'pending' },
      attributes: { exclude: ['passwordHash'] }
    });

    res.json({ users: pendingUsers });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending users' });
  }
});

app.post('/api/admin/users/:id/approve', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    await user.update({ status: 'approved' });
    res.json({ message: 'User approved successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to approve user' });
  }
});

app.post('/api/admin/sync-bills', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    console.log(`🔄 Manual sync triggered by ${req.user.email}`);
    
    syncRelevantBills().catch(error => {
      console.error('Background sync failed:', error);
    });
    
    res.json({
      message: 'Bill synchronization started in background',
      status: 'initiated',
      timestamp: new Date()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to start sync', details: error.message });
  }
});

app.get('/api/admin/sync-status', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const recentSyncs = await SyncStatus.findAll({
      order: [['startTime', 'DESC']],
      limit: 10
    });

    const totalBills = await Bill.count();
    const legiscanBills = await Bill.count({ where: { legiscanId: { [Op.ne]: null } } });

    res.json({
      apiStatus: 'active',
      totalBills,
      legiscanBills,
      manualBills: totalBills - legiscanBills,
      recentSyncs: recentSyncs.length,
      lastSync: recentSyncs[0]?.endTime || null,
      currentlyRunning: recentSyncs.some(sync => sync.status === 'running'),
      syncHistory: recentSyncs.map(sync => ({
        id: sync.id,
        type: sync.syncType,
        status: sync.status,
        startTime: sync.startTime,
        endTime: sync.endTime,
        billsFound: sync.billsFound,
        billsAdded: sync.billsAdded,
        billsUpdated: sync.billsUpdated,
        duration: sync.endTime ? Math.round((new Date(sync.endTime) - new Date(sync.startTime)) / 1000) : null
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get sync status' });
  }
});

// Frontend routes
app.get('/dashboard', (req, res) => {
  const frontendPath = path.join(__dirname, 'frontend.html');
  if (require('fs').existsSync(frontendPath)) {
    res.sendFile(frontendPath);
  } else {
    res.json({ message: 'Legislative Tracker API', status: 'Frontend not found' });
  }
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'frontend/build')));
}

app.get('*', (req, res) => {
  const frontendPath = path.join(__dirname, 'frontend.html');
  if (require('fs').existsSync(frontendPath)) {
    res.sendFile(frontendPath);
  } else {
    res.redirect('/dashboard');
  }
});

// Server startup
const PORT = process.env.PORT || 3001;

async function startServer() {
  try {
    console.log('🔗 Connecting to database...');
    await sequelize.authenticate();
    console.log('✅ Database connected successfully');
    
    console.log('🔄 Syncing database...');
    await sequelize.sync({ force: false });
    console.log('✅ Database synced');

    const adminPassword = await bcrypt.hash('admin123', 12);
    const [admin] = await User.findOrCreate({
      where: { email: 'admin@example.com' },
      defaults: {
        email: 'admin@example.com',
        passwordHash: adminPassword,
        firstName: 'Admin',
        lastName: 'User',
        role: 'admin',
        status: 'approved'
      }
    });

    const existingBills = await Bill.count();
    if (existingBills === 0) {
      const sampleBills = [
        {
          stateCode: 'US',
          billNumber: 'HR1577',
          title: 'Stop Fentanyl Money Laundering Act',
          description: 'A bill to strengthen financial crime enforcement against fentanyl trafficking',
          status: 'In Committee',
          progressPercentage: 35,
          introducedDate: '2025-03-21',
          fundsAllocated: 'TBD',
          sourceType: 'manual',
          keywords: 'Financial crimes, Money laundering prevention',
          relevanceScore: 5
        },
        {
          stateCode: 'CA',
          billNumber: 'AB603',
          title: 'Asset Forfeiture: Human Trafficking',
          description: 'Amends California Control of Profits of Organized Crime Act',
          status: 'Committee Review',
          progressPercentage: 15,
          introducedDate: '2025-03-19',
          fundsAllocated: 'Not specified',
          sourceType: 'manual',
          keywords: 'Asset forfeiture, Law enforcement training',
          relevanceScore: 3
        }
      ];

      for (const billData of sampleBills) {
        await Bill.findOrCreate({
          where: { billNumber: billData.billNumber, stateCode: billData.stateCode },
          defaults: billData
        });
      }
      console.log('✅ Sample bills created');
    }

    console.log('👤 Admin login: admin@example.com / admin123');
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📡 API available at: http://localhost:${PORT}/api`);
      console.log(`🏥 Health check: http://localhost:${PORT}/health`);
      console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
      console.log(`🔧 LegiScan Status: Active - Syncing every 2 minutes`);
    });

    setTimeout(() => {
      console.log('📅 Scheduling automatic bill sync every 2 minutes...');
      cron.schedule('*/2 * * * *', async () => {
        console.log('🕐 Running scheduled bill sync...');
        await syncRelevantBills();
      });

      setTimeout(async () => {
        console.log('🚀 Running initial bill sync...');
        await syncRelevantBills();
      }, 30000);
    }, 5000);
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();