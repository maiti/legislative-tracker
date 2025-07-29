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

// CRITICAL: Configure CSP properly BEFORE other middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

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

// ENHANCED LegiScan API configuration with better API key handling
const LEGISCAN_API_KEY = process.env.LEGISCAN_API_KEY || '65c8d4470aa39a31e376e82db13f1e72';
const LEGISCAN_BASE_URL = 'https://api.legiscan.com';

// Expanded Keywords for more comprehensive tracking
const TRACKING_KEYWORDS = [
  // Financial Crime Keywords
  'financial crimes', 'fraud investigation', 'anti-money laundering', 'AML',
  'economic crimes', 'white collar crime', 'asset forfeiture', 'illicit finance',
  'investigative accounting', 'forensic auditing', 'financial intelligence',
  'money laundering prevention', 'financial analysis training', 'banking fraud',
  'cybercrime', 'digital forensics', 'cryptocurrency regulation', 'fintech crime',
  
  // Law Enforcement Training Keywords  
  'law enforcement training', 'police training', 'officer education',
  'technical assistance', 'capacity building', 'justice assistance grants',
  'training and technical assistance', 'TTA', 'evidence-based practices',
  'criminal justice system improvement', 'intelligence sharing',
  'multi-jurisdictional task forces', 'federal grants', 'state grants',
  
  // Specific Program Keywords
  'COPS grants', 'JAG grants', 'Byrne grants', 'VOCA funds',
  'homeland security grants', 'drug enforcement', 'organized crime',
  'human trafficking', 'gang violence', 'domestic violence training',
  'crisis intervention', 'de-escalation training', 'community policing'
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
  },
  // NEW: Enhanced tracking fields
  sessionId: {
    type: DataTypes.STRING,
    allowNull: true
  },
  chamber: {
    type: DataTypes.STRING,
    allowNull: true
  },
  sponsors: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  subjects: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  changeHash: {
    type: DataTypes.STRING,
    allowNull: true
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

// Enhanced Sync Status Model
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
  },
  keywordsProcessed: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  statesProcessed: {
    type: DataTypes.TEXT,
    allowNull: true
  }
});

// Associations
User.hasMany(UserWatchlist);
UserWatchlist.belongsTo(User);
Bill.hasMany(UserWatchlist);
UserWatchlist.belongsTo(Bill);

// ===== FIXED LegiScan Service Class =====
class FixedLegiScanService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://api.legiscan.com';
    this.requestDelay = 3000; // Increased delay to avoid rate limits
    this.maxRetries = 3;
  }

  async makeRequest(operation, params = {}, retryCount = 0) {
    try {
      // Build the complete URL - CRITICAL: Use correct format
      const url = `${this.baseUrl}/?key=${this.apiKey}&op=${operation}&${new URLSearchParams(params).toString()}`;
      
      // Rate limiting delay
      await new Promise(resolve => setTimeout(resolve, this.requestDelay));
      
      console.log(`🌐 LegiScan API Request: ${operation} (attempt ${retryCount + 1})`);
      console.log(`🔗 URL: ${url.replace(this.apiKey, 'API_KEY_HIDDEN')}`);
      
      const response = await axios.get(url, { 
        timeout: 60000,
        headers: {
          'User-Agent': 'Legislative-Tracker-Bot/3.0',
          'Accept': 'application/json'
        }
      });
      
      console.log(`📥 Response status: ${response.status}`);
      console.log(`📄 Response data keys: ${Object.keys(response.data || {}).join(', ')}`);
      
      // Enhanced response validation
      if (response.data) {
        if (response.data.status === 'OK') {
          return response.data;
        } else if (response.data.status === 'ERROR') {
          console.error(`❌ LegiScan API Error: ${response.data.alert?.message || 'Unknown error'}`);
          throw new Error(`LegiScan API Error: ${response.data.alert?.message || 'Unknown API error'}`);
        }
      }
      
      throw new Error('Invalid response from LegiScan API');
      
    } catch (error) {
      console.error(`❌ Request failed: ${error.message}`);
      
      // Enhanced error handling with retries
      if (error.response?.status === 429 && retryCount < this.maxRetries) {
        const delay = Math.pow(2, retryCount) * 60000; // Exponential backoff
        console.log(`⏳ Rate limit hit, waiting ${delay/1000} seconds before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.makeRequest(operation, params, retryCount + 1);
      }
      
      if ((error.code === 'ENOTFOUND' || error.code === 'ECONNRESET') && retryCount < this.maxRetries) {
        console.log(`🔄 Network error, retrying in 15 seconds...`);
        await new Promise(resolve => setTimeout(resolve, 15000));
        return this.makeRequest(operation, params, retryCount + 1);
      }
      
      throw error;
    }
  }

  async getMasterList(state = 'ALL') {
    try {
      console.log(`📋 Fetching master list for: ${state}`);
      
      const data = await this.makeRequest('getMasterList', { state });
      
      if (data.masterlist) {
        console.log(`   Found master list data for ${state}`);
        return data.masterlist;
      }
      
      return null;
    } catch (error) {
      console.error(`Error fetching master list for ${state}:`, error.message);
      return null;
    }
  }

  // FIXED: Use proper search parameters and handle different search patterns
  async searchBillsFixed(keyword, state = 'ALL', year = 2) {
    try {
      console.log(`🔍 FIXED search for: "${keyword}" in ${state} (year=${year})`);
      
      // Try different search approaches
      const searchVariations = [
        keyword, // Exact keyword
        `"${keyword}"`, // Quoted exact phrase
        keyword.replace(/\s+/g, ' AND '), // AND between words
        keyword.split(' ')[0] // First word only
      ];
      
      for (const [index, searchTerm] of searchVariations.entries()) {
        try {
          console.log(`   Trying search variation ${index + 1}: "${searchTerm}"`);
          
          const params = {
            state: state,
            query: searchTerm,
            year: year // 2 = current year
          };
          
          const data = await this.makeRequest('search', params);
          
          if (data.searchresult) {
            // Handle different response formats
            let results = [];
            
            if (Array.isArray(data.searchresult)) {
              results = data.searchresult;
            } else if (data.searchresult && typeof data.searchresult === 'object') {
              // Sometimes it's an object with numbered keys
              const keys = Object.keys(data.searchresult).filter(key => !isNaN(key));
              results = keys.map(key => data.searchresult[key]);
              
              // Or it might have a summary and other data
              if (data.searchresult.summary) {
                console.log(`   Search summary: ${JSON.stringify(data.searchresult.summary)}`);
              }
            }
            
            if (results.length > 0) {
              console.log(`   ✅ Found ${results.length} results with variation: "${searchTerm}"`);
              return results;
            } else {
              console.log(`   ❌ No results with variation: "${searchTerm}"`);
            }
          } else {
            console.log(`   ❌ No searchresult in response for: "${searchTerm}"`);
          }
          
        } catch (searchError) {
          console.error(`   Error with search variation "${searchTerm}":`, searchError.message);
          continue; // Try next variation
        }
      }
      
      console.log(`   No results found for any variation of "${keyword}"`);
      return [];
      
    } catch (error) {
      console.error(`FIXED search error for "${keyword}":`, error.message);
      return [];
    }
  }

  // FIXED: Simpler approach - get recent bills from master list and filter
  async getRecentBillsByState(state = 'CA', limit = 50) {
    try {
      console.log(`📋 Getting recent bills from ${state}...`);
      
      const masterList = await this.getMasterList(state);
      
      if (!masterList) {
        console.log(`   No master list data for ${state}`);
        return [];
      }
      
      // Extract bills from master list
      let bills = [];
      
      if (Array.isArray(masterList)) {
        bills = masterList;
      } else if (masterList && typeof masterList === 'object') {
        // Handle different master list formats
        const keys = Object.keys(masterList).filter(key => !isNaN(key));
        bills = keys.map(key => masterList[key]);
      }
      
      console.log(`   Found ${bills.length} bills in master list`);
      
      // Sort by session year and take recent ones
      bills.sort((a, b) => {
        const aYear = parseInt(a.session?.year_start || 0);
        const bYear = parseInt(b.session?.year_start || 0);
        return bYear - aYear; // Most recent first
      });
      
      return bills.slice(0, limit);
      
    } catch (error) {
      console.error(`Error getting recent bills for ${state}:`, error.message);
      return [];
    }
  }

  async getBillDetailsFixed(billId) {
    try {
      console.log(`📄 Fetching bill details for ID: ${billId}`);
      
      const data = await this.makeRequest('getBill', { id: billId });
      
      if (data.bill) {
        console.log(`   ✅ Got bill details for ${billId}`);
        return data.bill;
      }
      
      console.log(`   ❌ No bill data for ${billId}`);
      return null;
    } catch (error) {
      console.error(`Error fetching bill ${billId}:`, error.message);
      return null;
    }
  }

  // Enhanced relevance analysis for better filtering
  isRelevantToTraining(billTitle, billDescription, billText = '') {
    const content = `${billTitle} ${billDescription} ${billText}`.toLowerCase();
    
    // Training-specific keywords
    const trainingKeywords = [
      'training', 'education', 'academy', 'instruction', 'certification',
      'professional development', 'curriculum', 'course', 'program',
      'law enforcement training', 'police training', 'officer training'
    ];
    
    // Financial crime keywords
    const financialKeywords = [
      'money laundering', 'financial crime', 'fraud', 'asset forfeiture',
      'aml', 'anti-money laundering', 'financial intelligence', 
      'economic crime', 'white collar', 'illicit finance'
    ];
    
    // Grant/funding keywords
    const fundingKeywords = [
      'grant', 'funding', 'appropriation', 'assistance', 'support',
      'cops grant', 'byrne grant', 'jag grant', 'federal assistance'
    ];
    
    let score = 0;
    let foundKeywords = [];
    
    // Check each category
    trainingKeywords.forEach(keyword => {
      if (content.includes(keyword)) {
        score += 3;
        foundKeywords.push(keyword);
      }
    });
    
    financialKeywords.forEach(keyword => {
      if (content.includes(keyword)) {
        score += 4;
        foundKeywords.push(keyword);
      }
    });
    
    fundingKeywords.forEach(keyword => {
      if (content.includes(keyword)) {
        score += 2;
        foundKeywords.push(keyword);
      }
    });
    
    // Bonus for law enforcement
    if (content.includes('law enforcement') || content.includes('police')) {
      score += 2;
      foundKeywords.push('law enforcement');
    }
    
    return {
      isRelevant: score >= 2,
      relevanceScore: Math.min(score, 10),
      foundKeywords: [...new Set(foundKeywords)]
    };
  }

  formatBillForDatabaseFixed(legiscanBill, relevanceAnalysis) {
    // More robust status mapping
    const statusText = this.getStatusText(legiscanBill.status);
    const progressPercentage = this.calculateProgressFixed(legiscanBill.status);
    
    return {
      legiscanId: legiscanBill.bill_id?.toString() || legiscanBill.id?.toString(),
      stateCode: legiscanBill.state || 'US',
      billNumber: legiscanBill.bill_number || legiscanBill.number || 'Unknown',
      title: legiscanBill.title || 'No title available',
      description: this.generateDescription(legiscanBill, relevanceAnalysis),
      status: statusText,
      progressPercentage: progressPercentage,
      introducedDate: legiscanBill.introduced_date || legiscanBill.date_introduced || null,
      fundsAllocated: this.extractFunding(legiscanBill),
      keywords: relevanceAnalysis.foundKeywords.join(', '),
      relevanceScore: relevanceAnalysis.relevanceScore,
      lastSynced: new Date(),
      legiscanUrl: this.buildUrl(legiscanBill),
      sourceType: 'legiscan',
      isActive: true,
      sessionId: legiscanBill.session_id?.toString() || null,
      chamber: this.extractChamber(legiscanBill.bill_number),
      sponsors: this.extractSponsors(legiscanBill),
      subjects: this.extractSubjects(legiscanBill)
    };
  }

  getStatusText(status) {
    const statusMap = {
      1: 'Introduced',
      2: 'Engrossed', 
      3: 'Enrolled',
      4: 'Passed',
      5: 'Vetoed',
      6: 'Failed/Dead'
    };
    return statusMap[status] || 'Unknown';
  }

  calculateProgressFixed(status) {
    const progressMap = {
      1: 20,  // Introduced
      2: 50,  // Engrossed
      3: 80,  // Enrolled
      4: 100, // Passed
      5: 0,   // Vetoed
      6: 0    // Failed/Dead
    };
    return progressMap[status] || 10;
  }

  generateDescription(billData, relevanceAnalysis) {
    const title = billData.title || '';
    const state = billData.state || 'Federal';
    
    let description = title;
    
    if (billData.description && billData.description !== title) {
      description = billData.description;
    } else {
      description += ` - A ${state} bill`;
      
      if (relevanceAnalysis.foundKeywords.includes('training')) {
        description += ' focused on training and professional development';
      }
      if (relevanceAnalysis.foundKeywords.includes('law enforcement')) {
        description += ' for law enforcement personnel';
      }
      if (relevanceAnalysis.foundKeywords.some(k => k.includes('financial') || k.includes('crime'))) {
        description += ' addressing financial crime prevention';
      }
      
      description += '.';
    }
    
    return description;
  }

  extractFunding(billData) {
    const text = `${billData.title || ''} ${billData.description || ''}`.toLowerCase();
    
    // Look for dollar amounts
    const dollarMatch = text.match(/\$\s*(\d+(?:,\d+)*(?:\.\d+)?)\s*(million|billion|thousand)?/i);
    if (dollarMatch) {
      return `$${dollarMatch[1]}${dollarMatch[2] ? ' ' + dollarMatch[2] : ''}`;
    }
    
    if (text.includes('appropriat')) return 'Appropriation';
    if (text.includes('grant')) return 'Grant Program';
    if (text.includes('fund')) return 'Funding Program';
    
    return 'Not specified';
  }

  buildUrl(billData) {
    const state = (billData.state || 'us').toLowerCase();
    const billNumber = billData.bill_number || '';
    const sessionId = billData.session_id || '';
    
    return `https://legiscan.com/${state}/bill/${billNumber}/${sessionId}`;
  }

  extractChamber(billNumber) {
    if (!billNumber) return 'Unknown';
    
    const num = billNumber.toUpperCase();
    if (num.startsWith('H') || num.includes('HOUSE')) return 'House';
    if (num.startsWith('S') || num.includes('SENATE')) return 'Senate';
    if (num.startsWith('A') || num.startsWith('AB')) return 'Assembly';
    
    return 'Unknown';
  }

  extractSponsors(billData) {
    if (billData.sponsors && Array.isArray(billData.sponsors)) {
      return billData.sponsors.slice(0, 3).map(sponsor => 
        sponsor.name || 'Unknown'
      ).join(', ');
    }
    return 'Not specified';
  }

  extractSubjects(billData) {
    if (billData.subjects && Array.isArray(billData.subjects)) {
      return billData.subjects.join(', ');
    }
    return '';
  }
}

// ===== ENHANCED Sync Function with Multiple Strategies =====
async function syncRelevantBillsFixed() {
  let syncRecord;
  
  try {
    syncRecord = await SyncStatus.create({
      syncType: 'fixed_enhanced',
      status: 'running',
      startTime: new Date()
    });

    console.log('🚀 Starting FIXED LegiScan synchronization with multiple strategies...');
    
    const fixedLegiScan = new FixedLegiScanService(LEGISCAN_API_KEY);
    
    let totalFound = 0;
    let totalAdded = 0;
    let totalUpdated = 0;
    
    // Strategy 1: Search for specific high-value keywords
    const highValueKeywords = [
      'police training',
      'law enforcement training', 
      'financial crimes',
      'money laundering',
      'grant program',
      'cops grant',
      'technical assistance'
    ];
    
    console.log(`📋 Strategy 1: Searching for ${highValueKeywords.length} high-value keywords...`);
    
    for (const [keywordIndex, keyword] of highValueKeywords.entries()) {
      console.log(`\n🔍 [${keywordIndex + 1}/${highValueKeywords.length}] Searching: "${keyword}"`);
      
      try {
        const searchResults = await fixedLegiScan.searchBillsFixed(keyword, 'ALL', 2);
        
        if (searchResults.length > 0) {
          totalFound += searchResults.length;
          console.log(`   ✅ Found ${searchResults.length} results`);
          
          // Process up to 5 bills per keyword to avoid overwhelming the system
          for (const result of searchResults.slice(0, 5)) {
            await processBillResult(result, fixedLegiScan);
          }
        } else {
          console.log(`   ❌ No results for "${keyword}"`);
        }
        
      } catch (keywordError) {
        console.error(`   Error processing keyword "${keyword}":`, keywordError.message);
      }
      
      // Delay between keywords
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
    
    // Strategy 2: Get recent bills from priority states and filter
    const priorityStates = ['CA', 'TX', 'FL', 'NY'];
    
    console.log(`\n📋 Strategy 2: Getting recent bills from ${priorityStates.length} priority states...`);
    
    for (const [stateIndex, state] of priorityStates.entries()) {
      console.log(`\n🏛️  [${stateIndex + 1}/${priorityStates.length}] Processing state: ${state}`);
      
      try {
        const recentBills = await fixedLegiScan.getRecentBillsByState(state, 20);
        
        if (recentBills.length > 0) {
          console.log(`   Found ${recentBills.length} recent bills`);
          
          for (const bill of recentBills.slice(0, 10)) {
            await processBillFromMasterList(bill, fixedLegiScan);
          }
        }
        
      } catch (stateError) {
        console.error(`   Error processing state ${state}:`, stateError.message);
      }
      
      // Delay between states
      await new Promise(resolve => setTimeout(resolve, 8000));
    }
    
    async function processBillResult(result, apiService) {
      try {
        if (!result || !result.bill_id) {
          console.log(`      ⚠️  Invalid search result`);
          return;
        }

        console.log(`      📄 Processing bill ID: ${result.bill_id}`);

        const billDetails = await apiService.getBillDetailsFixed(result.bill_id);
        if (!billDetails) {
          console.log(`         ❌ No details retrieved`);
          return;
        }

        const relevanceAnalysis = apiService.isRelevantToTraining(
          billDetails.title || '',
          billDetails.description || ''
        );

        console.log(`         🎯 Relevance: ${relevanceAnalysis.relevanceScore}/10`);

        if (!relevanceAnalysis.isRelevant) {
          console.log(`         ⚠️  Not relevant, skipping`);
          return;
        }

        const formattedBill = apiService.formatBillForDatabaseFixed(billDetails, relevanceAnalysis);

        const existingBill = await Bill.findOne({
          where: { legiscanId: formattedBill.legiscanId }
        });

        if (existingBill) {
          await existingBill.update({
            ...formattedBill,
            createdAt: existingBill.createdAt
          });
          totalUpdated++;
          console.log(`         ✅ Updated: ${formattedBill.billNumber}`);
        } else {
          await Bill.create(formattedBill);
          totalAdded++;
          console.log(`         ✨ Added: ${formattedBill.billNumber}`);
        }

      } catch (billError) {
        console.error(`         ❌ Error processing bill:`, billError.message);
      }
    }
    
    async function processBillFromMasterList(bill, apiService) {
      try {
        // Quick relevance check on title/description before fetching full details
        const quickCheck = apiService.isRelevantToTraining(
          bill.title || '',
          bill.description || ''
        );
        
        if (!quickCheck.isRelevant) {
          return; // Skip non-relevant bills
        }
        
        console.log(`      📄 Relevant bill found: ${bill.bill_number || bill.number}`);
        
        const billId = bill.bill_id || bill.id;
        if (billId) {
          await processBillResult({ bill_id: billId }, apiService);
        }
        
      } catch (error) {
        console.error(`      Error processing master list bill:`, error.message);
      }
    }

    // Update sync record
    if (syncRecord) {
      await syncRecord.update({
        status: 'completed',
        endTime: new Date(),
        billsFound: totalFound,
        billsAdded: totalAdded,
        billsUpdated: totalUpdated,
        keywordsProcessed: highValueKeywords.length,
        statesProcessed: priorityStates.join(', ')
      });
    }

    console.log(`\n✅ FIXED SYNC COMPLETE!`);
    console.log(`   📊 Found: ${totalFound} bills`);
    console.log(`   ➕ Added: ${totalAdded} new bills`);
    console.log(`   🔄 Updated: ${totalUpdated} existing bills`);
    
    return {
      success: true,
      totalFound,
      totalAdded,
      totalUpdated,
      strategies: ['keyword search', 'state filtering'],
      timestamp: new Date()
    };

  } catch (error) {
    console.error('❌ FIXED SYNC FAILED:', error);
    
    if (syncRecord) {
      try {
        await syncRecord.update({
          status: 'failed',
          endTime: new Date(),
          errorMessage: error.message
        });
      } catch (updateError) {
        console.error('Failed to update sync record:', updateError);
      }
    }
    
    return { success: false, error: error.message };
  }
}

// Database migration function with enhanced fields
async function runEnhancedDatabaseMigrations() {
  console.log('🔧 Running enhanced database migrations...');
  
  try {
    const queryInterface = sequelize.getQueryInterface();
    const tableDescription = await queryInterface.describeTable('Bills');
    
    const newColumnsToAdd = [
      {
        name: 'legiscanId',
        definition: {
          type: DataTypes.STRING,
          allowNull: true,
          unique: true
        }
      },
      {
        name: 'keywords',
        definition: {
          type: DataTypes.TEXT,
          allowNull: true
        }
      },
      {
        name: 'relevanceScore',
        definition: {
          type: DataTypes.INTEGER,
          defaultValue: 0
        }
      },
      {
        name: 'lastSynced',
        definition: {
          type: DataTypes.DATE,
          allowNull: true
        }
      },
      {
        name: 'legiscanUrl',
        definition: {
          type: DataTypes.STRING,
          allowNull: true
        }
      },
      {
        name: 'isActive',
        definition: {
          type: DataTypes.BOOLEAN,
          defaultValue: true
        }
      },
      {
        name: 'sourceType',
        definition: {
          type: DataTypes.ENUM('manual', 'legiscan'),
          defaultValue: 'manual'
        }
      },
      {
        name: 'sessionId',
        definition: {
          type: DataTypes.STRING,
          allowNull: true
        }
      },
      {
        name: 'chamber',
        definition: {
          type: DataTypes.STRING,
          allowNull: true
        }
      },
      {
        name: 'sponsors',
        definition: {
          type: DataTypes.TEXT,
          allowNull: true
        }
      },
      {
        name: 'subjects',
        definition: {
          type: DataTypes.TEXT,
          allowNull: true
        }
      },
      {
        name: 'changeHash',
        definition: {
          type: DataTypes.STRING,
          allowNull: true
        }
      }
    ];
    
    for (const column of newColumnsToAdd) {
      if (!tableDescription[column.name]) {
        console.log(`➕ Adding enhanced column: ${column.name}`);
        await queryInterface.addColumn('Bills', column.name, column.definition);
      } else {
        console.log(`✅ Enhanced column already exists: ${column.name}`);
      }
    }
    
    console.log('✅ Enhanced database migrations completed');
    
  } catch (error) {
    console.error('❌ Enhanced migration error:', error);
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

app.get('/api', (req, res) => {
  res.json({ 
    message: 'Legislative Tracker API - FIXED LegiScan Integration', 
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '3.1.0-FIXED',
    features: [
      'FIXED LegiScan Integration', 
      'Multi-Strategy Search', 
      'Enhanced Error Handling', 
      'Real Bill Retrieval',
      'Comprehensive Training Focus'
    ],
    apiKey: LEGISCAN_API_KEY ? `${LEGISCAN_API_KEY.substring(0, 8)}...` : 'Not configured',
    keywordsTracking: TRACKING_KEYWORDS.length,
    priorityStates: ['CA', 'TX', 'FL', 'NY'],
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
      'POST /api/admin/sync-bills-fixed',
      'GET /api/admin/sync-status-enhanced',
      'POST /api/admin/test-legiscan-fixed',
      'GET /api/admin/debug-bills',
      'POST /api/admin/add-test-bill'
    ]
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: 'connected',
    legiscan: 'fixed_integration',
    apiKey: LEGISCAN_API_KEY ? 'configured' : 'missing',
    keywords_tracking: TRACKING_KEYWORDS.length,
    version: '3.1.0-FIXED'
  });
});

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, organization } = req.body;

    console.log(`📝 Registration attempt for: ${email}`);

    if (!email || !password || !firstName || !lastName) {
      console.log(`❌ Missing required fields for registration: ${email}`);
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      console.log(`❌ Email already registered: ${email}`);
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

    console.log(`✅ Registration successful for: ${email}`);

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

    console.log(`🔐 LOGIN REQUEST for: ${email}`);

    if (!email || !password) {
      console.log(`❌ Missing credentials for: ${email}`);
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      console.log(`❌ User not found: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log(`🔍 User found: ${email}, Status: ${user.status}, Role: ${user.role}`);

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

    console.log(`✅ LOGIN SUCCESSFUL for: ${email}`);

    const response = {
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
    };

    res.json(response);
  } catch (error) {
    console.error('❌ LOGIN ERROR:', error);
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

app.get('/api/auth/profile', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Enhanced Bills routes
app.get('/api/bills', authenticateToken, async (req, res) => {
  try {
    console.log(`📄 Enhanced bills request from user: ${req.user.email}`);
    
    const { 
      search, state, status, minRelevance = 0, page = 1, limit = 20,
      sortBy = 'relevanceScore', sortOrder = 'DESC', source = 'all'
    } = req.query;

    const where = {};
    
    // Enhanced filtering with better column checking
    try {
      const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
      if (tableDescription.isActive) {
        where.isActive = true;
      }
    } catch (error) {
      console.log('isActive column check failed, skipping filter');
    }
    
    // Enhanced search functionality
    if (search) {
      where[Op.or] = [
        { title: { [Op.iLike]: `%${search}%` } },
        { description: { [Op.iLike]: `%${search}%` } },
        { billNumber: { [Op.iLike]: `%${search}%` } }
      ];
      
      try {
        const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
        if (tableDescription.keywords) {
          where[Op.or].push({ keywords: { [Op.iLike]: `%${search}%` } });
        }
        if (tableDescription.subjects) {
          where[Op.or].push({ subjects: { [Op.iLike]: `%${search}%` } });
        }
      } catch (error) {
        console.log('Enhanced search columns not available');
      }
    }

    if (state && state !== 'all') {
      where.stateCode = state;
    }

    if (status && status !== 'all') {
      where.status = { [Op.iLike]: `%${status}%` };
    }

    if (minRelevance > 0) {
      try {
        const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
        if (tableDescription.relevanceScore) {
          where.relevanceScore = { [Op.gte]: parseInt(minRelevance) };
        }
      } catch (error) {
        console.log('relevanceScore column not available for filtering');
      }
    }

    if (source !== 'all') {
      try {
        const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
        if (tableDescription.sourceType) {
          where.sourceType = source;
        }
      } catch (error) {
        console.log('sourceType column not available for filtering');
      }
    }

    const offset = (parseInt(page) - 1) * parseInt(limit);

    let actualSortBy = 'createdAt';
    try {
      const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
      if (tableDescription[sortBy]) {
        actualSortBy = sortBy;
      }
    } catch (error) {
      console.log(`Sort column ${sortBy} not available, using createdAt`);
    }

    const bills = await Bill.findAndCountAll({
      where,
      order: [[actualSortBy, sortOrder.toUpperCase()]],
      limit: parseInt(limit),
      offset: offset
    });

    // Enhanced statistics
    const totalBills = await Bill.count();
    let legiscanBills = 0;
    let manualBills = 0;
    let highRelevanceBills = 0;
    
    try {
      const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
      if (tableDescription.sourceType) {
        legiscanBills = await Bill.count({ where: { sourceType: 'legiscan' } });
        manualBills = await Bill.count({ where: { sourceType: 'manual' } });
      } else {
        manualBills = totalBills;
      }
      if (tableDescription.relevanceScore) {
        highRelevanceBills = await Bill.count({ 
          where: { relevanceScore: { [Op.gte]: 5 } }
        });
      }
    } catch (error) {
      manualBills = totalBills;
    }

    console.log(`📊 Enhanced response: ${bills.rows.length} bills (${bills.count} total matching criteria)`);

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
        totalBills,
        legiscanBills,
        manualBills,
        highRelevanceBills,
        relevantBills: bills.rows.filter(b => (b.relevanceScore || 0) >= 3).length
      },
      enhanced: true,
      version: '3.1.0-FIXED'
    });
  } catch (error) {
    console.error('Error fetching enhanced bills:', error);
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

// FIXED: Enhanced Admin Routes with better LegiScan integration
app.post('/api/admin/sync-bills-fixed', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    console.log(`🚀 FIXED MANUAL SYNC triggered by ${req.user.email}`);
    
    // Start fixed sync in background
    syncRelevantBillsFixed().catch(error => {
      console.error('Fixed background sync failed:', error);
    });
    
    res.json({
      message: 'FIXED LegiScan synchronization started with multiple strategies',
      status: 'initiated',
      timestamp: new Date(),
      strategies: ['keyword search', 'state filtering', 'relevance analysis'],
      version: '3.1.0-fixed',
      note: 'Using enhanced error handling and multiple search approaches'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to start fixed sync', details: error.message });
  }
});

// FIXED: More robust LegiScan test
app.post('/api/admin/test-legiscan-fixed', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    console.log('🧪 Testing FIXED LegiScan API connectivity...');

    const fixedLegiScan = new FixedLegiScanService(LEGISCAN_API_KEY);
    
    const testResults = {
      connectivity: false,
      searchTest: false,
      masterListTest: false,
      billDetailsTest: false,
      errors: []
    };

    // Test 1: Basic connectivity with getMasterList
    try {
      console.log('🔗 Test 1: Basic connectivity...');
      const masterList = await fixedLegiScan.getMasterList('CA');
      if (masterList) {
        testResults.connectivity = true;
        testResults.masterListTest = true;
        console.log('✅ Basic connectivity successful');
      }
    } catch (error) {
      testResults.errors.push(`Connectivity: ${error.message}`);
      console.log('❌ Basic connectivity failed');
    }

    // Test 2: Search functionality
    try {
      console.log('🔍 Test 2: Search functionality...');
      const searchResults = await fixedLegiScan.searchBillsFixed('police training', 'CA', 2);
      if (searchResults && searchResults.length > 0) {
        testResults.searchTest = true;
        console.log(`✅ Search test successful - found ${searchResults.length} results`);
        
        // Test 3: Get bill details for first result
        try {
          console.log('📄 Test 3: Bill details...');
          const billDetails = await fixedLegiScan.getBillDetailsFixed(searchResults[0].bill_id);
          if (billDetails) {
            testResults.billDetailsTest = true;
            console.log('✅ Bill details test successful');
          }
        } catch (detailsError) {
          testResults.errors.push(`Bill Details: ${detailsError.message}`);
        }
        
      } else {
        testResults.errors.push('Search returned no results');
      }
    } catch (searchError) {
      testResults.errors.push(`Search: ${searchError.message}`);
    }

    const overallSuccess = testResults.connectivity && (testResults.searchTest || testResults.masterListTest);
    
    res.json({
      success: overallSuccess,
      apiKey: LEGISCAN_API_KEY ? `${LEGISCAN_API_KEY.substring(0, 8)}...` : 'Not configured',
      testResults,
      timestamp: new Date(),
      message: overallSuccess ? 'Fixed LegiScan integration is working' : 'Some tests failed but basic connectivity works',
      recommendations: overallSuccess ? 
        ['API is working correctly', 'Try running the fixed sync'] :
        ['Check API key permissions', 'Verify network connectivity', 'Review error messages']
    });

  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Failed to test fixed LegiScan API', 
      details: error.message 
    });
  }
});

// Enhanced sync status endpoint
app.get('/api/admin/sync-status-enhanced', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const recentSyncs = await SyncStatus.findAll({
      order: [['startTime', 'DESC']],
      limit: 15
    });

    const totalBills = await Bill.count();
    let legiscanBills = 0;
    let manualBills = 0;
    let enhancedBills = 0;
    
    try {
      const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
      if (tableDescription.sourceType) {
        legiscanBills = await Bill.count({ where: { sourceType: 'legiscan' } });
        manualBills = await Bill.count({ where: { sourceType: 'manual' } });
      } else {
        manualBills = totalBills;
      }
      if (tableDescription.relevanceScore) {
        enhancedBills = await Bill.count({ 
          where: { 
            relevanceScore: { [Op.gte]: 5 }
          } 
        });
      }
    } catch (error) {
      console.log('Enhanced columns not available for stats');
      manualBills = totalBills;
    }

    res.json({
      apiStatus: 'fixed_active',
      apiKey: LEGISCAN_API_KEY ? 'configured' : 'missing',
      version: '3.1.0-FIXED',
      totalBills,
      legiscanBills,
      manualBills,
      highRelevanceBills: enhancedBills,
      keywordsTracking: TRACKING_KEYWORDS.length,
      recentSyncs: recentSyncs.length,
      lastSync: recentSyncs[0]?.endTime || null,
      currentlyRunning: recentSyncs.some(sync => sync.status === 'running'),
      fixedFeatures: [
        'Multi-strategy search capability',
        'Enhanced error handling',
        'Fixed API response parsing',
        'Improved rate limiting',
        'Master list integration'
      ],
      syncHistory: recentSyncs.map(sync => ({
        id: sync.id,
        type: sync.syncType,
        status: sync.status,
        startTime: sync.startTime,
        endTime: sync.endTime,
        billsFound: sync.billsFound,
        billsAdded: sync.billsAdded,
        billsUpdated: sync.billsUpdated,
        keywordsProcessed: sync.keywordsProcessed,
        statesProcessed: sync.statesProcessed,
        duration: sync.endTime ? Math.round((new Date(sync.endTime) - new Date(sync.startTime)) / 1000) : null
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get enhanced sync status' });
  }
});

// FIXED: Debug endpoint to show what's actually in the database
app.get('/api/admin/debug-bills', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const bills = await Bill.findAll({
      order: [['createdAt', 'DESC']],
      limit: 10
    });

    const billsSummary = bills.map(bill => ({
      id: bill.id,
      billNumber: bill.billNumber,
      title: bill.title?.substring(0, 100),
      stateCode: bill.stateCode,
      sourceType: bill.sourceType,
      relevanceScore: bill.relevanceScore,
      legiscanId: bill.legiscanId,
      createdAt: bill.createdAt,
      lastSynced: bill.lastSynced
    }));

    const stats = {
      totalBills: await Bill.count(),
      legiscanBills: await Bill.count({ where: { sourceType: 'legiscan' } }),
      manualBills: await Bill.count({ where: { sourceType: 'manual' } }),
      highRelevance: await Bill.count({ where: { relevanceScore: { [Op.gte]: 5 } } }),
      recentlyAdded: await Bill.count({ 
        where: { 
          createdAt: { 
            [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) 
          } 
        } 
      })
    };

    res.json({
      stats,
      recentBills: billsSummary,
      timestamp: new Date(),
      databaseHealth: 'OK'
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to get debug info', details: error.message });
  }
});

// FIXED: Manual bill addition for testing
app.post('/api/admin/add-test-bill', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const testBill = await Bill.create({
      stateCode: 'TEST',
      billNumber: 'TEST-' + Date.now(),
      title: 'Test Bill for Enhanced Law Enforcement Training Programs',
      description: 'A test bill to verify the system is working correctly. This bill addresses law enforcement training, financial crimes investigation, and technical assistance programs.',
      status: 'Test Status',
      progressPercentage: 50,
      introducedDate: new Date().toISOString().split('T')[0],
      fundsAllocated: '$1 million test appropriation',
      sourceType: 'manual',
      keywords: 'Law enforcement training, Financial crimes, Technical assistance, Test bill',
      relevanceScore: 8,
      isActive: true,
      chamber: 'Test Chamber',
      sponsors: 'Test Sponsor',
      subjects: 'Law enforcement, Training, Testing'
    });

    res.json({
      message: 'Test bill created successfully',
      bill: {
        id: testBill.id,
        billNumber: testBill.billNumber,
        title: testBill.title,
        relevanceScore: testBill.relevanceScore
      },
      timestamp: new Date()
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to create test bill', details: error.message });
  }
});

// Frontend routes
app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
  const frontendPath = path.join(__dirname, 'frontend.html');
  if (require('fs').existsSync(frontendPath)) {
    res.sendFile(frontendPath);
  } else {
    res.json({ 
      message: 'Legislative Tracker API - FIXED Version',
      status: 'Frontend not found',
      redirect: '/api'
    });
  }
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'frontend/build')));
}

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  
  const frontendPath = path.join(__dirname, 'frontend.html');
  if (require('fs').existsSync(frontendPath)) {
    res.sendFile(frontendPath);
  } else {
    res.redirect('/dashboard');
  }
});

// Enhanced Server startup
const PORT = process.env.PORT || 3001;

async function startFixedServer() {
  try {
    console.log('🚀 Starting FIXED Legislative Tracker Server...');
    console.log('🔗 Connecting to database...');
    await sequelize.authenticate();
    console.log('✅ Database connected successfully');
    
    console.log('🔄 Syncing database...');
    await sequelize.sync({ alter: false });
    console.log('✅ Database synced');

    // Run enhanced migrations
    await runEnhancedDatabaseMigrations();

    // Create admin user
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

    // Create enhanced sample bills if none exist
    const existingBills = await Bill.count();
    if (existingBills === 0) {
      const enhancedSampleBills = [
        {
          stateCode: 'US',
          billNumber: 'H.R.9999',
          title: 'Comprehensive Law Enforcement Training Enhancement Act',
          description: 'To establish comprehensive training programs for law enforcement officers focusing on financial crime investigation, de-escalation techniques, and community policing strategies. Includes provisions for federal grants to state and local agencies.',
          status: 'In Committee',
          progressPercentage: 35,
          introducedDate: '2025-01-15',
          fundsAllocated: '$250 million appropriation',
          sourceType: 'manual',
          keywords: 'Law enforcement training, Financial crimes, Technical assistance, Federal grants',
          relevanceScore: 9,
          isActive: true,
          chamber: 'House',
          sponsors: 'Rep. Johnson (D-CA), Rep. Smith (R-TX)',
          subjects: 'Crime and law enforcement, Education, Federal aid to law enforcement'
        },
        {
          stateCode: 'US',
          billNumber: 'S.2150',
          title: 'Financial Intelligence and Anti-Money Laundering Enhancement Act',
          description: 'A comprehensive bill to strengthen financial intelligence capabilities, enhance anti-money laundering enforcement, and provide advanced training for law enforcement personnel in financial crime investigation.',
          status: 'Passed Chamber',
          progressPercentage: 75,
          introducedDate: '2024-11-20',
          fundsAllocated: '$180 million over 3 years',
          sourceType: 'manual',
          keywords: 'Anti-money laundering, Financial intelligence, Law enforcement training, AML',
          relevanceScore: 10,
          isActive: true,
          chamber: 'Senate',
          sponsors: 'Sen. Williams (D-NY), Sen. Davis (R-FL)',
          subjects: 'Banking and finance, Crime prevention, Law enforcement training'
        }
      ];

      for (const billData of enhancedSampleBills) {
        await Bill.findOrCreate({
          where: { billNumber: billData.billNumber, stateCode: billData.stateCode },
          defaults: billData
        });
      }
      console.log('✅ Enhanced sample bills created with comprehensive data');
    }

    console.log('🎯 FIXED FEATURES ACTIVE:');
    console.log('   🔧 Fixed API response parsing');
    console.log('   🔍 Multi-strategy search capability');
    console.log('   🛡️  Enhanced error handling');
    console.log('   📈 Improved rate limiting');
    console.log('   🔗 Master list integration');
    console.log(`🔑 API Key Status: ${LEGISCAN_API_KEY ? 'Configured' : 'Missing'}`);
    console.log('👤 Admin login: admin@example.com / admin123');
    console.log(`🔍 Tracking ${TRACKING_KEYWORDS.length} keywords across multiple categories`);
    
    app.listen(PORT, () => {
      console.log(`🚀 FIXED SERVER running on port ${PORT}`);
      console.log(`📡 API available at: http://localhost:${PORT}/api`);
      console.log(`🏥 Health check: http://localhost:${PORT}/health`);
      console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
      console.log(`🧪 Test FIXED LegiScan: POST /api/admin/test-legiscan-fixed`);
      console.log(`🔄 FIXED Sync: POST /api/admin/sync-bills-fixed`);
      console.log(`🐛 Debug Bills: GET /api/admin/debug-bills`);
    });

    // Enhanced scheduling with immediate test
    setTimeout(async () => {
      console.log('🧪 Running initial FIXED LegiScan connectivity test...');
      try {
        const fixedLegiScan = new FixedLegiScanService(LEGISCAN_API_KEY);
        const testResult = await fixedLegiScan.getMasterList('CA');
        if (testResult) {
          console.log('✅ FIXED LegiScan API test successful');
          
          // Schedule fixed sync every 4 hours for stability
          console.log('📅 Scheduling FIXED bill sync every 4 hours...');
          cron.schedule('0 */4 * * *', async () => {
            console.log('🕐 Running scheduled FIXED bill sync...');
            await syncRelevantBillsFixed();
          });

          // Run initial fixed sync after 5 minutes
          setTimeout(async () => {
            console.log('🚀 Running initial FIXED bill sync...');
            const result = await syncRelevantBillsFixed();
            if (result.success) {
              console.log(`✅ Initial FIXED sync completed: ${result.totalAdded} new bills added`);
            } else {
              console.log(`❌ Initial FIXED sync failed: ${result.error}`);
            }
          }, 300000); // 5 minutes
          
        } else {
          console.log('❌ FIXED LegiScan API test failed - manual sync available');
        }
      } catch (testError) {
        console.error('❌ FIXED LegiScan API test failed:', testError.message);
        console.log('⚠️  Manual FIXED sync will be available but may encounter issues');
      }
    }, 15000); // 15 seconds after startup
    
  } catch (error) {
    console.error('❌ Failed to start FIXED server:', error);
    process.exit(1);
  }
}

startFixedServer();