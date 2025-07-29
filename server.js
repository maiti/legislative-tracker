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

// ===== ENHANCED LegiScan Service Class =====
class EnhancedLegiScanService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = LEGISCAN_BASE_URL;
    this.requestDelay = 2000; // Increased delay to avoid rate limits
    this.maxRetries = 3;
    this.sessionCache = new Map();
  }

  async makeRequest(operation, params = {}, retryCount = 0) {
    try {
      // Build the complete URL with operation and parameters
      const queryParams = new URLSearchParams({
        key: this.apiKey,
        op: operation,
        ...params
      });
      
      const url = `${this.baseUrl}/?${queryParams.toString()}`;
      
      // Rate limiting delay
      await new Promise(resolve => setTimeout(resolve, this.requestDelay));
      
      console.log(`🌐 LegiScan API Request: ${operation} (attempt ${retryCount + 1})`);
      
      const response = await axios.get(url, { 
        timeout: 45000,
        headers: {
          'User-Agent': 'Legislative-Tracker-Bot/2.0',
          'Accept': 'application/json'
        }
      });
      
      // Enhanced response validation
      if (response.data) {
        if (response.data.status === 'OK') {
          return response.data;
        } else if (response.data.status === 'ERROR') {
          throw new Error(`LegiScan API Error: ${response.data.alert?.message || 'Unknown API error'}`);
        }
      }
      
      throw new Error('Invalid response from LegiScan API');
      
    } catch (error) {
      // Enhanced error handling with retries
      if (error.response?.status === 429 && retryCount < this.maxRetries) {
        const delay = Math.pow(2, retryCount) * 30000; // Exponential backoff
        console.log(`⏳ Rate limit hit, waiting ${delay/1000} seconds before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.makeRequest(operation, params, retryCount + 1);
      }
      
      if (error.code === 'ENOTFOUND' || error.code === 'ECONNRESET') {
        if (retryCount < this.maxRetries) {
          console.log(`🔄 Network error, retrying in 10 seconds...`);
          await new Promise(resolve => setTimeout(resolve, 10000));
          return this.makeRequest(operation, params, retryCount + 1);
        }
      }
      
      throw error;
    }
  }

  async getSessionList(state = 'ALL') {
    try {
      console.log(`📋 Fetching session list for: ${state}`);
      
      const data = await this.makeRequest('getSessionList', { state });
      
      if (data.sessions) {
        const sessions = Array.isArray(data.sessions) ? data.sessions : [data.sessions];
        console.log(`   Found ${sessions.length} sessions for ${state}`);
        return sessions;
      }
      
      return [];
    } catch (error) {
      console.error(`Error fetching sessions for ${state}:`, error.message);
      return [];
    }
  }

  async searchBillsAdvanced(keyword, state = 'ALL', year = null, limit = 50) {
    try {
      const currentYear = year || new Date().getFullYear();
      console.log(`🔍 Enhanced search for: "${keyword}" in ${state} (${currentYear})`);
      
      // Get active sessions first
      let sessions = [];
      if (!this.sessionCache.has(state)) {
        sessions = await this.getSessionList(state);
        this.sessionCache.set(state, sessions);
      } else {
        sessions = this.sessionCache.get(state);
      }
      
      // Filter to current/recent sessions
      const recentSessions = sessions.filter(session => {
        const sessionYear = parseInt(session.year_start) || 0;
        return sessionYear >= currentYear - 1 && sessionYear <= currentYear + 1;
      });
      
      console.log(`   Using ${recentSessions.length} recent sessions`);
      
      const searchResults = [];
      
      // Search across recent sessions
      for (const session of recentSessions.slice(0, 5)) { // Limit to 5 most recent sessions
        try {
          const data = await this.makeRequest('search', {
            state: state,
            query: keyword,
            year: session.year_start || currentYear
          });
          
          if (data.searchresult && Array.isArray(data.searchresult)) {
            const results = data.searchresult.slice(0, limit);
            searchResults.push(...results);
            console.log(`     Found ${results.length} results in ${session.year_start} session`);
          }
          
        } catch (error) {
          console.error(`     Error searching session ${session.session_id}:`, error.message);
          continue;
        }
      }
      
      // Remove duplicates based on bill_id
      const uniqueResults = searchResults.filter((bill, index, self) =>
        index === self.findIndex(b => b.bill_id === bill.bill_id)
      );
      
      console.log(`   Total unique results: ${uniqueResults.length}`);
      return uniqueResults;
      
    } catch (error) {
      console.error(`Enhanced search error for "${keyword}":`, error.message);
      return [];
    }
  }

  async getBillDetailsEnhanced(billId) {
    try {
      console.log(`📄 Fetching enhanced bill details for ID: ${billId}`);
      
      const data = await this.makeRequest('getBill', { id: billId });
      
      if (data.bill) {
        // Also try to get bill text for better analysis
        try {
          const textData = await this.makeRequest('getBillText', { id: billId });
          if (textData.text && textData.text.doc) {
            data.bill.fullText = textData.text.doc;
          }
        } catch (textError) {
          console.log(`     No text available for bill ${billId}`);
        }
        
        return data.bill;
      }
      
      return null;
    } catch (error) {
      console.error(`Error fetching enhanced bill ${billId}:`, error.message);
      return null;
    }
  }

  enhancedRelevanceAnalysis(billTitle, billDescription, billText = '', subjects = []) {
    const content = `${billTitle} ${billDescription} ${billText}`.toLowerCase();
    const subjectText = Array.isArray(subjects) ? subjects.join(' ').toLowerCase() : '';
    const allContent = `${content} ${subjectText}`;
    
    const foundKeywords = [];
    let relevanceScore = 0;
    
    // Check for primary keywords
    TRACKING_KEYWORDS.forEach(keyword => {
      if (allContent.includes(keyword.toLowerCase())) {
        foundKeywords.push(keyword);
        relevanceScore += 1;
      }
    });
    
    // High-priority keyword bonus scoring
    const highPriorityKeywords = [
      'money laundering', 'financial crimes', 'asset forfeiture', 'aml',
      'law enforcement training', 'financial intelligence', 'fraud investigation',
      'police training', 'justice grants', 'cops grants', 'byrne grants',
      'technical assistance', 'capacity building'
    ];
    
    highPriorityKeywords.forEach(keyword => {
      if (allContent.includes(keyword)) {
        relevanceScore += 3; // Higher bonus for priority terms
      }
    });
    
    // Special pattern matching for funding/grants
    if (allContent.match(/\$[\d,]+|grant|appropriation|funding|million|billion/)) {
      relevanceScore += 2;
      foundKeywords.push('Funding/Grants');
    }
    
    // Training-specific patterns
    if (allContent.match(/training|education|certification|academy|instruction/)) {
      relevanceScore += 2;
      foundKeywords.push('Training Programs');
    }
    
    // Law enforcement agency patterns
    if (allContent.match(/police|sheriff|detective|officer|agent|enforcement|investigation/)) {
      relevanceScore += 1;
      foundKeywords.push('Law Enforcement');
    }
    
    return {
      isRelevant: foundKeywords.length > 0 || relevanceScore > 0,
      foundKeywords: [...new Set(foundKeywords)], // Remove duplicates
      relevanceScore: Math.min(relevanceScore, 10), // Cap at 10
      confidence: Math.min(relevanceScore * 10, 100),
      hasTraining: allContent.includes('training'),
      hasFunding: allContent.match(/\$|grant|fund/) !== null,
      hasLawEnforcement: allContent.match(/police|law enforcement|officer/) !== null
    };
  }

  formatBillForDatabaseEnhanced(legiscanBill, relevanceAnalysis) {
    const status = this.mapStatusEnhanced(legiscanBill.status, legiscanBill.status_date);
    const progressPercentage = this.calculateProgressEnhanced(legiscanBill.status, legiscanBill.history);
    
    return {
      legiscanId: legiscanBill.bill_id.toString(),
      stateCode: legiscanBill.state || 'US',
      billNumber: legiscanBill.bill_number || 'Unknown',
      title: legiscanBill.title || 'No title available',
      description: this.generateSmartDescription(legiscanBill, relevanceAnalysis),
      status: status,
      progressPercentage: progressPercentage,
      introducedDate: legiscanBill.introduced_date || null,
      fundsAllocated: this.extractFundingEnhanced(legiscanBill),
      keywords: relevanceAnalysis.foundKeywords.join(', '),
      relevanceScore: relevanceAnalysis.relevanceScore,
      lastSynced: new Date(),
      legiscanUrl: this.buildLegiscanUrl(legiscanBill),
      sourceType: 'legiscan',
      isActive: true,
      sessionId: legiscanBill.session_id?.toString() || null,
      chamber: this.extractChamber(legiscanBill.bill_number),
      sponsors: this.extractSponsors(legiscanBill),
      subjects: Array.isArray(legiscanBill.subjects) ? legiscanBill.subjects.join(', ') : '',
      changeHash: legiscanBill.change_hash || null
    };
  }

  generateSmartDescription(billData, relevanceAnalysis) {
    const title = billData.title || '';
    const state = billData.state || 'Federal';
    const hasTraining = relevanceAnalysis.hasTraining;
    const hasFunding = relevanceAnalysis.hasFunding;
    const hasLawEnforcement = relevanceAnalysis.hasLawEnforcement;
    
    let description = `${title}`;
    
    if (billData.description && billData.description !== title) {
      description = billData.description;
    } else {
      // Generate smart description based on analysis
      description += ` - `;
      
      if (hasTraining && hasLawEnforcement) {
        description += `A ${state} bill addressing law enforcement training and professional development. `;
      } else if (hasFunding && hasLawEnforcement) {
        description += `A ${state} bill providing funding for law enforcement programs and initiatives. `;
      } else if (hasTraining) {
        description += `A ${state} bill focused on training and educational programs. `;
      } else if (relevanceAnalysis.foundKeywords.includes('Financial crimes')) {
        description += `A ${state} bill addressing financial crime prevention and enforcement. `;
      } else {
        description += `A ${state} legislative initiative. `;
      }
      
      if (relevanceAnalysis.relevanceScore >= 5) {
        description += `This bill is highly relevant to law enforcement training and financial crime prevention efforts.`;
      } else if (relevanceAnalysis.relevanceScore >= 3) {
        description += `This bill has moderate relevance to our tracking criteria.`;
      } else {
        description += `This bill may contain provisions of interest to law enforcement professionals.`;
      }
    }
    
    return description;
  }

  mapStatusEnhanced(legiscanStatus, statusDate = null) {
    const statusMap = {
      1: 'Introduced',
      2: 'In Committee', 
      3: 'Committee Review',
      4: 'Passed Chamber',
      5: 'Passed Both Chambers',
      6: 'Signed/Enacted',
      7: 'Vetoed',
      8: 'Failed/Dead',
      9: 'Withdrawn'
    };
    
    const baseStatus = statusMap[legiscanStatus] || 'Unknown';
    
    // Add date context if available
    if (statusDate) {
      const date = new Date(statusDate);
      const now = new Date();
      const daysDiff = Math.floor((now - date) / (1000 * 60 * 60 * 24));
      
      if (daysDiff <= 7) {
        return `${baseStatus} (Recent)`;
      }
    }
    
    return baseStatus;
  }

  calculateProgressEnhanced(status, history = []) {
    const progressMap = {
      1: 15,  // Introduced
      2: 30,  // In Committee
      3: 45,  // Committee Review
      4: 70,  // Passed Chamber
      5: 90,  // Passed Both Chambers
      6: 100, // Signed/Enacted
      7: 0,   // Vetoed
      8: 0,   // Failed/Dead
      9: 0    // Withdrawn
    };
    
    let baseProgress = progressMap[status] || 5;
    
    // Enhance with history analysis
    if (Array.isArray(history) && history.length > 0) {
      const recentActions = history.slice(-3); // Last 3 actions
      const hasRecentActivity = recentActions.some(action => {
        if (action.date) {
          const actionDate = new Date(action.date);
          const now = new Date();
          const daysDiff = (now - actionDate) / (1000 * 60 * 60 * 24);
          return daysDiff <= 30; // Recent activity in last 30 days
        }
        return false;
      });
      
      if (hasRecentActivity) {
        baseProgress += 5; // Bonus for recent activity
      }
    }
    
    return Math.min(baseProgress, 100);
  }

  extractFundingEnhanced(billData) {
    const title = (billData.title || '').toLowerCase();
    const description = (billData.description || '').toLowerCase();
    const text = `${title} ${description}`;
    
    // Look for specific dollar amounts
    const dollarMatch = text.match(/\$\s*(\d+(?:,\d+)*(?:\.\d+)?)\s*(million|billion|thousand)?/i);
    if (dollarMatch) {
      const amount = dollarMatch[1];
      const unit = dollarMatch[2] || '';
      return `$${amount}${unit ? ' ' + unit : ''}`;
    }
    
    // Look for appropriation types
    if (text.includes('appropriat')) return 'Appropriation Bill';
    if (text.includes('grant')) return 'Grant Program';
    if (text.includes('fund')) return 'Funding Program';
    if (text.includes('budget')) return 'Budget Allocation';
    if (text.includes('financial assistance')) return 'Financial Assistance';
    
    return 'Not specified';
  }

  buildLegiscanUrl(billData) {
    const state = billData.state || 'us';
    const billNumber = billData.bill_number || '';
    const sessionId = billData.session_id || '';
    
    return `https://legiscan.com/${state.toLowerCase()}/bill/${billNumber}/${sessionId}`;
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
      return billData.sponsors.map(sponsor => 
        `${sponsor.name || 'Unknown'} (${sponsor.party || 'Unknown'})`
      ).join(', ');
    }
    return 'Not specified';
  }
}

const enhancedLegiScan = new EnhancedLegiScanService(LEGISCAN_API_KEY);

// ===== ENHANCED Bill Sync Function =====
async function syncRelevantBillsEnhanced() {
  let syncRecord;
  
  try {
    syncRecord = await SyncStatus.create({
      syncType: 'enhanced_automatic',
      status: 'running',
      startTime: new Date()
    });

    console.log('🚀 Starting ENHANCED LegiScan synchronization...');
    console.log(`🔑 Using API Key: ${LEGISCAN_API_KEY.substring(0, 8)}...`);
    
    let totalFound = 0;
    let totalAdded = 0;
    let totalUpdated = 0;
    const processedStates = [];

    // Priority states for law enforcement legislation
    const priorityStates = ['US', 'CA', 'TX', 'FL', 'NY', 'IL', 'PA', 'OH'];
    
    // Process high-priority keywords first
    const priorityKeywords = [
      'law enforcement training', 'police training', 'financial crimes',
      'money laundering', 'asset forfeiture', 'justice grants',
      'COPS grants', 'Byrne grants', 'technical assistance'
    ];
    
    console.log(`📋 Processing ${priorityKeywords.length} priority keywords across ${priorityStates.length} states`);
    
    for (const [keywordIndex, keyword] of priorityKeywords.entries()) {
      console.log(`\n🔍 [${keywordIndex + 1}/${priorityKeywords.length}] Processing: "${keyword}"`);
      
      for (const [stateIndex, state] of priorityStates.entries()) {
        try {
          console.log(`   🏛️  [${stateIndex + 1}/${priorityStates.length}] Searching in: ${state}`);
          
          const searchResults = await enhancedLegiScan.searchBillsAdvanced(keyword, state, null, 20);
          
          if (!Array.isArray(searchResults) || searchResults.length === 0) {
            console.log(`      ❌ No results found`);
            continue;
          }

          totalFound += searchResults.length;
          console.log(`      ✅ Found ${searchResults.length} bills`);

          // Process each bill with enhanced analysis
          for (const [billIndex, result] of searchResults.entries()) {
            try {
              if (!result || !result.bill_id) {
                console.log(`         ⚠️  Invalid result ${billIndex + 1}`);
                continue;
              }

              console.log(`         📄 [${billIndex + 1}/${searchResults.length}] Processing bill ID: ${result.bill_id}`);

              const billDetails = await enhancedLegiScan.getBillDetailsEnhanced(result.bill_id);
              if (!billDetails) {
                console.log(`            ❌ No details retrieved`);
                continue;
              }

              const relevanceAnalysis = enhancedLegiScan.enhancedRelevanceAnalysis(
                billDetails.title || '',
                billDetails.description || '',
                billDetails.fullText || '',
                billDetails.subjects || []
              );

              console.log(`            🎯 Relevance Score: ${relevanceAnalysis.relevanceScore}/10`);

              if (relevanceAnalysis.relevanceScore < 2) {
                console.log(`            ⚠️  Low relevance, skipping`);
                continue;
              }

              const formattedBill = enhancedLegiScan.formatBillForDatabaseEnhanced(billDetails, relevanceAnalysis);

              const existingBill = await Bill.findOne({
                where: { legiscanId: formattedBill.legiscanId }
              });

              if (existingBill) {
                await existingBill.update({
                  ...formattedBill,
                  createdAt: existingBill.createdAt
                });
                totalUpdated++;
                console.log(`            ✅ Updated: ${formattedBill.billNumber}`);
              } else {
                await Bill.create(formattedBill);
                totalAdded++;
                console.log(`            ✨ Added: ${formattedBill.billNumber}`);
              }

            } catch (billError) {
              console.error(`            ❌ Error processing bill ${result.bill_id}:`, billError.message);
            }
          }
          
          if (!processedStates.includes(state)) {
            processedStates.push(state);
          }
          
        } catch (stateError) {
          console.error(`      ❌ Error processing state ${state}:`, stateError.message);
        }
        
        // Delay between states to avoid rate limits
        if (stateIndex < priorityStates.length - 1) {
          console.log(`      ⏳ Waiting 3 seconds before next state...`);
          await new Promise(resolve => setTimeout(resolve, 3000));
        }
      }
      
      // Longer delay between keywords
      if (keywordIndex < priorityKeywords.length - 1) {
        console.log(`   ⏳ Waiting 10 seconds before next keyword...`);
        await new Promise(resolve => setTimeout(resolve, 10000));
      }
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
        billsUpdated: safeUpdated,
        keywordsProcessed: priorityKeywords.length,
        statesProcessed: processedStates.join(', ')
      });
    }

    console.log(`\n✅ ENHANCED SYNC COMPLETE!`);
    console.log(`   📊 Found: ${safeTotal} bills`);
    console.log(`   ➕ Added: ${safeAdded} new bills`);
    console.log(`   🔄 Updated: ${safeUpdated} existing bills`);
    console.log(`   🏛️  States: ${processedStates.join(', ')}`);
    console.log(`   🔍 Keywords: ${priorityKeywords.length} processed`);
    
    return {
      success: true,
      totalFound: safeTotal,
      totalAdded: safeAdded,
      totalUpdated: safeUpdated,
      statesProcessed: processedStates,
      keywordsProcessed: priorityKeywords.length,
      timestamp: new Date()
    };

  } catch (error) {
    console.error('❌ ENHANCED SYNC FAILED:', error);
    
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

// Database migration function with enhanced fields
async function runEnhancedDatabaseMigrations() {
  console.log('🔧 Running enhanced database migrations...');
  
  try {
    const queryInterface = sequelize.getQueryInterface();
    const tableDescription = await queryInterface.describeTable('Bills');
    
    const newColumnsToAdd = [
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

// Auth middleware (unchanged)
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
    message: 'Legislative Tracker API - ENHANCED LegiScan Integration', 
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '3.0.0',
    features: [
      'Enhanced LegiScan Integration', 
      'Advanced Bill Analysis', 
      'Multi-State Search', 
      'Smart Relevance Scoring',
      'Real-time Sync Status',
      'Comprehensive Training Focus'
    ],
    apiKey: LEGISCAN_API_KEY ? `${LEGISCAN_API_KEY.substring(0, 8)}...` : 'Not configured',
    keywordsTracking: TRACKING_KEYWORDS.length,
    priorityStates: ['US', 'CA', 'TX', 'FL', 'NY', 'IL', 'PA', 'OH'],
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
      'POST /api/admin/sync-bills-enhanced',
      'GET /api/admin/sync-status-enhanced',
      'POST /api/admin/test-legiscan'
    ]
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: 'connected',
    legiscan: 'enhanced_active',
    apiKey: LEGISCAN_API_KEY ? 'configured' : 'missing',
    keywords_tracking: TRACKING_KEYWORDS.length,
    version: '3.0.0'
  });
});

// Enhanced Admin Routes

app.post('/api/admin/sync-bills-enhanced', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    console.log(`🚀 ENHANCED MANUAL SYNC triggered by ${req.user.email}`);
    
    // Start enhanced sync in background
    syncRelevantBillsEnhanced().catch(error => {
      console.error('Enhanced background sync failed:', error);
    });
    
    res.json({
      message: 'ENHANCED LegiScan synchronization started in background',
      status: 'initiated',
      timestamp: new Date(),
      keywordsTracking: TRACKING_KEYWORDS.length,
      version: '3.0.0',
      features: ['Multi-state search', 'Enhanced relevance analysis', 'Smart bill processing']
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to start enhanced sync', details: error.message });
  }
});

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
    let enhancedBills = 0;
    
    try {
      const tableDescription = await sequelize.getQueryInterface().describeTable('Bills');
      if (tableDescription.sourceType) {
        legiscanBills = await Bill.count({ where: { sourceType: 'legiscan' } });
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
    }

    res.json({
      apiStatus: 'enhanced_active',
      apiKey: LEGISCAN_API_KEY ? 'configured' : 'missing',
      version: '3.0.0',
      totalBills,
      legiscanBills,
      manualBills: totalBills - legiscanBills,
      highRelevanceBills: enhancedBills,
      keywordsTracking: TRACKING_KEYWORDS.length,
      recentSyncs: recentSyncs.length,
      lastSync: recentSyncs[0]?.endTime || null,
      currentlyRunning: recentSyncs.some(sync => sync.status === 'running'),
      enhancedFeatures: [
        'Multi-state search capability',
        'Advanced relevance scoring',
        'Enhanced bill analysis',
        'Smart keyword matching',
        'Comprehensive error handling'
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

// NEW: Test LegiScan API connectivity
app.post('/api/admin/test-legiscan', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    console.log('🧪 Testing LegiScan API connectivity...');

    // Test 1: Basic API connectivity
    try {
      const testData = await enhancedLegiScan.makeRequest('getSessionList', { state: 'CA' });
      console.log('✅ API connectivity test passed');
      
      // Test 2: Search functionality
      const searchResults = await enhancedLegiScan.searchBillsAdvanced('police training', 'CA', null, 5);
      console.log(`✅ Search test passed - found ${searchResults.length} results`);
      
      res.json({
        success: true,
        apiKey: LEGISCAN_API_KEY ? `${LEGISCAN_API_KEY.substring(0, 8)}...` : 'Not configured',
        connectivity: 'successful',
        searchTest: `Found ${searchResults.length} test results`,
        timestamp: new Date(),
        message: 'LegiScan API is working correctly'
      });
      
    } catch (apiError) {
      console.error('❌ API test failed:', apiError.message);
      res.status(500).json({
        success: false,
        apiKey: LEGISCAN_API_KEY ? `${LEGISCAN_API_KEY.substring(0, 8)}...` : 'Not configured',
        connectivity: 'failed',
        error: apiError.message,
        timestamp: new Date(),
        message: 'LegiScan API test failed'
      });
    }

  } catch (error) {
    res.status(500).json({ error: 'Failed to test LegiScan API', details: error.message });
  }
});

// Auth routes (unchanged from previous version)
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
      version: '3.0.0'
    });
  } catch (error) {
    console.error('Error fetching enhanced bills:', error);
    res.status(500).json({ error: 'Failed to fetch bills', details: error.message });
  }
});

// Other bill routes (unchanged)
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
      message: 'Legislative Tracker API - Enhanced Version',
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

async function startEnhancedServer() {
  try {
    console.log('🚀 Starting ENHANCED Legislative Tracker Server...');
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
        },
        {
          stateCode: 'CA',
          billNumber: 'AB.1234',
          title: 'California Peace Officer Financial Crimes Training Act',
          description: 'Requires mandatory training for California peace officers in financial crime detection, asset forfeiture procedures, and cryptocurrency-related investigations. Establishes state funding for training programs.',
          status: 'Committee Review',
          progressPercentage: 45,
          introducedDate: '2025-02-10',
          fundsAllocated: '$50 million state appropriation',
          sourceType: 'manual',
          keywords: 'Police training, Financial crimes, Asset forfeiture, Peace officer training',
          relevanceScore: 8,
          isActive: true,
          chamber: 'Assembly',
          sponsors: 'Asm. Rodriguez (D-Los Angeles)',
          subjects: 'Peace officers, Training requirements, Financial crimes'
        },
        {
          stateCode: 'TX',
          billNumber: 'HB.2025',
          title: 'Texas Law Enforcement Technical Assistance Program',
          description: 'Establishes a comprehensive technical assistance program for Texas law enforcement agencies, focusing on modern investigative techniques, digital forensics, and inter-agency cooperation.',
          status: 'Introduced',
          progressPercentage: 20,
          introducedDate: '2025-03-01',
          fundsAllocated: '$75 million biennial',
          sourceType: 'manual',
          keywords: 'Technical assistance, Digital forensics, Law enforcement training, Inter-agency cooperation',
          relevanceScore: 7,
          isActive: true,
          chamber: 'House',
          sponsors: 'Rep. Martinez (R-Houston), Rep. Thompson (D-Austin)',
          subjects: 'Law enforcement, Technology, Training programs'
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

    console.log('🎯 ENHANCED FEATURES ACTIVE:');
    console.log('   📊 Advanced relevance scoring');
    console.log('   🔍 Multi-state search capability');
    console.log('   🧠 Smart bill analysis');
    console.log('   📈 Enhanced progress tracking');
    console.log('   🔗 Comprehensive LegiScan integration');
    console.log(`🔑 API Key Status: ${LEGISCAN_API_KEY ? 'Configured' : 'Missing'}`);
    console.log('👤 Admin login: admin@example.com / admin123');
    console.log(`🔍 Tracking ${TRACKING_KEYWORDS.length} keywords across multiple categories`);
    
    app.listen(PORT, () => {
      console.log(`🚀 ENHANCED SERVER running on port ${PORT}`);
      console.log(`📡 API available at: http://localhost:${PORT}/api`);
      console.log(`🏥 Health check: http://localhost:${PORT}/health`);
      console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
      console.log(`🧪 Test LegiScan: POST /api/admin/test-legiscan`);
      console.log(`🔄 Enhanced Sync: POST /api/admin/sync-bills-enhanced`);
    });

    // Enhanced scheduling with immediate test
    setTimeout(async () => {
      console.log('🧪 Running initial LegiScan connectivity test...');
      try {
        const testResult = await enhancedLegiScan.makeRequest('getSessionList', { state: 'CA' });
        console.log('✅ LegiScan API test successful');
        
        // Schedule enhanced sync every 2 hours for more frequent updates
        console.log('📅 Scheduling enhanced bill sync every 2 hours...');
        cron.schedule('0 */2 * * *', async () => {
          console.log('🕐 Running scheduled ENHANCED bill sync...');
          await syncRelevantBillsEnhanced();
        });

        // Run initial enhanced sync after 3 minutes
        setTimeout(async () => {
          console.log('🚀 Running initial ENHANCED bill sync...');
          const result = await syncRelevantBillsEnhanced();
          if (result.success) {
            console.log(`✅ Initial sync completed: ${result.totalAdded} new bills added`);
          } else {
            console.log(`❌ Initial sync failed: ${result.error}`);
          }
        }, 180000); // 3 minutes
        
      } catch (testError) {
        console.error('❌ LegiScan API test failed:', testError.message);
        console.log('⚠️  Manual sync will be available but may not work correctly');
      }
    }, 10000); // 10 seconds after startup
    
  } catch (error) {
    console.error('❌ Failed to start enhanced server:', error);
    process.exit(1);
  }
}

startEnhancedServer();