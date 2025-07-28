import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Dashboard.css';

const Dashboard = () => {
  const [bills, setBills] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [user, setUser] = useState(null);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = () => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
      fetchBills();
    } else {
      // Show login form
      setLoading(false);
    }
  };

  const fetchBills = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/bills', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setBills(response.data.bills);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching bills:', error);
      if (error.response?.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setUser(null);
      }
      setLoading(false);
    }
  };

  const handleLogin = async (email, password) => {
    try {
      const response = await axios.post('/api/auth/login', { email, password });
      const { accessToken, user } = response.data;
      
      localStorage.setItem('token', accessToken);
      localStorage.setItem('user', JSON.stringify(user));
      setUser(user);
      fetchBills();
    } catch (error) {
      alert(error.response?.data?.error || 'Login failed');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setBills([]);
  };

  const filteredBills = bills.filter(bill => {
    const matchesSearch = search === '' || 
      bill.title.toLowerCase().includes(search.toLowerCase()) ||
      bill.stateCode.toLowerCase().includes(search.toLowerCase()) ||
      bill.description?.toLowerCase().includes(search.toLowerCase());
    
    const matchesFilter = filter === 'all' || 
      bill.status.toLowerCase().includes(filter);
    
    return matchesSearch && matchesFilter;
  });

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  if (!user) {
    return <LoginForm onLogin={handleLogin} />;
  }

  return (
    <div className="container">
      <div className="header">
        <h1>Legislative Tracker</h1>
        <p>Tracking legislation related to training for law enforcement and financial crime prevention</p>
        <div className="user-info">
          Welcome, {user.firstName} {user.lastName} 
          <button onClick={handleLogout} className="logout-btn">Logout</button>
        </div>
      </div>
      
      <div className="keywords">
        <div className="keywords-title">Key Search Terms:</div>
        <div className="keywords-list">
          <span className="keyword-tag">Financial crimes</span>
          <span className="keyword-tag">Fraud investigation</span>
          <span className="keyword-tag">Anti-money laundering (AML)</span>
          <span className="keyword-tag">Asset forfeiture</span>
          <span className="keyword-tag">Law enforcement training</span>
          <span className="keyword-tag">Technical assistance</span>
        </div>
      </div>
      
      <div className="controls">
        <input 
          type="text" 
          className="search-box" 
          placeholder="Search bills by title, keywords, or state..." 
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <button 
          className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
          onClick={() => setFilter('all')}
        >
          All
        </button>
        <button 
          className={`filter-btn ${filter === 'introduced' ? 'active' : ''}`}
          onClick={() => setFilter('introduced')}
        >
          Introduced
        </button>
        <button 
          className={`filter-btn ${filter === 'committee' ? 'active' : ''}`}
          onClick={() => setFilter('committee')}
        >
          In Committee
        </button>
        <button 
          className={`filter-btn ${filter === 'passed' ? 'active' : ''}`}
          onClick={() => setFilter('passed')}
        >
          Passed
        </button>
      </div>
      
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>State/Congress</th>
              <th>Bill Title</th>
              <th>Status</th>
              <th>Description</th>
              <th>Funds Allocated</th>
              <th>% Progression</th>
              <th>Introduced</th>
            </tr>
          </thead>
          <tbody>
            {filteredBills.map(bill => (
              <tr key={bill.id}>
                <td>{bill.stateCode}</td>
                <td>
                  <div className="bill-title">{bill.title}</div>
                  <div className="bill-number">{bill.billNumber}</div>
                </td>
                <td>
                  <span className={`status status-${getStatusClass(bill.status)}`}>
                    {bill.status}
                  </span>
                </td>
                <td>{bill.description}</td>
                <td>{bill.fundsAllocated}</td>
                <td>
                  <div className="progress-bar">
                    <div 
                      className="progress-fill" 
                      style={{ width: `${bill.progressPercentage}%` }}
                    ></div>
                  </div>
                  {bill.progressPercentage}%
                </td>
                <td>{bill.introducedDate}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const LoginForm = ({ onLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    onLogin(email, password);
  };

  return (
    <div className="login-container">
      <div className="login-form">
        <h2>Legislative Tracker Login</h2>
        <form onSubmit={handleSubmit}>
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button type="submit">Login</button>
        </form>
        <div className="demo-credentials">
          <p><strong>Demo Credentials:</strong></p>
          <p>Email: admin@example.com</p>
          <p>Password: admin123</p>
        </div>
      </div>
    </div>
  );
};

const getStatusClass = (status) => {
  if (status?.toLowerCase().includes('introduced')) return 'introduced';
  if (status?.toLowerCase().includes('committee')) return 'committee';
  if (status?.toLowerCase().includes('passed')) return 'passed';
  return 'introduced';
};

export default Dashboard;
