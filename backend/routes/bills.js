// src/pages/Bills.js
import React, { useState } from 'react';
import { useQuery } from 'react-query';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { 
  MagnifyingGlassIcon, 
  FunnelIcon,
  BookmarkIcon,
  EyeIcon 
} from '@heroicons/react/24/outline';
import { BookmarkIcon as BookmarkSolidIcon } from '@heroicons/react/24/solid';

const Bills = () => {
  const [filters, setFilters] = useState({
    search: '',
    state: 'all',
    status: 'all',
    keyword: '',
    page: 1,
    limit: 20
  });

  const { data, isLoading, refetch } = useQuery(
    ['bills', filters],
    () => {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value && value !== 'all') {
          params.append(key, value);
        }
      });
      return axios.get(`/api/bills?${params}`).then(res => res.data);
    },
    { keepPreviousData: true }
  );

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value,
      page: 1 // Reset to first page when filtering
    }));
  };

  const handleWatchBill = async (billId, isWatched) => {
    try {
      if (isWatched) {
        await axios.delete(`/api/bills/${billId}/watch`);
      } else {
        await axios.post(`/api/bills/${billId}/watch`);
      }
      refetch();
    } catch (error) {
      console.error('Error updating watchlist:', error);
    }
  };

  const getStatusColor = (status) => {
    if (!status) return 'gray';
    const lower = status.toLowerCase();
    if (lower.includes('passed') || lower.includes('signed')) return 'green';
    if (lower.includes('committee')) return 'yellow';
    if (lower.includes('failed') || lower.includes('vetoed')) return 'red';
    return 'blue';
  };

  if (isLoading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 bg-gray-300 rounded w-1/4 mb-6"></div>
        <div className="bg-white shadow rounded-lg p-6">
          <div className="space-y-4">
            {[1, 2, 3, 4, 5].map(i => (
              <div key={i} className="h-16 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Legislative Bills</h1>
        <p className="mt-1 text-sm text-gray-500">
          Track and monitor legislation across all jurisdictions
        </p>
      </div>

      {/* Filters */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Search
            </label>
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search bills..."
                className="pl-10 w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                value={filters.search}
                onChange={(e) => handleFilterChange('search', e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              State
            </label>
            <select
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              value={filters.state}
              onChange={(e) => handleFilterChange('state', e.target.value)}
            >
              <option value="all">All States</option>
              <option value="US">US Congress</option>
              <option value="CA">California</option>
              <option value="NY">New York</option>
              <option value="TX">Texas</option>
              <option value="FL">Florida</option>
              {/* Add more states as needed */}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Status
            </label>
            <select
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
            >
              <option value="all">All Statuses</option>
              <option value="introduced">Introduced</option>
              <option value="committee">In Committee</option>
              <option value="passed">Passed</option>
              <option value="failed">Failed</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Keyword
            </label>
            <input
              type="text"
              placeholder="Filter by keyword..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              value={filters.keyword}
              onChange={(e) => handleFilterChange('keyword', e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="bg-white shadow rounded-lg">
        {data?.bills?.length === 0 ? (
          <div className="p-6 text-center">
            <FunnelIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No bills found</h3>
            <p className="mt-1 text-sm text-gray-500">
              Try adjusting your search criteria.
            </p>
          </div>
        ) : (
          <>
            <div className="px-6 py-4 border-b border-gray-200">
              <p className="text-sm text-gray-700">
                Showing {data?.bills?.length || 0} of {data?.pagination?.total || 0} bills
              </p>
            </div>

            <ul className="divide-y divide-gray-200">
              {data?.bills?.map((bill) => (
                <li key={bill.id} className="p-6 hover:bg-gray-50">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                          {bill.stateCode} {bill.billNumber}
                        </span>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-${getStatusColor(bill.status)}-100 text-${getStatusColor(bill.status)}-800`}>
                          {bill.status || 'Unknown'}
                        </span>
                        <div className="flex items-center space-x-1">
                          <div className="w-16 bg-gray-200 rounded-full h-1.5">
                            <div 
                              className={`bg-${getStatusColor(bill.status)}-600 h-1.5 rounded-full`}
                              style={{ width: `${bill.progressPercentage}%` }}
                            ></div>
                          </div>
                          <span className="text-xs text-gray-500">
                            {bill.progressPercentage}%
                          </span>
                        </div>
                      </div>

                      <h3 className="text-lg font-medium text-gray-900 mb-2">
                        <Link 
                          to={`/bills/${bill.id}`}
                          className="hover:text-blue-600"
                        >
                          {bill.title}
                        </Link>
                      </h3>

                      {bill.description && (
                        <p className="text-sm text-gray-600 mb-2 line-clamp-2">
                          {bill.description}
                        </p>
                      )}

                      <div className="flex items-center space-x-4 text-xs text-gray-500">
                        {bill.introducedDate && (
                          <span>Introduced: {new Date(bill.introducedDate).toLocaleDateString()}</span>
                        )}
                        {bill.lastActionDate && (
                          <span>Last Action: {new Date(bill.lastActionDate).toLocaleDateString()}</span>
                        )}
                        {bill.fundsAllocated && (
                          <span>Funds: {bill.fundsAllocated}</span>
                        )}
                      </div>

                      {bill.Keywords && bill.Keywords.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {bill.Keywords.slice(0, 3).map((keyword) => (
                            <span 
                              key={keyword.id}
                              className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800"
                            >
                              {keyword.term}
                            </span>
                          ))}
                          {bill.Keywords.length > 3 && (
                            <span className="text-xs text-gray-500">
                              +{bill.Keywords.length - 3} more
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => handleWatchBill(bill.id, bill.isWatched)}
                        className={`p-2 rounded-full ${
                          bill.isWatched 
                            ? 'text-yellow-500 hover:text-yellow-600' 
                            : 'text-gray-400 hover:text-yellow-500'
                        }`}
                      >
                        {bill.isWatched ? (
                          <BookmarkSolidIcon className="h-5 w-5" />
                        ) : (
                          <BookmarkIcon className="h-5 w-5" />
                        )}
                      </button>

                      <Link
                        to={`/bills/${bill.id}`}
                        className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-sm font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                      >
                        <EyeIcon className="h-4 w-4 mr-1" />
                        View
                      </Link>
                    </div>
                  </div>
                </li>
              ))}
            </ul>

            {/* Pagination */}
            {data?.pagination?.totalPages > 1 && (
              <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200">
                <div className="flex-1 flex justify-between sm:hidden">
                  <button
                    disabled={filters.page === 1}
                    onClick={() => handleFilterChange('page', filters.page - 1)}
                    className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <button
                    disabled={filters.page >= data.pagination.totalPages}
                    onClick={() => handleFilterChange('page', filters.page + 1)}
                    className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
                <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm text-gray-700">
                      Showing page {filters.page} of {data.pagination.totalPages}
                    </p>
                  </div>
                  <div>
                    <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                      <button
                        disabled={filters.page === 1}
                        onClick={() => handleFilterChange('page', filters.page - 1)}
                        className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                      >
                        Previous
                      </button>
                      <button
                        disabled={filters.page >= data.pagination.totalPages}
                        onClick={() => handleFilterChange('page', filters.page + 1)}
                        className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
                      >
                        Next
                      </button>
                    </nav>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default Bills;

// src/pages/BillDetail.js
import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import axios from 'axios';
import { format } from 'date-fns';
import {
  ArrowLeftIcon,
  BookmarkIcon,
  ExternalLinkIcon,
  PencilIcon
} from '@heroicons/react/24/outline';
import { BookmarkIcon as BookmarkSolidIcon } from '@heroicons/react/24/solid';
import toast from 'react-hot-toast';

const BillDetail = () => {
  const { id } = useParams();
  const queryClient = useQueryClient();
  const [isEditingNotes, setIsEditingNotes] = useState(false);
  const [notes, setNotes] = useState('');

  const { data: bill, isLoading } = useQuery(
    ['bill', id],
    () => axios.get(`/api/bills/${id}`).then(res => res.data),
    {
      onSuccess: (data) => {
        setNotes(data.watchNotes || '');
      }
    }
  );

  const watchMutation = useMutation(
    ({ isWatched, notes }) => {
      if (isWatched) {
        return axios.delete(`/api/bills/${id}/watch`);
      } else {
        return axios.post(`/api/bills/${id}/watch`, { notes });
      }
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['bill', id]);
        toast.success(bill?.isWatched ? 'Removed from watchlist' : 'Added to watchlist');
      },
      onError: () => {
        toast.error('Failed to update watchlist');
      }
    }
  );

  const updateNotesMutation = useMutation(
    (notes) => axios.put(`/api/bills/${id}/watch`, { notes }),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['bill', id]);
        setIsEditingNotes(false);
        toast.success('Notes updated');
      },
      onError: () => {
        toast.error('Failed to update notes');
      }
    }
  );

  const handleWatchToggle = () => {
    watchMutation.mutate({ 
      isWatched: bill.isWatched, 
      notes: bill.isWatched ? '' : notes 
    });
  };

  const handleNotesUpdate = () => {
    updateNotesMutation.mutate(notes);
  };

  if (isLoading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 bg-gray-300 rounded w-3/4 mb-4"></div>
        <div className="bg-white shadow rounded-lg p-6">
          <div className="space-y-4">
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
            <div className="h-4 bg-gray-200 rounded w-3/4"></div>
            <div className="h-4 bg-gray-200 rounded w-1/3"></div>
          </div>
        </div>
      </div>
    );
  }

  if (!bill) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-gray-900">Bill not found</h2>
        <Link to="/bills" className="mt-4 text-blue-600 hover:text-blue-500">
          ← Back to Bills
        </Link>
      </div>
    );
  }

  const getStatusColor = (status) => {
    if (!status) return 'gray';
    const lower = status.toLowerCase();
    if (lower.includes('passed') || lower.includes('signed')) return 'green';
    if (lower.includes('committee')) return 'yellow';
    if (lower.includes('failed') || lower.includes('vetoed')) return 'red';
    return 'blue';
  };

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <Link
          to="/bills"
          className="inline-flex items-center text-sm text-gray-500 hover:text-gray-700 mb-4"
        >
          <ArrowLeftIcon className="h-4 w-4 mr-1" />
          Back to Bills
        </Link>
        
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center space-x-3 mb-2">
              <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-800">
                {bill.stateCode} {bill.billNumber}
              </span>
              <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-${getStatusColor(bill.status)}-100 text-${getStatusColor(bill.status)}-800`}>
                {bill.status || 'Unknown'}
              </span>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">
              {bill.title}
            </h1>
            <div className="flex items-center space-x-2">
              <div className="w-32 bg-gray-200 rounded-full h-2">
                <div 
                  className={`bg-${getStatusColor(bill.status)}-600 h-2 rounded-full`}
                  style={{ width: `${bill.progressPercentage}%` }}
                ></div>
              </div>
              <span className="text-sm text-gray-600">
                {bill.progressPercentage}% Complete
              </span>
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={handleWatchToggle}
              disabled={watchMutation.isLoading}
              className={`inline-flex items-center px-4 py-2 border rounded-md text-sm font-medium ${
                bill.isWatched
                  ? 'border-yellow-300 text-yellow-700 bg-yellow-50 hover:bg-yellow-100'
                  : 'border-gray-300 text-gray-700 bg-white hover:bg-gray-50'
              }`}
            >
              {bill.isWatched ? (
                <BookmarkSolidIcon className="h-4 w-4 mr-2" />
              ) : (
                <BookmarkIcon className="h-4 w-4 mr-2" />
              )}
              {bill.isWatched ? 'Watching' : 'Watch'}
            </button>
            
            {bill.url && (
              <a
                href={bill.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                <ExternalLinkIcon className="h-4 w-4 mr-2" />
                View Source
              </a>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          {bill.description && (
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">Description</h2>
              <p className="text-gray-700 whitespace-pre-wrap">{bill.description}</p>
            </div>
          )}

          {/* Salient Points */}
          {bill.salientPoints && (
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">Key Provisions</h2>
              <div className="prose prose-sm max-w-none">
                <div dangerouslySetInnerHTML={{ __html: bill.salientPoints.replace(/\n/g, '<br>') }} />
              </div>
            </div>
          )}

          {/* Keywords */}
          {bill.Keywords && bill.Keywords.length > 0 && (
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">Related Keywords</h2>
              <div className="flex flex-wrap gap-2">
                {bill.Keywords.map((keyword) => (
                  <span 
                    key={keyword.id}
                    className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800"
                  >
                    {keyword.term}
                    {keyword.BillKeyword?.relevanceScore && (
                      <span className="ml-1 text-xs text-blue-600">
                        ({(keyword.BillKeyword.relevanceScore * 100).toFixed(0)}%)
                      </span>
                    )}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Bill History */}
          {bill.BillHistories && bill.BillHistories.length > 0 && (
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">Status History</h2>
              <div className="flow-root">
                <ul className="-mb-8">
                  {bill.BillHistories.map((history, index) => (
                    <li key={history.id}>
                      <div className="relative pb-8">
                        {index !== bill.BillHistories.length - 1 && (
                          <span className="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-200" />
                        )}
                        <div className="relative flex space-x-3">
                          <div>
                            <span className={`h-8 w-8 rounded-full bg-${getStatusColor(history.newStatus)}-500 flex items-center justify-center ring-8 ring-white`}>
                              <span className="h-2 w-2 rounded-full bg-white" />
                            </span>
                          </div>
                          <div className="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                            <div>
                              <p className="text-sm text-gray-500">
                                {history.changeDescription}
                              </p>
                              <p className="text-sm font-medium text-gray-900">
                                Status: {history.newStatus} ({history.newProgress}%)
                              </p>
                              {history.User && (
                                <p className="text-xs text-gray-500">
                                  Updated by {history.User.firstName} {history.User.lastName}
                                </p>
                              )}
                            </div>
                            <div className="text-right text-sm whitespace-nowrap text-gray-500">
                              {format(new Date(history.createdAt), 'MMM d, yyyy')}
                            </div>
                          </div>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Bill Details */}
          <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-lg font-medium text-gray-900 mb-4">Bill Details</h2>
            <dl className="space-y-3">
              <div>
                <dt className="text-sm font-medium text-gray-500">Jurisdiction</dt>
                <dd className="text-sm text-gray-900">{bill.stateCode}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Bill Number</dt>
                <dd className="text-sm text-gray-900">{bill.billNumber}</dd>
              </div>
              {bill.chamber && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">Chamber</dt>
                  <dd className="text-sm text-gray-900">{bill.chamber}</dd>
                </div>
              )}
              {bill.introducedDate && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">Introduced</dt>
                  <dd className="text-sm text-gray-900">
                    {format(new Date(bill.introducedDate), 'MMMM d, yyyy')}
                  </dd>
                </div>
              )}
              {bill.lastActionDate && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">Last Action</dt>
                  <dd className="text-sm text-gray-900">
                    {format(new Date(bill.lastActionDate), 'MMMM d, yyyy')}
                  </dd>
                </div>
              )}
              {bill.fundsAllocated && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">Funds Allocated</dt>
                  <dd className="text-sm text-gray-900">{bill.fundsAllocated}</dd>
                </div>
              )}
              <div>
                <dt className="text-sm font-medium text-gray-500">Source</dt>
                <dd className="text-sm text-gray-900 capitalize">{bill.sourceType}</dd>
              </div>
              {bill.legiscanId && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">LegiScan ID</dt>
                  <dd className="text-sm text-gray-900">{bill.legiscanId}</dd>
                </div>
              )}
            </dl>
          </div>

          {/* Watchlist Notes */}
          {bill.isWatched && (
            <div className="bg-white shadow rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-medium text-gray-900">My Notes</h2>
                <button
                  onClick={() => setIsEditingNotes(!isEditingNotes)}
                  className="text-blue-600 hover:text-blue-500"
                >
                  <PencilIcon className="h-4 w-4" />
                </button>
              </div>
              
              {isEditingNotes ? (
                <div>
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={4}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Add your notes about this bill..."
                  />
                  <div className="mt-3 flex space-x-2">
                    <button
                      onClick={handleNotesUpdate}
                      disabled={updateNotesMutation.isLoading}
                      className="px-3 py-1 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
                    >
                      Save
                    </button>
                    <button
                      onClick={() => {
                        setIsEditingNotes(false);
                        setNotes(bill.watchNotes || '');
                      }}
                      className="px-3 py-1 bg-gray-300 text-gray-700 text-sm rounded hover:bg-gray-400"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div>
                  {notes ? (
                    <p className="text-sm text-gray-700 whitespace-pre-wrap">{notes}</p>
                  ) : (
                    <p className="text-sm text-gray-500 italic">No notes added yet.</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default BillDetail;

// src/pages/Watchlist.js
import React from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import {
  BookmarkIcon,
  EyeIcon,
  TrashIcon
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

const Watchlist = () => {
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery(
    'user-watchlist',
    () => axios.get('/api/bills/watchlist/mine').then(res => res.data)
  );

  const removeMutation = useMutation(
    (billId) => axios.delete(`/api/bills/${billId}/watch`),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('user-watchlist');
        toast.success('Removed from watchlist');
      },
      onError: () => {
        toast.error('Failed to remove from watchlist');
      }
    }
  );

  const getStatusColor = (status) => {
    if (!status) return 'gray';
    const lower = status.toLowerCase();
    if (lower.includes('passed') || lower.includes('signed')) return 'green';
    if (lower.includes('committee')) return 'yellow';
    if (lower.includes('failed') || lower.includes('vetoed')) return 'red';
    return 'blue';
  };

  if (isLoading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 bg-gray-300 rounded w-1/4 mb-6"></div>
        <div className="bg-white shadow rounded-lg p-6">
          <div className="space-y-4">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-24 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">My Watchlist</h1>
        <p className="mt-1 text-sm text-gray-500">
          Bills you're tracking for updates and changes
        </p>
      </div>

      <div className="bg-white shadow rounded-lg">
        {!data?.watchlist || data.watchlist.length === 0 ? (
          <div className="p-6 text-center">
            <BookmarkIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No bills in watchlist</h3>
            <p className="mt-1 text-sm text-gray-500">
              Start watching bills to track their progress.
            </p>
            <div className="mt-6">
              <Link
                to="/bills"
                className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
              >
                Browse Bills
              </Link>
            </div>
          </div>
        ) : (
          <ul className="divide-y divide-gray-200">
            {data.watchlist.map((item) => (
              <li key={item.id} className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-3 mb-2">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                        {item.Bill.stateCode} {item.Bill.billNumber}
                      </span>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-${getStatusColor(item.Bill.status)}-100 text-${getStatusColor(item.Bill.status)}-800`}>
                        {item.Bill.status || 'Unknown'}
                      </span>
                      <div className="flex items-center space-x-1">
                        <div className="w-16 bg-gray-200 rounded-full h-1.5">
                          <div 
                            className={`bg-${getStatusColor(item.Bill.status)}-600 h-1.5 rounded-full`}
                            style={{ width: `${item.Bill.progressPercentage}%` }}
                          ></div>
                        </div>
                        <span className="text-xs text-gray-500">
                          {item.Bill.progressPercentage}%
                        </span>
                      </div>
                    </div>

                    <h3 className="text-lg font-medium text-gray-900 mb-2">
                      <Link 
                        to={`/bills/${item.Bill.id}`}
                        className="hover:text-blue-600"
                      >
                        {item.Bill.title}
                      </Link>
                    </h3>

                    {item.notes && (
                      <div className="mb-2">
                        <p className="text-sm text-gray-600 bg-gray-50 p-2 rounded">
                          <span className="font-medium">My notes:</span> {item.notes}
                        </p>
                      </div>
                    )}

                    <div className="flex items-center space-x-4 text-xs text-gray-500">
                      <span>
                        Added to watchlist: {format(new Date(item.createdAt), 'MMM d, yyyy')}
                      </span>
                      {item.Bill.lastActionDate && (
                        <span>
                          Last action: {format(new Date(item.Bill.lastActionDate), 'MMM d, yyyy')}
                        </span>
                      )}
                    </div>

                    {item.Bill.Keywords && item.Bill.Keywords.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {item.Bill.Keywords.slice(0, 3).map((keyword) => (
                          <span 
                            key={keyword.id}
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800"
                          >
                            {keyword.term}
                          </span>
                        ))}
                        {item.Bill.Keywords.length > 3 && (
                          <span className="text-xs text-gray-500">
                            +{item.Bill.Keywords.length - 3} more
                          </span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center space-x-2 ml-4">
                    <Link
                      to={`/bills/${item.Bill.id}`}
                      className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-sm font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                    >
                      <EyeIcon className="h-4 w-4 mr-1" />
                      View
                    </Link>
                    <button
                      onClick={() => removeMutation.mutate(item.Bill.id)}
                      disabled={removeMutation.isLoading}
                      className="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-sm font-medium rounded text-red-700 bg-white hover:bg-red-50 disabled:opacity-50"
                    >
                      <TrashIcon className="h-4 w-4 mr-1" />
                      Remove
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default Watchlist;