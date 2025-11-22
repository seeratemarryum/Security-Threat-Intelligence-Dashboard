import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const threatIntelAPI = {
  getThreatIntel: () => api.get('/threat-intel'),
  getStats: () => api.get('/stats'),
  uploadLogs: (formData) => api.post('/upload-logs', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
};

export default api;