import axios from 'axios';
import {environment} from "../../environment/environment";

const api = axios.create({baseURL: environment.apiBaseUrl, withCredentials: true});

// Add auth token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('authToken');
  if (token) {
    config.headers['x-auth-token'] = token;
  }
  return config;
});

export default api;
