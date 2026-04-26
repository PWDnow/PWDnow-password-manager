import React from 'react';
import { createBrowserRouter, Navigate } from 'react-router-dom';
import AppLayout from './layouts/AppLayout';
import Vault from './pages/Vault';
import BreachMonitor from './pages/BreachMonitor';
import Settings from './pages/Settings';
import ManageFolders from './pages/ManageFolders';
import Dashboard from './pages/Dashboard';
import AssetHolder from './pages/AssetHolder';
import NotFound from './pages/NotFound';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import Setup from './pages/Setup';

export const router = createBrowserRouter([
  {
    path: '/setup',
    element: <Setup />
  },
  {
    path: '/login',
    element: <Login />
  },
  {
    path: '/register',
    element: <Register />
  },
  {
    path: '/forgot-password',
    element: <ForgotPassword />
  },
  {
    path: '/',
    element: <AppLayout />,
    children: [
      {
        index: true,
        element: <Navigate to="/vault" replace />
      },
      {
        path: 'vault',
        element: <Vault />
      },
      {
        path: 'vault/:folderId',
        element: <Vault />
      },
      {
        path: 'security',
        element: <BreachMonitor />
      },
      {
        path: 'settings',
        element: <Settings />
      },
      {
        path: 'manage-folders',
        element: <ManageFolders />
      },
      {
        path: 'dashboard',
        element: <Dashboard />
      },
      {
        path: 'asset-holder',
        element: <AssetHolder />
      }
    ]
  },
  {
    path: '*',
    element: <NotFound />
  }
]);
