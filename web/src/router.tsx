import React, { Suspense, lazy } from 'react';
import { createBrowserRouter, Navigate } from 'react-router-dom';
import { keyStore } from './crypto/keystore';
import { RouteErrorBoundary } from './components/ErrorBoundary';
import { hasServerSession as _hasServerSession } from './utils/api';

const AppLayout = lazy(() => import('./layouts/AppLayout'));

const Vault = lazy(() => import('./pages/Vault'));
const BreachMonitor = lazy(() => import('./pages/BreachMonitor'));
const Settings = lazy(() => import('./pages/Settings'));
const ManageFolders = lazy(() => import('./pages/ManageFolders'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const AssetHolder = lazy(() => import('./pages/AssetHolder'));
const NotFound = lazy(() => import('./pages/NotFound'));
const Login = lazy(() => import('./pages/Login'));
const Register = lazy(() => import('./pages/Register'));
const ForgotPassword = lazy(() => import('./pages/ForgotPassword'));
const Setup = lazy(() => import('./pages/Setup'));
const EmergencyRequest = lazy(() => import('./pages/EmergencyRequest'));
const VaultHealth = lazy(() => import('./pages/VaultHealth'));
const ShareView = lazy(() => import('./pages/ShareView'));
const PasswordGenerator = lazy(() => import('./pages/PasswordGenerator'));

const PageLoader = () => (
  <div className="flex items-center justify-center min-h-[50vh]">
    <div className="w-8 h-8 border-4 border-current border-t-transparent rounded-full animate-spin opacity-40" />
  </div>
);

const AuthPageLoader = () => (
  <div className="flex items-center justify-center min-h-screen" />
);

const wrap = (Component: React.ComponentType, fallback = <PageLoader />) => (
  <Suspense fallback={fallback}><Component /></Suspense>
);

// Synchronous auth check: skip loading AppLayout (and vendor-motion) entirely
// when the session is already known to be absent on the first render.
function isAuthenticated(): boolean {
  return keyStore.hasToken ||
    _hasServerSession();
}

function AuthedLayout() {
  if (!isAuthenticated()) return <Navigate to="/login" replace />;
  return <Suspense fallback={<div />}><AppLayout /></Suspense>;
}

export const router = createBrowserRouter([
  {
    path: '/',
    errorElement: <RouteErrorBoundary />,
    children: [
      {
        path: '/setup',
        element: wrap(Setup, <AuthPageLoader />),
      },
      {
        path: '/login',
        element: wrap(Login, <AuthPageLoader />),
      },
      {
        path: '/register',
        element: wrap(Register, <AuthPageLoader />),
      },
      {
        path: '/forgot-password',
        element: wrap(ForgotPassword, <AuthPageLoader />),
      },
      {
        path: '/emergency/request/:token',
        element: wrap(EmergencyRequest, <AuthPageLoader />),
      },
      {
        path: '/share/:shareId',
        element: wrap(ShareView, <AuthPageLoader />),
      },
      {
        path: '/',
        element: <AuthedLayout />,
        children: [
          {
            index: true,
            element: <Navigate to="/vault" replace />,
          },
          {
            path: 'vault',
            element: wrap(Vault),
          },
          {
            path: 'vault/:folderId',
            element: wrap(Vault),
          },
          {
            path: 'security',
            element: wrap(BreachMonitor),
          },
          {
            path: 'settings',
            element: wrap(Settings),
          },
          {
            path: 'manage-folders',
            element: wrap(ManageFolders),
          },
          {
            path: 'dashboard',
            element: wrap(Dashboard),
          },
          {
            path: 'asset-holder',
            element: wrap(AssetHolder),
          },
          {
            path: 'health',
            element: wrap(VaultHealth),
          },
          {
            path: 'generator',
            element: wrap(PasswordGenerator),
          },
        ],
      },
      {
        path: '*',
        element: wrap(NotFound),
      },
    ]
  }
]);
