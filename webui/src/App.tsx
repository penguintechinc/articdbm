import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/layout/Layout';
import ProtectedRoute from './components/layout/ProtectedRoute';

// Public pages
import Index from './pages/Index';
import Login from './pages/Login';
import Register from './pages/Register';

// Protected pages
import Dashboard from './pages/Dashboard';
import Resources from './pages/Resources';
import Applications from './pages/Applications';
import DatabaseExplorer from './pages/DatabaseExplorer';
import BigData from './pages/BigData';
import BigDataSpark from './pages/BigDataSpark';
import BigDataFlink from './pages/BigDataFlink';
import BigDataTrino from './pages/BigDataTrino';
// Note: Object storage is managed by NEST project, not ArticDBM
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<Index />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Protected routes with layout */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Layout>
                <Dashboard />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/resources"
          element={
            <ProtectedRoute>
              <Layout>
                <Resources />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/applications"
          element={
            <ProtectedRoute>
              <Layout>
                <Applications />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/explorer"
          element={
            <ProtectedRoute>
              <Layout>
                <DatabaseExplorer />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/bigdata"
          element={
            <ProtectedRoute>
              <Layout>
                <BigData />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/bigdata/spark"
          element={
            <ProtectedRoute>
              <Layout>
                <BigDataSpark />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/bigdata/flink"
          element={
            <ProtectedRoute>
              <Layout>
                <BigDataFlink />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/bigdata/trino"
          element={
            <ProtectedRoute>
              <Layout>
                <BigDataTrino />
              </Layout>
            </ProtectedRoute>
          }
        />
        {/* Storage is managed by NEST project */}
        <Route
          path="/settings"
          element={
            <ProtectedRoute>
              <Layout>
                <Settings />
              </Layout>
            </ProtectedRoute>
          }
        />

        {/* Catch all - redirect to index */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
