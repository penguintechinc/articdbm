import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/common/Button';
import { Loader } from 'lucide-react';

export default function Index() {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Check if user is authenticated
    const authToken = localStorage.getItem('auth_token');
    const user = localStorage.getItem('user');

    if (authToken && user) {
      setIsAuthenticated(true);
      // Redirect to dashboard if logged in
      navigate('/dashboard', { replace: true });
    } else {
      setIsAuthenticated(false);
      setIsLoading(false);
    }
  }, [navigate]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gradient-to-b from-blue-900 to-blue-700">
        <Loader className="h-8 w-8 animate-spin text-white" />
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-b from-blue-900 to-blue-700">
      <div className="text-center max-w-md px-4">
        <h1 className="text-4xl font-bold text-white mb-4">ArticDBM v2.0</h1>
        <p className="text-xl text-blue-100 mb-8">Database Management Platform</p>

        {!isAuthenticated ? (
          <>
            <div className="space-y-3 mb-8">
              <Button
                className="w-full"
                onClick={() => navigate('/login')}
              >
                Sign In
              </Button>
              <Button
                variant="outline"
                className="w-full"
                onClick={() => navigate('/register')}
              >
                Create Account
              </Button>
            </div>

            <div className="mt-8 pt-6 border-t border-blue-500">
              <p className="text-sm text-blue-100 mb-4">Quick Links</p>
              <div className="space-y-2">
                <a
                  href="#features"
                  className="block text-blue-200 hover:text-white text-sm transition"
                >
                  Dashboard
                </a>
                <a
                  href="#resources"
                  className="block text-blue-200 hover:text-white text-sm transition"
                >
                  Resources
                </a>
                <a
                  href="#bigdata"
                  className="block text-blue-200 hover:text-white text-sm transition"
                >
                  Big Data Clusters
                </a>
              </div>
            </div>
          </>
        ) : null}

        <div className="mt-12 text-xs text-blue-200">
          <p>Enterprise Database Management Solution</p>
          <p className="mt-1">Powered by Penguin Tech Inc.</p>
        </div>
      </div>
    </div>
  );
}
