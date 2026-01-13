import { ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Database,
  Box,
  Settings,
  LogOut,
  Layers,
  ChevronRight,
  Search
} from 'lucide-react';

interface LayoutProps {
  children: ReactNode;
}

interface NavItem {
  name: string;
  path: string;
  icon: any;
  children?: NavItem[];
}

const navigation: NavItem[] = [
  { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { name: 'Resources', path: '/resources', icon: Database },
  { name: 'Applications', path: '/applications', icon: Box },
  { name: 'Database Explorer', path: '/explorer', icon: Search },
  {
    name: 'Big Data',
    path: '/bigdata',
    icon: Layers,
    children: [
      { name: 'Overview', path: '/bigdata', icon: Layers },
      { name: 'Spark', path: '/bigdata/spark', icon: Layers },
      { name: 'Flink', path: '/bigdata/flink', icon: Layers },
      { name: 'Trino', path: '/bigdata/trino', icon: Layers },
      { name: 'Storage', path: '/bigdata/storage', icon: Layers },
    ]
  },
  { name: 'Settings', path: '/settings', icon: Settings },
];

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  const isActive = (path: string) => {
    if (path === '/bigdata') {
      return location.pathname.startsWith('/bigdata');
    }
    return location.pathname === path;
  };

  const isBigDataPage = location.pathname.startsWith('/bigdata');

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-gray-200 flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-gray-200">
          <Link to="/dashboard" className="flex items-center space-x-2">
            <Database className="h-8 w-8 text-blue-600" />
            <span className="text-xl font-bold text-gray-900">ArticDBM</span>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 overflow-y-auto">
          <ul className="space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.path);
              const showChildren = item.children && isBigDataPage && item.path === '/bigdata';

              return (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    className={`flex items-center px-4 py-2 rounded-lg transition-colors ${
                      active
                        ? 'bg-blue-50 text-blue-600'
                        : 'text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    <Icon className="h-5 w-5 mr-3" />
                    <span className="font-medium">{item.name}</span>
                    {item.children && (
                      <ChevronRight className={`h-4 w-4 ml-auto transition-transform ${
                        showChildren ? 'rotate-90' : ''
                      }`} />
                    )}
                  </Link>

                  {/* Sub-navigation for Big Data */}
                  {showChildren && (
                    <ul className="mt-1 ml-4 space-y-1">
                      {item.children.map((child) => (
                        <li key={child.path}>
                          <Link
                            to={child.path}
                            className={`flex items-center px-4 py-2 rounded-lg text-sm transition-colors ${
                              location.pathname === child.path
                                ? 'bg-blue-50 text-blue-600'
                                : 'text-gray-600 hover:bg-gray-50'
                            }`}
                          >
                            <span>{child.name}</span>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>
        </nav>

        {/* User section */}
        <div className="p-4 border-t border-gray-200">
          <button
            onClick={handleLogout}
            className="flex items-center w-full px-4 py-2 text-gray-700 hover:bg-gray-50 rounded-lg transition-colors"
          >
            <LogOut className="h-5 w-5 mr-3" />
            <span className="font-medium">Logout</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <div className="container mx-auto p-8">
          {children}
        </div>
      </main>
    </div>
  );
}
