
import { NavLink, useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, 
  Map, 
  Settings, 
  LogOut, 
  Bell, 
  Upload, 
  Camera,
  FileText,
  Home,
  User
} from 'lucide-react';

export default function Sidebar({ isAdmin = false }) {
  const navigate = useNavigate();
  const navItems = isAdmin ? [
    { icon: Home, label: 'Dashboard', path: '/admin/d' },
    { icon: AlertTriangle, label: 'Incident Reports', path: '/admin/incidents' },
    { icon: User, label: 'User Submissions', path: '/admin/user' },
    {icon: User, label: 'User Management', path: '/admin/usermanagement'},
    { icon: Bell, label: 'Analytics', path: '/admin/analytics' },
    { icon: Settings, label: 'Settings', path: '/admin/settings' }
  ] : [
    { icon: Home, label: 'Home', path: '/user' },
    { icon: AlertTriangle, label: 'Report an Incident', path: '/report' },
    { icon: Map, label: 'Incidents Map', path: '/map' },
    { icon: Bell, label: 'News & Updates', path: '/news' },
    { icon: FileText, label: 'Incident Details', path: '/incidents' },
    { icon: Settings, label: 'App Settings', path: '/settings' }
  ];

  const handleLogout = () => {
    localStorage.removeItem("user_id");
    navigate("/");
  };
 return (
    <div className="w-64 h-100 bg-gray-900 text-white p-4">
      <div className="flex items-center gap-2 mb-8">
        <AlertTriangle className="w-8 h-8 text-yellow-400" />
        <h1 className="text-xl font-bold">Rescue! Platform</h1>
      </div>

      <nav className="space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2 rounded-lg transition-colors ${
                isActive
                  ? 'bg-yellow-500 text-gray-900'
                  : 'hover:bg-gray-800'
              }`
            }
          >
            <item.icon className="w-5 h-5" />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="absolute bottom-4 left-4 right-4">
        <button onClick={handleLogout} className="flex items-center gap-2 w-full px-4 py-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors">

          <LogOut className="w-5 h-5" />
          <span>Log Out</span>
        </button>
      </div>
    </div>
  );
}