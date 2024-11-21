import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

export default function Layout({ isAdmin }) {
  return (
    <div className="flex min-h-screen">
      <div className="w-64 fixed top-0 left-0 h-full bg-gray-900">
        <Sidebar isAdmin={isAdmin} />
      </div>

      <div className="flex-1 ml-64 bg-gray-900">
        <Outlet />
      </div>
    </div>
  );
}
