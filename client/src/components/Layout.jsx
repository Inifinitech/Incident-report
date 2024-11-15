
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

export default function Layout({ isAdmin }) {
  return (
    <div className="flex min-h-screen">
      <Sidebar isAdmin={isAdmin} />
      <div className="flex-1 bg-gray-900">
        <Outlet />
      </div>
    </div>
  );
}