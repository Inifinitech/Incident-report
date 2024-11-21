import React from 'react';
import { Bell, Search, User } from 'lucide-react';

const Header = ({ userName, profileImageUrl }) => {
  return (
    <header className="bg-[#2a2f33] shadow-lg">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex-1 flex items-center">
            <div className="relative w-96">
              <input
                type="text"
                placeholder="Search for incidents..."
                className="w-full bg-[#1a1f23] border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-gray-100"
              />
              <Search className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <button className="p-2 text-gray-400 hover:text-white">
              <Bell className="h-6 w-6" />
            </button>

            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-300">{userName || 'John Doe'}</span>
              <img
                src={profileImageUrl || "https://ui-avatars.com/api/?name=John+Doe"}
                alt="Profile"
                className="h-8 w-8 rounded-full"
              />
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
