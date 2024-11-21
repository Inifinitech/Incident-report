import React from 'react';
import { 
  BarChart2, 
  TrendingUp, 
  Map, 
  AlertTriangle,
  Activity,
  Users
} from 'lucide-react';

export default function Analytics() {
  const recentActivity = [
    { type: 'incident', text: 'New incident reported in Westlands', time: '5 minutes ago' },
    { type: 'status', text: 'Incident #1234 marked as resolved', time: '15 minutes ago' },
    { type: 'user', text: 'New user registration: Jane Smith', time: '1 hour ago' },
  ];

  return (
    <div className="space-y-6 text-white">
      <h1 className="text-2xl font-bold">Analytics Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold">Incident Trends</h2>
            <TrendingUp className="w-6 h-6 text-yellow-500" />
          </div>
          <div className="h-48 flex items-center justify-center">
            <BarChart2 className="w-12 h-12 text-gray-400" />
          </div>
          <div className="mt-4">
            <p className="text-sm text-gray-400">15% increase from last month</p>
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold">Geographic Distribution</h2>
            <Map className="w-6 h-6 text-yellow-500" />
          </div>
          <div className="h-48 flex items-center justify-center">
            <Map className="w-12 h-12 text-gray-400" />
          </div>
          <div className="mt-4">
            <p className="text-sm text-gray-400">Most incidents reported in Nairobi</p>
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold">Response Times</h2>
            <Activity className="w-6 h-6 text-yellow-500" />
          </div>
          <div className="h-48 flex items-center justify-center">
            <Activity className="w-12 h-12 text-gray-400" />
          </div>
          <div className="mt-4">
            <p className="text-sm text-gray-400">Average response time: 15 minutes</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 p-6 rounded-lg">
          <h2 className="text-xl font-bold mb-4">Recent Activity</h2>
          <div className="space-y-4">
            {recentActivity.map((activity, index) => (
              <div key={index} className="flex items-start gap-4 p-4 bg-gray-700 rounded-lg">
                {activity.type === 'incident' && <AlertTriangle className="w-5 h-5 text-yellow-500" />}
                {activity.type === 'status' && <Activity className="w-5 h-5 text-green-500" />}
                {activity.type === 'user' && <Users className="w-5 h-5 text-blue-500" />}
                <div>
                  <p>{activity.text}</p>
                  <p className="text-sm text-gray-400">{activity.time}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg">
          <h2 className="text-xl font-bold mb-4">Incident Categories</h2>
          <div className="space-y-4">
            {[
              { category: 'Traffic Accidents', count: 45, color: 'bg-yellow-500' },
              { category: 'Medical Emergencies', count: 32, color: 'bg-red-500' },
              { category: 'Fire Incidents', count: 28, color: 'bg-orange-500' },
              { category: 'Security Alerts', count: 21, color: 'bg-blue-500' },
            ].map((category) => (
              <div key={category.category} className="p-4 bg-gray-700 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span>{category.category}</span>
                  <span className="font-bold">{category.count}</span>
                </div>
                <div className="w-full h-2 bg-gray-600 rounded-full">
                  <div
                    className={`h-full ${category.color} rounded-full`}
                    style={{ width: `${(category.count / 45) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
