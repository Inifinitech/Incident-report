import { useState } from 'react';
import { Camera, MapPin, AlertTriangle, ThumbsUp, MessageSquare, Share2, Clock } from 'lucide-react';
import { AlertCard } from './user/AlertCard';
import { StatCard } from './user/StatCard';

export default function UserDashboard() {
  const [newIncident, setNewIncident] = useState('');

  return (
    <div className="flex min-h-screen bg-gray-900">
      <div className="flex-1 p-6">
        <div className="bg-gray-800 rounded-lg p-6 mb-8">
          <div className="flex items-center gap-4 mb-4">
            <input
              type="text"
              placeholder="What happened?"
              className="flex-1 bg-gray-700 text-white px-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-yellow-500"
              value={newIncident}
              onChange={(e) => setNewIncident(e.target.value)}
            />
            <div className="flex gap-2">
              <button className="p-2 text-gray-400 hover:text-white">
                <Camera className="w-5 h-5" />
              </button>
              <button className="p-2 text-gray-400 hover:text-white">
                <MapPin className="w-5 h-5" />
              </button>
              <button className="p-2 text-gray-400 hover:text-white">
                <AlertTriangle className="w-5 h-5" />
              </button>
            </div>
            <button className="px-6 py-2 bg-yellow-500 text-gray-900 font-medium rounded-lg hover:bg-yellow-600 transition-colors">
              Submit Report
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <StatCard
            icon={AlertTriangle}
            title="Active Incidents"
            value="15"
            change={10}
            timeframe="week"
          />
          <StatCard
            icon={Clock}
            title="Resolved Incidents"
            value="42"
            change={20}
            timeframe="month"
          />
          <StatCard
            icon={ThumbsUp}
            title="User Engagement"
            value="238 Likes"
            change={5}
            timeframe="day"
          />
        </div>

        <div className="bg-gray-800 rounded-lg p-6 mb-8">
          <div className="flex items-start gap-4">
            <div className="flex-1">
              <h3 className="font-medium text-white">Report an accident or emergency now</h3>
              <p className="text-gray-400 mt-2">
                Welcome to Ajali! Incident Reporting, a modern web application designed for
                reporting accidents and emergencies in Kenya. Our user-friendly features for incident
                reporting help save lives.
              </p>
              <div className="mt-4 flex gap-4">
                <button className="flex items-center gap-2 text-gray-400 hover:text-white">
                  <ThumbsUp className="w-5 h-5" />
                  <span>238 Likes</span>
                </button>
                <button className="flex items-center gap-2 text-gray-400 hover:text-white">
                  <MessageSquare className="w-5 h-5" />
                  <span>42 Comments</span>
                </button>
                <button className="flex items-center gap-2 text-gray-400 hover:text-white">
                  <Share2 className="w-5 h-5" />
                  <span>Share</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-bold mb-4 text-white">Recent Alerts</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <AlertCard
              image="https://images.pexels.com/photos/1739855/pexels-photo-1739855.jpeg?auto=compress&cs=tinysrgb&w=300"
              title="Flood Alert"
              description="Heavy rains are expected in the next 48 hours, causing potential floods."
              time="2 hours ago"
              location="Nairobi, Kenya"
              severity="high"
              status="Resolved"
            />
            <AlertCard
              image="https://images.pexels.com/photos/189524/pexels-photo-189524.jpeg?auto=compress&cs=tinysrgb&w=300"
              title="Power Outage"
              description="Scheduled maintenance may cause power outages in your area."
              time="1 day ago"
              location="Mombasa, Kenya"
              severity="medium"
              status="Resolved"
            />
            <AlertCard
              image="https://images.pexels.com/photos/10476391/pexels-photo-10476391.jpeg?auto=compress&cs=tinysrgb&w=300"
              title="Road Block"
              description="A fallen tree is blocking the main road in your area."
              time="3 hours ago"
              location="Kisumu, Kenya"
              severity="low"
              status="Resolved"
            />
          </div>
        </div>
      </div>
    </div>
  );
}