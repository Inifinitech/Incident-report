import React from 'react';
import { Clock, MapPin, AlertTriangle, ArrowRight } from 'lucide-react';

const severityColors = {
  high: 'bg-red-500',
  medium: 'bg-orange-500',
  low: 'bg-yellow-500'
};

export function AlertCard({ image, title, description, time, location, severity, status }) {
  return (
    <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl overflow-hidden border border-gray-700/50 hover:border-yellow-500/50 transition-all duration-300 group">
      <div className="relative">
        <img src={image} alt={title} className="w-full h-48 object-cover" />
        <div className="absolute inset-0 bg-gradient-to-t from-gray-900 to-transparent" />
        <div className={`absolute top-4 right-4 ${severityColors[severity]} text-white text-xs font-bold px-2 py-1 rounded-full`}>
          {severity.toUpperCase()}
        </div>
      </div>
      
      <div className="p-5">
        <div className="flex items-start justify-between">
          <h3 className="text-lg font-semibold text-white group-hover:text-yellow-400 transition-colors">{title}</h3>
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
            status === 'Active' ? 'bg-green-500/20 text-green-400' : 'bg-gray-700 text-gray-400'
          }`}>
            {status}
          </span>
        </div>
        
        <p className="text-gray-400 mt-2 text-sm line-clamp-2">{description}</p>
        
        <div className="mt-4 space-y-2">
          <div className="flex items-center text-gray-500 text-sm">
            <Clock className="h-4 w-4 mr-2" />
            <span>{time}</span>
          </div>
          <div className="flex items-center text-gray-500 text-sm">
            <MapPin className="h-4 w-4 mr-2" />
            <span>{location}</span>
          </div>
        </div>
        
        <button className="mt-4 w-full bg-gray-700/50 hover:bg-yellow-500 text-gray-300 hover:text-gray-900 py-2 px-4 rounded-lg font-medium text-sm transition-all duration-300 flex items-center justify-center space-x-2">
          <span>View Details</span>
          <ArrowRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
