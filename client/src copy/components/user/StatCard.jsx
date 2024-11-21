import React from 'react';

export function StatCard({ icon: Icon, title, value, change, timeframe }) {
  const isPositive = change > 0;

  return (
    <div className="bg-gray-800/50 backdrop-blur-lg rounded-xl p-6 border border-gray-700/50">
      <div className="flex items-center space-x-4">
        <div className="bg-yellow-500/10 p-3 rounded-lg">
          <Icon className="h-6 w-6 text-yellow-400" />
        </div>
        <div>
          <h3 className="text-sm font-medium text-gray-400">{title}</h3>
          <div className="flex items-baseline space-x-4">
            <span className="text-2xl font-bold text-white">{value}</span>
            <span className={`text-sm font-medium ${isPositive ? 'text-green-400' : 'text-red-400'}`}>
              {isPositive ? '+' : ''}{change}%
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1">vs. previous {timeframe}</p>
        </div>
      </div>
    </div>
  );
}
