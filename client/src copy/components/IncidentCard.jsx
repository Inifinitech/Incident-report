import React from 'react';
import { Link } from 'react-router-dom';
import { MapPin, Clock, AlertCircle } from 'lucide-react';

const statusColors = {
  pending: 'bg-yellow-100 text-yellow-800',
  investigating: 'bg-blue-100 text-blue-800',
  rejected: 'bg-red-100 text-red-800',
  resolved: 'bg-green-100 text-green-800',
};

function IncidentCard({ incident }) {
  return (
    <Link
      to={`/incident/${incident.id}`}
      className="block rounded-lg bg-white p-6 shadow-md transition-transform hover:scale-[1.02]"
    >
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-xl font-semibold text-gray-900">{incident.title}</h3>
        <span
          className={`rounded-full px-3 py-1 text-sm font-medium ${
            statusColors[incident.status]
          }`}
        >
          {incident.status}
        </span>
      </div>
      <p className="mb-4 text-gray-600 line-clamp-2">{incident.description}</p>
      <div className="flex flex-wrap gap-4 text-sm text-gray-500">
        <div className="flex items-center gap-1">
          <MapPin className="h-4 w-4" />
          <span>{incident.location.address}</span>
        </div>
        <div className="flex items-center gap-1">
          <Clock className="h-4 w-4" />
          <span>{new Date(incident.createdAt).toLocaleDateString()}</span>
        </div>
        {incident.images.length > 0 && (
          <div className="flex items-center gap-1">
            <AlertCircle className="h-4 w-4" />
            <span>{incident.images.length} images</span>
          </div>
        )}
      </div>
    </Link>
  );
}

export default IncidentCard;
