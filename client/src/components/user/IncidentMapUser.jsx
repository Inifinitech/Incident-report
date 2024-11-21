import React, { useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Circle, ZoomControl } from 'react-leaflet';
import { Info } from 'lucide-react';
import 'leaflet/dist/leaflet.css';
import { Icon } from 'leaflet';

const defaultIcon = new Icon({
  iconUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon.png',
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon-2x.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
});

const incidents = [
  { 
    id: 1, 
    position: [-1.2921, 36.8219], 
    title: 'Traffic Accident', 
    description: 'Multi-vehicle collision',
    severity: 'high',
    time: '10 minutes ago',
    type: 'accident'
  },
  { 
    id: 2, 
    position: [-1.2864, 36.8172], 
    title: 'Fire Emergency', 
    description: 'Building fire reported',
    severity: 'critical',
    time: '25 minutes ago',
    type: 'fire'
  },
  { 
    id: 3, 
    position: [-1.2954, 36.8080], 
    title: 'Medical Emergency', 
    description: 'Ambulance requested',
    severity: 'medium',
    time: '1 hour ago',
    type: 'medical'
  }
];

function IncidentMapUser() {
  const [mapType, setMapType] = useState('streets');
  const [selectedIncident, setSelectedIncident] = useState(null);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'rgb(220, 38, 38)';
      case 'high': return 'rgb(234, 88, 12)';
      case 'medium': return 'rgb(234, 179, 8)';
      default: return 'rgb(59, 130, 246)';
    }
  };

  return (
    <div className="h-full w-full relative">
      <div className="absolute top-4 left-4 z-[1000] bg-white/10 backdrop-blur-md rounded-lg p-2 flex space-x-2">
        <button
          onClick={() => setMapType('streets')}
          className={`px-4 py-2 rounded-lg transition-all ${
            mapType === 'streets' ? 'bg-yellow-500 text-gray-900' : 'text-white hover:bg-white/10'
          }`}
        >
          Streets
        </button>
        <button
          onClick={() => setMapType('satellite')}
          className={`px-4 py-2 rounded-lg transition-all ${
            mapType === 'satellite' ? 'bg-yellow-500 text-gray-900' : 'text-white hover:bg-white/10'
          }`}
        >
          Satellite
        </button>
      </div>

      <div className="absolute bottom-4 right-4 z-[1000] bg-white/10 backdrop-blur-md rounded-lg p-4 w-80">
        <h3 className="text-white font-semibold mb-2 flex items-center">
          <Info className="h-4 w-4 mr-2" />
          Incident Summary
        </h3>
        <div className="space-y-2">
          {incidents.map((incident) => (
            <div
              key={incident.id}
              className={`p-2 rounded-lg transition-all cursor-pointer ${
                selectedIncident === incident.id
                  ? 'bg-yellow-500/20 border border-yellow-500/50'
                  : 'bg-white/5 hover:bg-white/10'
              }`}
              onClick={() => setSelectedIncident(incident.id)}
            >
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="text-white font-medium">{incident.title}</h4>
                  <p className="text-gray-400 text-sm">{incident.time}</p>
                </div>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                  incident.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                  incident.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-yellow-500/20 text-yellow-400'
                }`}>
                  {incident.severity.toUpperCase()}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <MapContainer
        center={[-1.2921, 36.8219]}
        zoom={13}
        style={{ height: '100%', width: '100%' }}
        zoomControl={false}
      >
        <ZoomControl position="bottomleft" />
        <TileLayer
          url={mapType === 'streets' 
            ? "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            : "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"
          }
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        />
        {incidents.map((incident) => (
          <React.Fragment key={incident.id}>
            <Marker
              position={incident.position}
              icon={defaultIcon}
            >
              <Popup>
                <div className="p-2">
                  <h3 className="font-bold text-lg">{incident.title}</h3>
                  <p className="text-sm text-gray-600">{incident.description}</p>
                  <p className="text-xs text-gray-500 mt-1">{incident.time}</p>
                </div>
              </Popup>
            </Marker>
            <Circle
              center={incident.position}
              radius={500}
              pathOptions={{
                color: getSeverityColor(incident.severity),
                fillColor: getSeverityColor(incident.severity),
                fillOpacity: 0.2
              }}
            />
          </React.Fragment>
        ))}
      </MapContainer>
    </div>
  );
}

export default IncidentMapUser;
