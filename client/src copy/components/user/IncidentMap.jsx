import { MapPin } from 'lucide-react';

export default function IncidentsMap() {
  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold text-white mb-6">Incidents Map</h1>
      
      <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
        <div className="aspect-[16/9] bg-gray-700 rounded-lg flex items-center justify-center relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-t from-black/70 to-transparent" />
          <div className="z-10 text-center">
            <MapPin className="w-16 h-16 mx-auto mb-4 text-yellow-500" />
            <p className="text-lg text-gray-300">Map integration is coming soon to help you track incidents in real-time!</p>
          </div>
        </div>
      </div>
    </div>
  );
}
