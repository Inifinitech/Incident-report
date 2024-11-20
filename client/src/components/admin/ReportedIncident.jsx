import { useState, useEffect } from 'react';
import { 
  Search,
  CheckCircle,
  Clock,
  XCircle,
  MapPin,
  Calendar,
  User,
  X as CloseIcon
} from 'lucide-react';

export default function ReportedIncidents() {
  const [incidents, setIncidents] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedImage, setSelectedImage] = useState(null);
  
  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        const response = await fetch('https://incident-report-98rf.onrender.com/incidents');
        const data = await response.json();

        const userIncidents = await Promise.all(data.map(async (incident) => {
          const { latitude, longitude } = incident;
          const location = latitude && longitude ? await fetchLocation(latitude, longitude) : "Location unavailable";
          return { 
            ...incident, 
            location, 
            type: 'user',
            images: incident.images || [],
            videos: incident.videos || [] 
          };
        }));

        const emergencyResponse = await fetch('https://incident-report-98rf.onrender.com/emergency-reporting');
        const emergencyData = await emergencyResponse.json();

        const emergencyIncidents = await Promise.all(emergencyData.map(async (emergency) => {
          const { latitude, longitude } = emergency;
          const location = latitude && longitude ? await fetchLocation(latitude, longitude) : "Location unavailable";
          return { 
            ...emergency, 
            location, 
            type: 'emergency',
            images: emergency.images || [], 
            videos: emergency.videos || []  
          };
        }));

        setIncidents([...userIncidents, ...emergencyIncidents]);
      } catch (error) {
        console.error("Error fetching incidents:", error);
      }
    };

    fetchIncidents();
  }, []);

  const fetchLocation = async (latitude, longitude) => {
    try {
      const response = await fetch(
        `https://api.opencagedata.com/geocode/v1/json?q=${latitude}+${longitude}&key=e8e97b4bccb04cbf84c4835212b56571`
      );
      const data = await response.json();
      return data.results[0]?.formatted || `Lat: ${latitude}, Long: ${longitude}`;
    } catch (error) {
      console.error("Error fetching location data:", error);
      return `Lat: ${latitude}, Long: ${longitude}`;
    }
  };

  const updateStatus = async (id, newStatus, type) => {
    const url = type === 'emergency' ? `https://incident-report-98rf.onrender.com/emergency/${id}/status` : `https://incident-report-98rf.onrender.com/incident/${id}/status`;

    try {
      const response = await fetch(url, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: newStatus })
      });
      
      if (response.ok) {
        setIncidents((prevIncidents) =>
          prevIncidents.map((incident) =>
            incident.id === id ? { ...incident, status: newStatus } : incident
          )
        );
      } else {
        console.error("Failed to update incident status");
      }
    } catch (error) {
      console.error("Error updating incident status:", error);
    }
  };

  const openImageModal = (image) => {
    setSelectedImage(image);
  };

  const closeImageModal = () => {
    setSelectedImage(null);
  };

  const filteredIncidents = incidents.filter((incident) => 
    incident.description.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 text-white relative">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Incident Management</h1>
        <div className="flex gap-4">
          <div className="relative">
            <input
              type="text"
              placeholder="Search incidents..."
              className="pl-10 pr-4 py-2 bg-gray-800 rounded-lg border border-gray-700 focus:outline-none focus:border-yellow-500"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <Search className="w-5 h-5 text-gray-400 absolute left-3 top-2.5" />
          </div>
          <select
            className="px-4 py-2 bg-gray-800 rounded-lg border border-gray-700 focus:outline-none focus:border-yellow-500"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="all">All Status</option>
            <option value="under investigation">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="rejected">Rejected</option>
          </select>
        </div>
      </div>

      <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
        <h2 className="text-xl font-bold mb-4 text-yellow-500">Emergency Reports</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredIncidents.filter((incident) => incident.type === 'emergency').map((incident) => (
            <div key={incident.id} className="bg-gray-800 rounded-lg overflow-hidden shadow-lg">
              <div className="p-4 space-y-4">
                <div className="flex items-start justify-between">
                  <h2 className="text-lg font-bold">{incident.description}</h2>
                  <span className={`px-3 py-1 rounded-full text-sm ${
                    incident.status === 'resolved' ? 'bg-green-500' :
                    incident.status === 'under investigation' ? 'bg-yellow-500' :
                    incident.status === 'rejected' ? 'bg-red-500' :
                    'bg-gray-500'
                  } text-gray-900`}>
                    {incident.status}
                  </span>
                </div>

                <div className="text-sm space-y-2">
                  <div className="flex items-center gap-2 text-gray-400">
                    <MapPin className="w-4 h-4" />
                    <span>{incident.location}</span>
                  </div>
                  <div className="flex items-center gap-2 text-gray-400">
                    <Calendar className="w-4 h-4" />
                    <span>{incident.date}</span>
                  </div>
                  <div className="flex items-center gap-2 text-gray-400">
                    <User className="w-4 h-4" />
                    <span>Reported by: {incident.reporter || "Emergency Service"}</span>
                  </div>
                </div>

                <div className="flex gap-4 items-center">
                  {incident.images?.length > 0 && (
                    <div className="space-y-2">
                      {incident.images.map((image, index) => (
                        <img
                          key={index}
                          src={image}
                          alt={`Incident ${incident.id}`}
                          className="w-32 h-32 object-cover rounded-md cursor-pointer"
                          onClick={() => openImageModal(image)}
                        />
                      ))}
                    </div>
                  )}

                  {incident.videos?.length > 0 && (
                    <div className="space-y-2">
                      {incident.videos.map((video, index) => (
                        <video
                          key={index}
                          controls
                          className="w-48 h-32 object-cover rounded-md"
                          src={video}
                        />
                      ))}
                    </div>
                  )}
                </div>

                <div className="mt-4 flex gap-2 flex-wrap">
                  <button
                    onClick={() => updateStatus(incident.id, 'under investigation', incident.type)}
                    className="px-3 py-1 bg-yellow-500 text-gray-900 rounded-md text-xs hover:bg-yellow-600 transition-colors flex items-center gap-1"
                  >
                    <Clock className="w-3 h-3" />
                    Investigate
                  </button>
                  <button
                    onClick={() => updateStatus(incident.id, 'resolved', incident.type)}
                    className="px-3 py-1 bg-green-500 text-white rounded-md text-xs hover:bg-green-600 transition-colors flex items-center gap-1"
                  >
                    <CheckCircle className="w-3 h-3" />
                    Resolve
                  </button>
                  <button
                    onClick={() => updateStatus(incident.id, 'rejected', incident.type)}
                    className="px-3 py-1 bg-red-500 text-white rounded-md text-xs hover:bg-red-600 transition-colors flex items-center gap-1"
                  >
                    <XCircle className="w-3 h-3" />
                    Reject
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-gray-800 p-6 rounded-lg shadow-lg mt-8">
        <h2 className="text-xl font-bold mb-4 text-yellow-500">User-Reported Incidents</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredIncidents.filter((incident) => incident.type === 'user').map((incident) => (
            <div key={incident.id} className="bg-gray-800 rounded-lg overflow-hidden shadow-lg">
              <div className="p-4 space-y-4">
                <div className="flex items-start justify-between">
                  <h2 className="text-lg font-bold">{incident.description}</h2>
                  <span className={`px-3 py-1 rounded-full text-sm ${
                    incident.status === 'resolved' ? 'bg-green-500' :
                    incident.status === 'under investigation' ? 'bg-yellow-500' :
                    incident.status === 'rejected' ? 'bg-red-500' :
                    'bg-gray-500'
                  } text-gray-900`}>
                    {incident.status}
                  </span>
                </div>

                <div className="text-sm space-y-2">
                  <div className="flex items-center gap-2 text-gray-400">
                    <MapPin className="w-4 h-4" />
                    <span>{incident.location}</span>
                  </div>
                  <div className="flex items-center gap-2 text-gray-400">
                    <Calendar className="w-4 h-4" />
                    <span>{incident.date}</span>
                  </div>
                  <div className="flex items-center gap-2 text-gray-400">
                    <User className="w-4 h-4" />
                    <span>Reported by: {incident.reporter || "Unknown"}</span>
                  </div>
                </div>

                <div className="flex gap-4 items-center">
                  {incident.images?.length > 0 && (
                    <div className="space-y-2">
                      {incident.images.map((image, index) => (
                        <img
                          key={index}
                          src={image}
                          alt={`Incident ${incident.id}`}
                          className="w-32 h-32 object-cover rounded-md cursor-pointer"
                          onClick={() => openImageModal(image)}
                        />
                      ))}
                    </div>
                  )}

                  {incident.videos?.length > 0 && (
                    <div className="space-y-2">
                      {incident.videos.map((video, index) => (
                        <video
                          key={index}
                          controls
                          className="w-48 h-32 object-cover rounded-md"
                          src={video}
                        />
                      ))}
                    </div>
                  )}
                </div>

                <div className="mt-4 flex gap-2 flex-wrap">
                  <button
                    onClick={() => updateStatus(incident.id, 'under investigation', incident.type)}
                    className="px-3 py-1 bg-yellow-500 text-gray-900 rounded-md text-xs hover:bg-yellow-600 transition-colors flex items-center gap-1"
                  >
                    <Clock className="w-3 h-3" />
                    Investigate
                  </button>
                  <button
                    onClick={() => updateStatus(incident.id, 'resolved', incident.type)}
                    className="px-3 py-1 bg-green-500 text-white rounded-md text-xs hover:bg-green-600 transition-colors flex items-center gap-1"
                  >
                    <CheckCircle className="w-3 h-3" />
                    Resolve
                  </button>
                  <button
                    onClick={() => updateStatus(incident.id, 'rejected', incident.type)}
                    className="px-3 py-1 bg-red-500 text-white rounded-md text-xs hover:bg-red-600 transition-colors flex items-center gap-1"
                  >
                    <XCircle className="w-3 h-3" />
                    Reject
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {selectedImage && (
        <div className="fixed inset-0 flex justify-center items-center bg-black bg-opacity-50 z-50">
          <div className="bg-white p-4 rounded-lg max-w-xl w-full">
            <button
              className="absolute top-4 right-4 text-black"
              onClick={closeImageModal}
            >
              <CloseIcon className="w-6 h-6" />
            </button>
            <img
              src={selectedImage}
              alt="Incident"
              className="w-full h-auto rounded-md"
            />
          </div>
        </div>
      )}
    </div>
  );
}
