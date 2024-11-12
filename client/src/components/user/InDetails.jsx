import React, { useState } from "react";
import { AlertTriangle, Clock, MapPin, Camera, MessageSquare, Star } from "lucide-react";
import { StarRating } from "../StarRating.jsx";
import { ReviewCard } from "../ReviewCard.jsx";
import { ReviewForm } from "../ReviewForm.jsx";


export default function IncidentDetails() {
  const [showReviewForm, setShowReviewForm] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [reviews, setReviews] = useState([
    {
      id: 1,
      author: 'Fire Fighter',
      content: 'Swift response and effective coordination at the scene.',
      rating: 4,
      date: '2024-03-10',
      incidentId: 'INC-001'
    },
    {
      id: 2,
      author: 'Witness',
      content: 'Excellent handling of the situation with swift response.',
      rating: 5,
      date: '2024-03-09',
      incidentId: 'INC-001'
    }
  ]);

  const incidents = [
    {
      id: "INC-001",
      title: "Traffic Accident on Highway",
      status: "Under Investigation",
      location: "Mombasa Road, Near Exit 7",
      description: "Multiple vehicle collision reported...",
      timestamp: "2024-02-28 14:30",
      images: ["https://images.unsplash.com/photo-1584438784894-089d6a62b8fa?w=800&auto=format&fit=crop"]
    },
    {
      id: "INC-002",
      title: "Building Fire Emergency",
      status: "Resolved",
      location: "Central Business District",
      description: "Commercial building fire incident...",
      timestamp: "2024-02-28 12:15",
      images: ["https://images.unsplash.com/photo-1599587897943-467f82141a45?w=800&auto=format&fit=crop"]
    }
  ];

  const handleSubmitReview = (reviewData) => {
    if (!selectedIncidentId) return;
    
    const newReview = {
      id: reviews.length + 1,
      author: 'Anonymous User',
      content: reviewData.content,
      rating: reviewData.rating,
      date: new Date().toISOString().split('T')[0],
      incidentId: selectedIncidentId
    };
    setReviews([newReview, ...reviews]);
    setShowReviewForm(false);
  };

  const getIncidentReviews = (incidentId) => {
    return reviews.filter(review => review.incidentId === incidentId);
  };

  const getAverageRating = (incidentId) => {
    const incidentReviews = getIncidentReviews(incidentId);
    if (incidentReviews.length === 0) return 0;
    return incidentReviews.reduce((acc, review) => acc + review.rating, 0) / incidentReviews.length;
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-6 text-white">Incident Details</h1>

      <div className="space-y-6">
        {incidents.map((incident) => {
          const incidentReviews = getIncidentReviews(incident.id);
          const averageRating = getAverageRating(incident.id);

          return (
            <div key={incident.id} className="bg-gray-800 rounded-lg overflow-hidden text-white">
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold text-white">{incident.title}</h2>
                  <span className={`px-3 py-1 rounded-full text-sm ${
                    incident.status === 'Resolved' ? 'bg-green-500' : 'bg-yellow-500'
                  } text-gray-900`}>
                    {incident.status}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <div className="flex items-center gap-2 text-gray-400 mb-2">
                      <MapPin className="w-4 h-4" />
                      <span>{incident.location}</span>
                    </div>
                    <div className="flex items-center gap-2 text-gray-400 mb-4">
                      <Clock className="w-4 h-4" />
                      <span>{incident.timestamp}</span>
                    </div>
                    <p className="text-gray-300">{incident.description}</p>
                  </div>

                  <div>
                    <img 
                      src={incident.images[0]} 
                      alt={incident.title}
                      className="w-full h-48 object-cover rounded-lg"
                    />
                  </div>
                </div>

                <div className="mt-6 flex flex-wrap gap-4">
                  <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-gray-400 hover:text-white rounded-lg">
                    <Camera className="w-4 h-4" />
                    <span>Add Media</span>
                  </button>
                  <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-gray-400 hover:text-white rounded-lg">
                    <MessageSquare className="w-4 h-4" />
                    <span>Comment</span>
                  </button>
                  <button 
                    onClick={() => {
                      setSelectedIncidentId(incident.id);
                      setShowReviewForm(true);
                    }}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white hover:bg-blue-700 rounded-lg"
                  >
                    <Star className="w-4 h-4" />
                    <span>Rate Response</span>
                  </button>
                </div>

                {incidentReviews.length > 0 && (
                  <div className="mt-6">
                    <div className="flex items-center gap-3 mb-4">
                      <h3 className="text-lg font-semibold">Response Ratings</h3>
                      <div className="flex items-center gap-2">
                        <StarRating rating={averageRating} />
                        <span className="text-gray-400">
                          ({incidentReviews.length} {incidentReviews.length === 1 ? 'review' : 'reviews'})
                        </span>
                      </div>
                    </div>
                    <div className="space-y-4">
                      {incidentReviews.map((review) => (
                        <ReviewCard key={review.id} {...review} />
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {showReviewForm && selectedIncidentId && (
        <ReviewForm
          onSubmit={handleSubmitReview}
          onClose={() => {
            setShowReviewForm(false);
            setSelectedIncidentId(null);
          }}
          incidentId={selectedIncidentId}
        />
      )}
    </div>
  );
}