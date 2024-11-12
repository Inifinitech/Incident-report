import React, { useState } from 'react';
import { StarRating } from './StarRating';
import { X } from 'lucide-react';

export function ReviewForm({ onSubmit, onClose, incidentId }) {
  const [rating, setRating] = useState(0);
  const [content, setContent] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (rating === 0) {
      setError('Please select a rating');
      return;
    }
    if (!content.trim()) {
      setError('Please write a review');
      return;
    }
    onSubmit({ rating, content });
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center p-4 z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md relative">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-gray-400 hover:text-gray-200"
        >
          <X className="h-6 w-6" />
        </button>
        
        <h2 className="text-2xl font-bold mb-6 text-white">Rate Response</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="mb-6">
            <label className="block text-gray-300 mb-2">Rating</label>
            <StarRating rating={rating} setRating={setRating} interactive />
          </div>
          
          <div className="mb-6">
            <label className="block text-gray-300 mb-2">Your Feedback</label>
            <textarea
              className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg 
                focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-white"
              rows={4}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Write your feedback here..."
            />
          </div>

          {error && (
            <p className="text-red-400 mb-4">{error}</p>
          )}

          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-3 rounded-lg 
              hover:bg-blue-700 transition-colors"
          >
            Submit Feedback
          </button>
        </form>
      </div>
    </div>
  );
}