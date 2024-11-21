import React from 'react';
import { StarRating } from './StarRating';
import { Clock } from 'lucide-react';

export function ReviewCard({ author, content, rating, date }) {
  return (
    <div className="bg-gray-700 rounded-lg p-4">
      <div className="flex items-center gap-4 mb-3">
        <StarRating rating={rating} />
      </div>
      <p className="text-gray-300 mb-3">{content}</p>
      <div className="flex justify-between items-center text-sm text-gray-400">
        <p>- {author}</p>
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4" />
          <span>{date}</span>
        </div>
      </div>
    </div>
  );
}