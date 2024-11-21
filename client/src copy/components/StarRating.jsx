import React from 'react';
import { Star } from 'lucide-react';

export function StarRating({ rating, setRating, interactive = false }) {
  return (
    <div className="flex gap-1">
      {[1, 2, 3, 4, 5].map((star) => (
        <button
          key={star}
          onClick={() => interactive && setRating?.(star)}
          className={`${interactive ? 'cursor-pointer hover:scale-110' : 'cursor-default'} 
          transition-transform`}
          disabled={!interactive}
        >
          <Star
            className={`h-5 w-5 ${
              star <= rating
                ? 'fill-yellow-400 text-yellow-400'
                : 'fill-gray-600 text-gray-600'
            }`}
          />
        </button>
      ))}
    </div>
  );
}