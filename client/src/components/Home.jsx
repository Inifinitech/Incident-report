import { Link } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import videoBg from '../videos/response1.mp4';

export default function LandingPage() {
  return (
    <div className="relative min-h-screen flex items-center justify-center overflow-hidden text-white">
      <video
        autoPlay
        loop
        muted
        playsInline
        className="absolute inset-0 w-full h-full object-cover"
        style={{ filter: 'blur(4px) brightness(0.4)' }}
      >
        <source src={videoBg} type="video/mp4" />
      </video>

      <div className="absolute top-4 left-4 flex items-center gap-2 z-10">
        <AlertTriangle className="w-16 h-16 text-yellow-500" />
        <h1 className="text-4xl font-bold text-white">Zusha!</h1>
      </div>

      <div className="relative z-10 text-center px-4">

        <p className="text-xl md:text-2xl text-gray-200 mb-8 max-w-2xl mx-auto">
          Report and track incidents in real-time before or after they happen. Help make our communities safer together.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            to="/login"
            className="px-8 py-3 p-8 bg-yellow-500 text-gray-900 font-semibold rounded-lg hover:bg-yellow-400 transition-colors duration-300"
          >
            Sign In
          </Link>
          <Link
            to="/signup"
            className="px-8 py-3 p-8 bg-gray-800 text-white font-semibold rounded-lg hover:bg-gray-700 transition-colors duration-300 border border-gray-600"
          >
            Create Account
          </Link>
        </div>

        <div className="mt-12 text-gray-400">
          <p>An Emergency that can't wait? Click here!</p>
        </div>
      </div>
    </div>
  );
}
