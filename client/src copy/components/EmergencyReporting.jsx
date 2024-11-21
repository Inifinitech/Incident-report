import React, { useState, useRef } from 'react';
import { AlertTriangle, MapPin, Phone, Send } from 'lucide-react';
import toast from 'react-hot-toast';
import { useFormik } from 'formik';
import * as Yup from 'yup';

export default function EmergencyReport({ onClose }) {
  const [loading, setLoading] = useState(false);
  const [coordinates, setCoordinates] = useState({ lat: null, lng: null });
  const [location, setLocation] = useState('');

  const formik = useFormik({
    initialValues: {
      description: '',
      location: '',
      contact: '',
      name: '',
    },
    validationSchema: Yup.object({
      description: Yup.string().required('Description is required'),
      location: Yup.string().required('Location is required'),
      contact: Yup.string().required('Contact is required'),
    }),
    onSubmit: async (values) => {
      setLoading(true);
      try {
        await getCoordinates(values.location);

        if (coordinates.lat && coordinates.lng) {
          const emergencyIncident = {
            name: values.name,
            description: values.description,
            phone: values.contact,
            latitude: coordinates.lat,
            longitude: coordinates.lng,
          };

          await addIncident(emergencyIncident);

          toast.success('Emergency reported! Help is on the way.');
          onClose();
        } else {
          toast.error('Unable to get location coordinates.');
        }
      } catch (error) {
        toast.error('Failed to submit emergency report. Please try again.');
      } finally {
        setLoading(false);
      }
    },
  });

  const getCoordinates = async (address) => {
    try {
      const apiKey = 'e8e97b4bccb04cbf84c4835212b56571';
      const response = await fetch(`https://api.opencagedata.com/geocode/v1/json?q=${address}&key=${apiKey}`);
      const data = await response.json();

      if (data.results && data.results.length > 0) {
        const { lat, lng } = data.results[0].geometry;
        setCoordinates({ lat, lng });
        setLocation(data.results[0].formatted || `Lat: ${lat}, Long: ${lng}`);
        formik.setFieldValue('location', data.results[0].formatted || `Lat: ${lat}, Long: ${lng}`);
      } else {
        toast.error('Location not found. Please check your address.');
      }
    } catch (error) {
      console.error(error);
      toast.error('Error fetching location coordinates.');
    }
  };

  const addIncident = async (incidentData) => {
    try {
      const response = await fetch('http://127.0.0.1:5555/emergency-reporting', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(incidentData),
      });

      if (!response.ok) {
        throw new Error('Failed to submit the emergency report');
      }
      const data = await response.json();
      return data;
    } catch (error) {
      console.error(error);
      throw error;
    }
  };

  const handleGeolocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition((position) => {
        const { latitude, longitude } = position.coords;
        setCoordinates({ lat: latitude, lng: longitude });
        formik.setFieldValue('latitude', latitude);
        formik.setFieldValue('longitude', longitude);

        fetch(`https://api.opencagedata.com/geocode/v1/json?q=${latitude}+${longitude}&key=e8e97b4bccb04cbf84c4835212b56571`)
          .then((res) => res.json())
          .then((data) => {
            const humanReadableLocation = data.results[0]?.formatted || `Lat: ${latitude}, Long: ${longitude}`;
            formik.setFieldValue('location', humanReadableLocation);
            setLocation(humanReadableLocation);
          })
          .catch((error) => {
            console.error('Error fetching location data:', error);
            formik.setFieldValue('location', `Lat: ${latitude}, Long: ${longitude}`);
            setLocation(`Lat: ${latitude}, Long: ${longitude}`);
          });
      });
    } else {
      toast.error('Geolocation is not supported by this browser.');
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-md">
        <div className="p-6">
          
          <div className="bg-yellow-500 text-white p-3 rounded-lg mb-6 text-center font-bold text-lg">
            <p>Post Real time <span className="underline text-green-500">images</span> and <span className="underline text-green-500">videos</span>,<span className="underline text-red-500">sign in</span></p>
            <p>For quicker updates and personalized emergency assistance, <span className="underline text-red-500">sign up or log in</span>. Your details help us prioritize your safety and keep you informed!</p>
          </div>

          <div className="flex items-center gap-3 mb-6">
            <AlertTriangle className="w-8 h-8 text-red-500 animate-pulse" />
            <h2 className="text-2xl font-bold">Emergency Report</h2>
          </div>

          <form onSubmit={formik.handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Your Name</label>
              <input
                type="text"
                className="w-full bg-gray-700 text-white px-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-red-500"
                placeholder="Your name"
                {...formik.getFieldProps('name')}
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">What's happening?</label>
              <textarea
                className="w-full bg-gray-700 text-white px-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-red-500"
                rows={3}
                placeholder="Describe the emergency situation..."
                {...formik.getFieldProps('description')}
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Location</label>
              <div className="relative">
                <input
                  type="text"
                  className="w-full bg-gray-700 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-red-500"
                  placeholder="Where is this happening?"
                  {...formik.getFieldProps('location')}
                  required
                />
                <MapPin className="w-5 h-5 text-gray-400 absolute left-3 top-2.5" />
              </div>
              <button
                type="button"
                className="mt-2 p-2 bg-gray-700 text-gray-400 hover:text-white rounded-lg"
                onClick={handleGeolocation}
              >
                Use my location
              </button>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Contact Number</label>
              <div className="relative">
                <input
                  type="tel"
                  className="w-full bg-gray-700 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-red-500"
                  placeholder="Your phone number for emergency contact"
                  {...formik.getFieldProps('contact')}
                  required
                />
                <Phone className="w-5 h-5 text-gray-400 absolute left-3 top-2.5" />
              </div>
            </div>

            <div className="flex gap-4 mt-6">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors flex items-center justify-center gap-2"
              >
                {loading ? 'Sending...' : <><Send className="w-4 h-4" /> Send Alert</>}
              </button>
            </div>
          </form>

          <div className="mt-6 text-center text-sm text-gray-400">
            <p>Your emergency report will be processed and help dispatched as soon as possible.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
