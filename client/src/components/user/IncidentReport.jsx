import { useState, useRef } from 'react';
import { Camera, MapPin } from 'lucide-react';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import toast from 'react-hot-toast';

export default function IncidentReport() {
  const [location, setLocation] = useState('');
  const [latLong, setLatLong] = useState({ lat: '', long: '' });
  const [imagePreviews, setImagePreviews] = useState([]);
  const [videoPreviews, setVideoPreviews] = useState([]);
  const [responseMessage, setResponseMessage] = useState('');

  const imageInputRef = useRef(null);
  const videoInputRef = useRef(null);

  const formik = useFormik({
    initialValues: {
      description: '',
      location: '',
      latitude: '',
      longitude: '',
      images: [],
      videos: [],
    },
    validationSchema: Yup.object({
      description: Yup.string().required('Description is required'),
      location: Yup.string().required('Location is required'),
    }),
    onSubmit: async (values) => {
      try {
        const formData = new FormData();
        formData.append('user_id', localStorage.getItem('user_id'));
        formData.append('description', values.description);
        formData.append('location', values.location);
        formData.append('latitude', values.latitude);
        formData.append('longitude', values.longitude);

        values.images.forEach((image) => {
          formData.append('media_image', image);
        });

        values.videos.forEach((video) => {
          formData.append('media_video', video);
        });

        const response = await fetch('https://incident-report-98rf.onrender.com/incidents', {
          method: 'POST',
          body: formData,
        });

        if (response.ok) {
          const data = await response.json();
          toast.success('Incident reported successfully. Help is on the way!');
          formik.resetForm();
          setImagePreviews([]);
          setVideoPreviews([]);
        } else {
          const errorData = await response.json();
          toast.error(errorData.error || 'Error posting incident or media.');
        }
      } catch (error) {
        console.error('Error creating incident or uploading media:', error);
        toast.error('An unexpected error occurred. Please try again.');
      }
    },
  });

  const handleLocationChange = (e) => {
    setLocation(e.target.value);
    formik.setFieldValue('location', e.target.value);
  };

  const handleGeolocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition((position) => {
        const { latitude, longitude } = position.coords;
        setLatLong({ lat: latitude, long: longitude });
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
      alert('Geolocation is not supported by this browser.');
    }
  };

  const handleImageUpload = (e) => {
    const files = Array.from(e.target.files);
    formik.setFieldValue('images', files);

    const imageUrls = files.map((file) => URL.createObjectURL(file));
    setImagePreviews(imageUrls);
  };

  const handleVideoUpload = (e) => {
    const files = Array.from(e.target.files);
    formik.setFieldValue('videos', files);

    const videoUrls = files.map((file) => URL.createObjectURL(file));
    setVideoPreviews(videoUrls);
  };

  const triggerImageUpload = () => {
    imageInputRef.current.click();
  };

  const triggerVideoUpload = () => {
    videoInputRef.current.click();
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-6 text-white">Report an Incident</h1>

      <div className="bg-gray-800 rounded-lg p-6 space-y-6">
        <form onSubmit={formik.handleSubmit} className="space-y-4">
          <div>
            <label className="block">
              <span className="text-lg font-medium text-white">What happened?</span>
              <textarea
                className="mt-2 w-full bg-gray-700 text-white px-4 py-3 rounded-lg border border-gray-600 focus:outline-none focus:border-yellow-500"
                rows={4}
                placeholder="Describe the incident in detail..."
                name="description"
                value={formik.values.description}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
              />
              {formik.touched.description && formik.errors.description && (
                <div className="text-red-500 text-sm">{formik.errors.description}</div>
              )}
            </label>
          </div>

          <div>
            <label className="block">
              <span className="text-lg font-medium text-white">Location</span>
              <div className="mt-2 flex gap-2">
                <input
                  type="text"
                  className="flex-1 bg-gray-700 text-white px-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-yellow-500"
                  placeholder="Enter location or use map pin"
                  name="location"
                  value={formik.values.location}
                  onChange={handleLocationChange}
                  onBlur={formik.handleBlur}
                />
                <button
                  type="button"
                  className="p-2 bg-gray-700 text-gray-400 hover:text-white rounded-lg"
                  onClick={handleGeolocation}
                >
                  Use My Location
                  <MapPin className="w-5 h-5" />
                </button>
              </div>
              {formik.touched.location && formik.errors.location && (
                <div className="text-red-500 text-sm">{formik.errors.location}</div>
              )}
            </label>
          </div>

          <div>
            <span className="text-lg font-medium text-white">Evidence</span>
            <div className="mt-2 flex gap-4">
              <button
                type="button"
                className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-gray-400 hover:text-white rounded-lg"
                onClick={triggerImageUpload}
              >
                <Camera className="w-5 h-5" />
                <span>Add Photos</span>
                <input
                  ref={imageInputRef}
                  type="file"
                  accept="image/*"
                  multiple
                  className="hidden"
                  onChange={handleImageUpload}
                />
              </button>
              <button
                type="button"
                className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-gray-400 hover:text-white rounded-lg"
                onClick={triggerVideoUpload}
              >
                <Camera className="w-5 h-5" />
                <span>Add Videos</span>
                <input
                  ref={videoInputRef}
                  type="file"
                  accept="video/*"
                  multiple
                  className="hidden"
                  onChange={handleVideoUpload}
                />
              </button>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-4">
              {imagePreviews.map((url, idx) => (
                <img key={idx} src={url} alt={`preview-${idx}`} className="h-24 object-cover rounded-lg" />
              ))}
              {videoPreviews.map((url, idx) => (
                <video key={idx} src={url} className="h-24 object-cover rounded-lg" controls />
              ))}
            </div>
          </div>

          <div>
            <button
              type="submit"
              className="w-full py-3 bg-yellow-500 text-white rounded-lg focus:outline-none hover:bg-yellow-400"
            >
              Report Incident
            </button>
          </div>
        </form>
      </div>

      {responseMessage && (
        <div className="mt-4 text-white">
          <strong>{responseMessage}</strong>
        </div>
      )}
    </div>
  );
}
