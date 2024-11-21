import React from 'react';
import { GoogleMap, LoadScript, Marker } from '@react-google-maps/api';

const GOOGLE_MAPS_API_KEY = 'YOUR_GOOGLE_MAPS_API_KEY';

function Map({ center, markers = [], zoom = 12, onLocationSelect }) {
  const mapStyles = {
    height: '100%',
    width: '100%',
  };

  const handleMapClick = React.useCallback(
    (e) => {
      if (onLocationSelect && e.latLng) {
        const lat = e.latLng.lat();
        const lng = e.latLng.lng();

        const geocoder = new google.maps.Geocoder();
        geocoder.geocode(
          { location: { lat, lng } },
          (results, status) => {
            if (status === 'OK' && results?.[0]) {
              onLocationSelect({
                lat,
                lng,
                address: results[0].formatted_address,
              });
            }
          }
        );
      }
    },
    [onLocationSelect]
  );

  return (
    <LoadScript googleMapsApiKey={GOOGLE_MAPS_API_KEY}>
      <GoogleMap
        mapContainerStyle={mapStyles}
        zoom={zoom}
        center={center}
        onClick={handleMapClick}
      >
        {markers.map((location, index) => (
          <Marker
            key={index}
            position={{ lat: location.lat, lng: location.lng }}
          />
        ))}
      </GoogleMap>
    </LoadScript>
  );
}

export default Map;
