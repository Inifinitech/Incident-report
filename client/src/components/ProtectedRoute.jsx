import { useContext } from "react";
import { Navigate } from "react-router-dom";
import { AppContext } from "../AppContext";

const ProtectedRoute = ({ children, isAdminRoute = false }) => {
  const { value } = useContext(AppContext); // Access AppContext
  const { userData } = value;

  if (!userData) {
    // If no user data is available, redirect to the login page
    return <Navigate to="/login" />;
  }

  // Check role for admin routes
  if (isAdminRoute && userData.role !== "admin") {
    // If the route is admin-only and the user is not an admin, redirect to user dashboard
    return <Navigate to="/user" />;
  }

  return children; // Render the protected component
};

export default ProtectedRoute;
