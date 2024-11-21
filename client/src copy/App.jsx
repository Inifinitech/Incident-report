import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Layout from './components/Layout.jsx';
import AdminDashboard from './components/AdminDashboard.jsx';
import UserDashboard from './components/UserDashboard.jsx';
import IncidentReport from './components/user/IncidentReport';
import IncidentMap from './components/user/IncidentMap';
import News from './components/user/News';
import InDetails from './components/user/InDetails';
import UserSettings from './components/user/UserSettings';
import Login from './components/auth/Login';
import Signup from './components/auth/Signup';
import Home from './components/Home';
import Contact from './components/Contact';

import AppSettings from './components/admin/AppSettings.jsx';
import AdminOverview from './components/admin/AdminOverview.jsx';
import Analytics from './components/admin/Analytics.jsx'
import UserData from './components/admin/UserData.jsx'
import ReportedIncidents from './components/admin/ReportedIncident.jsx'
import AboutUs from "./components/AboutUs.jsx";
import Services from './components/Services.jsx';



function App() {
  return (
    <Router>
      <Routes>
       <Route path="/" element={<Home />} />
        {/* Authentication routes*/}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/contact" element={<Contact />} />

        {/* Layout with user/admin routes */}
        <Route element={<Layout isAdmin={false} />}>
          <Route path="/user" element={<UserDashboard />} />
          <Route path="/report" element={<IncidentReport />} />
          <Route path="/map" element={<IncidentMap />} />
          <Route path="/news" element={<News />} />
          <Route path="/incidents" element={<InDetails />} />
          <Route path="/settings" element={<UserSettings />} />

          <Route path="/about" element={<AboutUs />} />
          <Route path="/services" element={<Services />} />


        </Route>

        {/* Admin route */}
        <Route element={<Layout isAdmin={true} />}>
          <Route path="/admin" element={<AdminDashboard />} />
          <Route path="/admin/d" element={<AdminOverview />} />
          <Route path="admin/analytics" element={<Analytics />} />
          <Route path="admin/usermanagement" element={<UserData />} />
          <Route path="admin/incidents" element={<ReportedIncidents />} />
          <Route path="admin/settings" element={<AppSettings />} />
        </Route>
      </Routes>
      <Toaster position="top-right" />
    </Router>
  );
}

export default App;
