import { Link } from 'react-router-dom';
import { ArrowRight, Clock, Shield, Phone } from 'lucide-react';
import Navbar from './Navbar';

const VehicleCard = ({ category, type, details, price, perKm, recovery }) => (
  <div className="bg-white/10 rounded-xl shadow-lg p-8 transform transition-all duration-300 hover:scale-105 hover:shadow-xl border border-gray-100">
    <div className="flex justify-between items-start mb-6">
      <div>
        <h3 className="text-2xl font-bold text-gray-200">{category}</h3>
        <p className="text-gray-200 mt-1">{type}</p>
      </div>
      <div className="bg-yellow-400 text-black px-4 py-2 rounded-full text-sm font-medium">
        {details}
      </div>
    </div>
    <div className="space-y-4">
      <div className="flex justify-between items-center py-3 border-b border-gray-100">
        <span className="text-gray-400">Base Rate (0-30km)</span>
        <span className="text-lg font-semibold text-gray-500">{price}</span>
      </div>
      <div className="flex justify-between items-center py-3 border-b border-gray-100">
        <span className="text-gray-400">Per KM after 30km</span>
        <span className="text-lg font-semibold text-gray-500">{perKm}</span>
      </div>
      <div className="flex justify-between items-center py-3">
        <span className="text-gray-400">Recovery Service</span>
        <span className="text-lg font-semibold text-gray-500">{recovery}</span>
      </div>
    </div>
  </div>
);

const ProcessStep = ({ step, title, description }) => (
  <div className="relative flex items-start group">
    <div className="flex flex-col items-center mr-4">
      <div className="w-12 h-12 rounded-full bg-yellow-400 text-black flex items-center justify-center font-bold text-lg group-hover:bg-yellow-600 transition-colors">
        {step}
      </div>
      <div className="h-full w-0.5 bg-[#5D4E8C] opacity-20 mt-4"></div>
    </div>
    <div className="pb-12">
      <h4 className="text-xl font-bold text-gray-300 mb-2">{title}</h4>
      <p className="text-gray-300 leading-relaxed">{description}</p>
    </div>
  </div>
);

function Services() {
  return (
    <>
    <Navbar />
    <section className="py-20 bg-gray-900">
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-gray-400 mb-4">Our Towing & Recovery Rates</h2>
          <p className="text-gray-500 text-lg">Transparent pricing with no hidden charges*</p>
          <p className="text-sm text-gray-500 mt-2">*Rates may vary based on conditions and location</p>
        </div>

        <div className="grid lg:grid-cols-3 gap-8 mb-20">
          <VehicleCard
            category="Category A"
            type="Salon & Station Wagon"
            details="Up to 2 tons"
            price="KES 6,000"
            perKm="KES 220"
            recovery="KES 2,800"
          />
          <VehicleCard
            category="Category B"
            type="SUVs & Pickups"
            details="2-4 tons"
            price="KES 7,500"
            perKm="KES 240"
            recovery="KES 3,700"
          />
          <VehicleCard
            category="Category C"
            type="Light Trucks & Minibus"
            details="4-6 tons"
            price="KES 8,500"
            perKm="KES 290"
            recovery="KES 5,000"
          />
        </div>

        <div className=" rounded-2xl shadow-xl p-12 mt-20">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-200 mb-4">Service Delivery Journey</h2>
            <p className="text-gray-300 text-lg">Simple, streamlined process for quick assistance</p>
          </div>

          <div className="grid md:grid-cols-2 gap-12">
            <div className="space-y-8">
              <ProcessStep
                step="1"
                title="Report Incident"
                description="Use our mobile app, website, or call center to report your incident. Our 24/7 support ensures immediate attention."
              />
              <ProcessStep
                step="2"
                title="Location & Details"
                description="Share your location and incident details. Our system automatically finds the nearest service provider."
              />
              <ProcessStep
                step="3"
                title="Provider Assignment"
                description="Get connected with a verified service provider within minutes. Track their arrival in real-time."
              />
              <ProcessStep
                step="4"
                title="Service & Payment"
                description="Receive professional assistance and complete secure payment through our platform."
              />
            </div>

            <div className="bg-gray-800 rounded-xl p-8 text-white self-start sticky top-8">
              <h3 className="text-2xl font-bold mb-8">Why Choose RescueApp?</h3>
              <div className="space-y-6">
                <div className="flex items-start space-x-4">
                  <Clock className="w-8 h-8 text-yellow-500 flex-shrink-0" />
                  <div>
                    <h4 className="font-semibold mb-2">15-Minute Response</h4>
                    <p className="text-gray-200">Fastest incident response service in Kenya</p>
                  </div>
                </div>
                <div className="flex items-start space-x-4">
                  <Shield className="w-8 h-8 text-yellow-500 flex-shrink-0" />
                  <div>
                    <h4 className="font-semibold mb-2">Verified Providers</h4>
                    <p className="text-gray-200">All service providers are vetted and certified</p>
                  </div>
                </div>
                <div className="flex items-start space-x-4">
                  <Phone className="w-8 h-8 text-yellow-500 flex-shrink-0" />
                  <div>
                    <h4 className="font-semibold mb-2">24/7 Support</h4>
                    <p className="text-gray-200">Round-the-clock assistance via multiple channels</p>
                  </div>
                </div>
              </div>
              <Link to={'/signup'}>
              <button className="w-full mt-8 bg-white/10 text-gray-100 py-3 px-6 rounded-lg font-semibold hover:bg-gray-600 transition-colors flex items-center justify-center space-x-2">
                <span>Get Started Now</span>
                <ArrowRight className="w-5 h-5" />
              </button>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </section>
    </>
  );
}
export default Services;