
import React from 'react';
import { Shield, Award, Users, Clock, CheckCircle, MapPin, Phone, ArrowRight } from 'lucide-react';
import Navbar from './Navbar';

const StatCard = ({ icon: Icon, value, label }) => (
  <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 transform transition-all duration-300 hover:scale-105">
    <Icon className="h-8 w-8 mb-4 text-yellow-400" />
    <div className="text-3xl font-bold mb-1">{value}</div>
    <div className="text-gray-300">{label}</div>
  </div>
);

const ValueCard = ({ title, description }) => (
  <div className="bg-white/10 rounded-xl shadow-lg p-8 transform transition-all duration-300 hover:scale-105">
    <div className="w-12 h-12 bg-[#5D4E8C]/10 rounded-lg flex items-center justify-center mb-6">
      <CheckCircle className="h-6 w-6 text-yellow-400" />
    </div>
    <h3 className="text-xl font-bold text-yellow-500 mb-3">{title}</h3>
    <p className="text-gray-200 leading-relaxed">{description}</p>
  </div>
);

export default function AboutUs() {
  return (
    <>
    <Navbar />
    <div className="pt-30 bg-gray-900">
      <div className="bg-gray-800 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h1 className="text-4xl font-bold mb-6">Revolutionizing Emergency Response in Kenya</h1>
              <p className="text-xl text-gray-300 mb-8 leading-relaxed">
                RescueApp is transforming how Kenyans handle roadside emergencies through innovative technology and a nationwide network of trusted service providers.
              </p>
              <div className="grid grid-cols-2 gap-4 text-yellow-400">
                <StatCard icon={Clock} value="15min" label="Average Response" />
                <StatCard icon={Users} value="500+" label="Service Providers" />
                <StatCard icon={MapPin} value="47" label="Counties Covered" />
                <StatCard icon={Phone} value="24/7" label="Support Available" />
              </div>
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-t from-[#5D4E8C] to-transparent opacity-40 rounded-xl"></div>
              <img 
                src="https://images.unsplash.com/photo-1581092160562-40aa08e78837?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80"
                alt="Emergency Response Team"
                className="rounded-xl shadow-2xl"
              />
            </div>
          </div>
        </div>
      </div>

      <div className="bg-gray-900 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-white">Our Core Values</h2>
            <p className="text-xl text-gray-500">Building trust through reliable service and innovation</p>
          </div>
          <div className="grid md:grid-cols-3 gap-8">
            <ValueCard 
              title="Excellence in Service"
              description="We maintain the highest standards in emergency response through continuous training and quality assurance."
            />
            <ValueCard 
              title="Innovation First"
              description="Leveraging cutting-edge technology to provide faster, more efficient emergency assistance."
            />
            <ValueCard 
              title="Customer Safety"
              description="Your safety is our priority. All our service providers undergo rigorous vetting and regular assessments."
            />
          </div>
        </div>
      </div>

      <div className="bg-gray-800 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-3xl font-bold text-white mb-6">Our Mission</h2>
              <p className="text-gray-300 text-lg mb-8 leading-relaxed">
                To provide swift, reliable, and professional emergency response services across Kenya, ensuring peace of mind for every road user through innovative technology and a trusted network of service providers.
              </p>
              <div className="space-y-4">
                <div className="flex items-center space-x-3 text-gray-400">
                  <Award className="h-6 w-6 text-yellow-400" />
                  <span>First digital accident management platform in Kenya</span>
                </div>
                <div className="flex items-center space-x-3  text-gray-400">
                  <Users className="h-6 w-6  text-yellow-400" />
                  <span>Extensive network of vetted service providers</span>
                </div>
                <div className="flex items-center space-x-3  text-gray-400">
                  <Shield className="h-6 w-6  text-yellow-400" />
                  <span>Comprehensive insurance partnership network</span>
                </div>
              </div>
              <button className="mt-8 bg-yellow-500 text-gray-800 px-6 py-3 rounded-lg font-semibold hover:bg-yellow-100 transition-colors flex items-center space-x-2">
                <span>Join Our Network</span>
                <ArrowRight className="w-5 h-5" />
              </button>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <img 
                src="https://images.pexels.com/photos/7709296/pexels-photo-7709296.jpeg?auto=compress&cs=tinysrgb&w=600"
                alt="Team at work"
                className="rounded-xl shadow-lg w-full h-64 object-cover"
              />
              <img 
                src="https://images.unsplash.com/photo-1530043305597-f5c2ee504c3f?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80"
                alt="Emergency response"
                className="rounded-xl shadow-lg w-full h-64 object-cover mt-8"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
    </>
  );
}