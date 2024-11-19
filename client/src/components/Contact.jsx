import React, { useState } from 'react';
import { Mail, Phone, MapPin, Clock } from 'lucide-react';

export default function ContactPage() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    message: '',
  });

  const [isSubmitted, setIsSubmitted] = useState(false);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitted(false);

    try {
      const response = await fetch('http://127.0.0.1:5555/contact', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        setIsSubmitted(true);
        setFormData({ name: '', email: '', message: '' });
        alert('Your message has been sent successfully!');
      } else {
        throw new Error('Failed to send message.');
      }
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  return (
    <>
      <div className="pt-16 min-h-screen bg-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-bold text-gray-100 mb-4">Contact Us</h1>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              We're here to help. Reach out to us for any questions or concerns.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            {/* Contact Form */}
            <div className="bg-gray-900 p-8 rounded-xl shadow-lg">
              <h2 className="text-2xl font-semibold mb-6 text-gray-100">Send us a message</h2>
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label
                    htmlFor="name"
                    className="block text-sm font-medium text-gray-100 mb-1"
                  >
                    Name
                  </label>
                  <input
                    type="text"
                    name="name"
                    id="name"
                    value={formData.name}
                    onChange={handleChange}
                    className="w-full px-4 py-3 border border-gray-700 rounded-lg shadow-sm focus:ring-red-500 focus:border-red-500 placeholder-gray-400 text-gray-100 bg-gray-800"
                    placeholder="Your name"
                    required
                  />
                </div>
                <div>
                  <label
                    htmlFor="email"
                    className="block text-sm font-medium text-gray-100 mb-1"
                  >
                    Email
                  </label>
                  <input
                    type="email"
                    name="email"
                    id="email"
                    value={formData.email}
                    onChange={handleChange}
                    className="w-full px-4 py-3 border border-gray-700 rounded-lg shadow-sm focus:ring-red-500 focus:border-red-500 placeholder-gray-400 text-gray-100 bg-gray-800"
                    placeholder="your@email.com"
                    required
                  />
                </div>
                <div>
                  <label
                    htmlFor="message"
                    className="block text-sm font-medium text-gray-100 mb-1"
                  >
                    Message
                  </label>
                  <textarea
                    rows={5}
                    name="message"
                    id="message"
                    value={formData.message}
                    onChange={handleChange}
                    className="w-full px-4 py-3 border border-gray-700 rounded-lg shadow-sm focus:ring-red-500 focus:border-red-500 placeholder-gray-400 text-gray-100 bg-gray-800"
                    placeholder="Your message"
                    required
                  ></textarea>
                </div>
                <button
                  type="submit"
                  className="w-full bg-red-500 text-white font-semibold px-6 py-3 rounded-lg hover:bg-red-600 transition duration-300 shadow-sm"
                >
                  Send Message
                </button>
              </form>
              {isSubmitted && (
                <p className="mt-4 text-green-600 font-medium">
                  Thank you! Your message has been sent.
                </p>
              )}
            </div>

            {/* Contact Information */}
            <div className="space-y-8">
              <div className="bg-gray-900 p-8 rounded-xl shadow-lg">
                <h2 className="text-2xl font-semibold mb-6 text-gray-100">Contact Information</h2>
                <div className="space-y-4">
                  <div className="flex items-center space-x-4">
                    <Phone className="h-6 w-6 text-red-500" />
                    <div>
                      <p className="font-medium text-gray-100">Phone</p>
                      <p className="text-gray-400">+1 (555) 123-4567</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <Mail className="h-6 w-6 text-red-500" />
                    <div>
                      <p className="font-medium text-gray-100">Email</p>
                      <p className="text-gray-400">support@ajali.com</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <MapPin className="h-6 w-6 text-red-500" />
                    <div>
                      <p className="font-medium text-gray-100">Address</p>
                      <p className="text-gray-400">
                        123 Safety Street, Security City, SC 12345
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <Clock className="h-6 w-6 text-red-500" />
                    <div>
                      <p className="font-medium text-gray-100">Hours</p>
                      <p className="text-gray-400">24/7 Emergency Response</p>
                      <p className="text-gray-400">Support: Mon-Fri, 9AM-6PM</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-gray-900 p-8 rounded-xl shadow-lg">
                <h2 className="text-2xl font-semibold mb-4 text-gray-100">Emergency?</h2>
                <p className="text-gray-400 mb-4">
                  For immediate emergency assistance, please call:
                </p>
                <div className="text-2xl font-bold text-red-500">999 or 112</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
