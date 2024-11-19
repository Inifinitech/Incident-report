import { Mail, Phone, MapPin, Clock, User, MessageSquare } from 'lucide-react';
import Navbar from './Navbar';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import toast, { Toaster } from 'react-hot-toast';

export default function ContactPage() {
  const formik = useFormik({
    initialValues: {
      name: '',
      email: '',
      message: '',
    },
    validationSchema: Yup.object({
      name: Yup.string().required('Name is required'),
      email: Yup.string().email('Invalid email address').required('Email is required'),
      message: Yup.string().min(10, 'Message must be at least 10 characters').required('Message is required'),
    }),
    onSubmit: async (values, { resetForm }) => {
      try {
        const response = await fetch('http://127.0.0.1:5555/contact', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(values),
        });

        if (response.ok) {
          toast.success('Your message has been sent successfully!');
          resetForm();
        } else {
          throw new Error('Failed to send message.');
        }
      } catch (error) {
        toast.error(`Error: ${error.message}`);
      }
    },
  });

  return (
    <>
      <Navbar />
      <Toaster position="top-right" reverseOrder={false} />
      <div className="pt-16 min-h-screen bg-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-bold text-gray-100 mb-4">Tell us what you think!</h1>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              We're here to help. Reach out to us for any questions or concerns. Your voice matters! We would love to hear from you.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            <div className="bg-gray-900 p-8 rounded-xl shadow-lg">
              <h2 className="text-2xl font-semibold mb-6 text-gray-100">Send us a message</h2>
              <form onSubmit={formik.handleSubmit} className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-100 mb-1">Name</label>
                  <div className="relative">
                    <input
                      type="text"
                      name="name"
                      value={formik.values.name}
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      className="w-full bg-gray-800 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-yellow-500"
                      placeholder="Your name"
                      required
                    />
                    <User className="w-5 h-5 text-gray-400 absolute left-3 top-2.5" />
                  </div>
                  {formik.touched.name && formik.errors.name && (
                    <div className="text-red-500 text-sm mt-1">{formik.errors.name}</div>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-100 mb-1">Email</label>
                  <div className="relative">
                    <input
                      type="email"
                      name="email"
                      value={formik.values.email}
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      className="w-full bg-gray-800 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-yellow-500"
                      placeholder="you@example.com"
                      required
                    />
                    <Mail className="w-5 h-5 text-gray-400 absolute left-3 top-2.5" />
                  </div>
                  {formik.touched.email && formik.errors.email && (
                    <div className="text-red-500 text-sm mt-1">{formik.errors.email}</div>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-100 mb-1">Message</label>
                  <div className="relative">
                    <textarea
                      rows={5}
                      name="message"
                      value={formik.values.message}
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      className="w-full bg-gray-800 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-yellow-500"
                      placeholder="Your message"
                      required
                    ></textarea>
                    <MessageSquare className="w-5 h-5 text-gray-400 absolute left-3 top-2.5 mt-2.5" />
                  </div>
                  {formik.touched.message && formik.errors.message && (
                    <div className="text-red-500 text-sm mt-1">{formik.errors.message}</div>
                  )}
                </div>

                <button
                  type="submit"
                  className="w-full bg-white/10 text-yellow-500 font-semibold px-6 py-3 rounded-lg hover:bg-yellow-500 hover:text-white transition duration-300 shadow-sm"
                >
                  Send Message
                </button>
              </form>
            </div>

            <div className="space-y-8">
              <div className="bg-gray-900 p-8 rounded-xl shadow-lg">
                <h2 className="text-2xl font-semibold mb-6 text-gray-100">Contact Information</h2>
                <div className="space-y-4">
                  <div className="flex items-center space-x-4">
                    <Phone className="h-6 w-6 text-yellow-500" />
                    <div>
                      <p className="font-medium text-gray-100">Phone</p>
                      <p className="text-gray-400">+254 71234568 </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <Mail className="h-6 w-6 text-yellow-500" />
                    <div>
                      <p className="font-medium text-gray-100">Email</p>
                      <p className="text-gray-400">noreply@rescueapp.com</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <MapPin className="h-6 w-6 text-yellow-500" />
                    <div>
                      <p className="font-medium text-gray-100">Address</p>
                      <p className="text-gray-400">123 Kanairo, Security City, SC 12345</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <Clock className="h-6 w-6 text-yellow-500" />
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
                <div className="text-2xl font-bold text-yellow-500">999 or 112</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
