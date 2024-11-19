import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertTriangle, LogIn, Mail, Lock, Eye, EyeOff } from 'lucide-react';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import toast from 'react-hot-toast';
import { useContext } from 'react';
import { AppContext } from '../../AppContext';

const loginValidationSchema = Yup.object({
  email: Yup.string().email('Invalid email address').required('Required'),
  password: Yup.string().min(4, 'Password must be at least 4 characters').required('Required'),
});

export default function Login() {
  const navigate = useNavigate();
  const value = useContext(AppContext)
  const [showPassword, setShowPassword] = useState(false)

  const formik = useFormik({
    initialValues: {
      email: '',
      password: '',
    },
    validationSchema: loginValidationSchema,
    onSubmit: async (values) => {
      try {
        
        const response = await fetch('http://127.0.0.1:5555/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(values),
        });
        
        if (response.ok) {
          return response.json().then(data => {
            localStorage.setItem('user_id', data.user_data.id)
            toast.success('Login successful!');
            data.role === 'user' ? navigate('/user') : navigate('/admin/d')
          })
        } else {
          const errorMessage = await response.text();
          toast.error(errorMessage || 'Login failed. Please check your credentials.');
        }
      } catch (error) {
        toast.error('Login failed. Please try again.');
      }
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 p-6">
      <div className="max-w-md w-full text-white">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-4">
            <AlertTriangle className="w-10 h-10 text-yellow-500" />
            <h1 className="text-2xl font-bold">RescueApp! Platform</h1>
          </div>
          <p className="text-gray-400">Sign in to your account to report incidents</p>
        </div>

        <form onSubmit={formik.handleSubmit} className="bg-gray-800 rounded-lg p-6 space-y-6">
          <div>
            <label className="block text-sm font-medium mb-2">Email Address</label>
            <div className="relative">
              <input
                type="email"
                name="email"
                className="w-full bg-gray-700 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-yellow-500"
                placeholder="you@example.com"
                value={formik.values.email}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                required
              />
              <Mail className="w-5 h-5 text-gray-400 absolute left-3 top-2.5" />
            </div>
            {formik.touched.email && formik.errors.email && (
              <div className="text-red-500 text-sm">{formik.errors.email}</div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Password</label>
            <div className="relative">
              <input
                type="password"
                name="password"
                className="w-full bg-gray-700 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-600 focus:outline-none focus:border-yellow-500"
                placeholder="••••••••"
                value={formik.values.password}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                required
              />
              <Lock className="w-5 h-5 text-gray-400 absolute left-3 top-2.5" />
            </div>
            {formik.touched.password && formik.errors.password && (
              <div className="text-red-500 text-sm">{formik.errors.password}</div>
            )}
          </div>

          <div className="flex items-center justify-between text-sm">
            <label className="flex items-center">
              <input type="checkbox" className="mr-2" />
              <span>Remember me</span>
            </label>
            <Link to="/forgotP" className="text-yellow-500 hover:text-yellow-400">
              Forgot password?
            </Link>
          </div>

          <button
            type="submit"
            disabled={formik.isSubmitting}
            className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-yellow-500 text-gray-900 font-medium rounded-lg hover:bg-yellow-600 transition-colors disabled:opacity-50"
          >
            {formik.isSubmitting ? (
              'Signing in...'
            ) : (
              <>
                <LogIn className="w-5 h-5" />
                Sign In
              </>
            )}
          </button>

          <p className="text-center text-sm text-gray-400">
            Don't have an account?{' '}
            <Link to="/signup" className="text-yellow-500 hover:text-yellow-400">
              Sign up
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
