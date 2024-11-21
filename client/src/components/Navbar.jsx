import { useState, useEffect } from 'react';
import { Menu, X, AlertTriangle } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

export default function Navbar() {
  const [isOpen, setIsOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const location = useLocation();

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (sectionId) => {
    setIsOpen(false);
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const isHome = location.pathname === '/';

  return (
    <nav
      className={`fixed w-full top-0 z-50 transition-all duration-300 ${
        isScrolled ? 'bg-white/80 backdrop-blur-lg shadow-sm' : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <Link to={'/'}>
          <div className="flex items-center">
            <AlertTriangle
              className={`h-8 w-8 ${isScrolled ? 'text-yellow-500' : 'text-white'}`}
            />
            <span
              className={`ml-2 text-xl font-bold ${
                isScrolled ? 'text-gray-900' : 'text-white'
              }`}
            >
              RescueApp!
            </span>
          </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            <Link to="/">
              <button
                onClick={() => scrollToSection('home')}
                className={`${
                  isScrolled
                    ? 'text-gray-700 hover:text-[#5D4E8C]'
                    : 'text-white hover:text-teal-400'
                } transition-colors`}
              >
                Home
              </button>
            </Link>
            <Link to="/services">
              <button
                className={`${
                  isScrolled
                    ? 'text-gray-700 hover:text-[#5D4E8C]'
                    : 'text-white hover:text-teal-400'
                } transition-colors`}
              >
                Services
              </button>
            </Link>
            <Link to="/about">
              <button
                className={`${
                  isScrolled
                    ? 'text-gray-700 hover:text-[#5D4E8C]'
                    : 'text-white hover:text-teal-400'
                } transition-colors`}
              >
                About
              </button>
            </Link>
            <Link to="/contact">
              <button
                className={`${
                  isScrolled
                    ? 'text-gray-700 hover:text-[#5D4E8C]'
                    : 'text-white hover:text-teal-400'
                } transition-colors`}
              >
                Contact Us
              </button>
            </Link>
            {!isHome && (
              <Link to="/login">
                <button className="bg-yellow-500 text-black px-4 py-2 rounded-md hover:bg-gray-900 transition-colors">
                  Get Access
                </button>
              </Link>
            )}
          </div>


          <div className="md:hidden">
            <button
              onClick={() => setIsOpen(!isOpen)}
              className={`${isScrolled ? 'text-gray-700' : 'text-white'} p-2`}
            >
              {isOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        <div
          className={`md:hidden transition-all duration-300 ease-in-out ${
            isOpen ? 'block' : 'hidden'
          }`}
        >
          <div className="py-4 space-y-4">
            <Link to="/" onClick={() => setIsOpen(false)}>
              <span className="block w-full text-left px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-md">
                Home
              </span>
            </Link>
            <Link to="/services" onClick={() => setIsOpen(false)}>
              <span className="block w-full text-left px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-md">
                Services
              </span>
            </Link>
            <Link to="/about" onClick={() => setIsOpen(false)}>
              <span className="block w-full text-left px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-md">
                About
              </span>
            </Link>
            <Link to="/contact" onClick={() => setIsOpen(false)}>
              <span className="block w-full text-left px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-md">
                Contact Us
              </span>
            </Link>
            {!isHome && (
              <Link to="/login" onClick={() => setIsOpen(false)}>
                <span className="block w-32 px-4 py-2 bg-yellow-500 text-white rounded-md hover:bg-[#4A3D70] transition-colors">
                  Get Access
                </span>
              </Link>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}
