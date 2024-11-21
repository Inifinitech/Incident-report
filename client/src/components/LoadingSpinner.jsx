const LoadingSpinner = ({ size = 'md' }) => {
    const sizeClasses = {
      sm: 'h-8 w-8',
      md: 'h-12 w-12',
      lg: 'h-16 w-16'
    };
  
    return (
      <div className="flex items-center justify-center">
        <div className={`${sizeClasses[size]} animate-spin rounded-full border-4 border-gray-200 border-t-yellow-500`} />
      </div>
    );
  };
  
  export default LoadingSpinner;
  