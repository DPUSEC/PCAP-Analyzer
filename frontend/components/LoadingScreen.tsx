import React from 'react';

const LoadingScreen: React.FC = () => {
  const text = "DPUSEC";

  return (
    <div className="fixed inset-0 flex flex-col items-center justify-center bg-gray-500 bg-opacity-50 z-50">
      <div className="loader"></div>
      <p className="text-5xl font-bold text-orange-500 mt-6">{text}</p>
      <style jsx>{`
        .loader {
          border: 16px solid #f3f3f3; /* Light grey */
          border-top: 16px solid #3498db; /* Blue */
          border-radius: 50%;
          width: 200px;
          height: 200px;
          animation: spin 2s linear infinite;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default LoadingScreen; 