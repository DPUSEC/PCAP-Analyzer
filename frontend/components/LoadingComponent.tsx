import React from 'react'

export default function LoadingComponent() {
    return (
        <div className="h-screen overflow-hidden flex justify-center items-center">
            <div className="loading-screen">
                <div className="loader-container flex flex-col items-center">
                    <div className="w-20 h-20 border-8 border-gray-300 border-t-orange-500 rounded-full 
                      animate-[spin_1.5s_linear_infinite] mb-5"></div>
                    <p className="text-orange-500 font-bold uppercase tracking-widest text-lg">DPUSEC</p>
                </div>
            </div>
        </div>
    )
}