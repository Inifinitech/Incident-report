import React, { useEffect, useState } from "react";

const ContactMessages = () => {
    const [messages, setMessages] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchMessages = async () => {
            try {
                const response = await fetch("https://incident-report-98rf.onrender.com/contact");
                if (!response.ok) {
                    throw new Error("Failed to fetch messages");
                }
                const data = await response.json();
                if (Array.isArray(data)) {
                    setMessages(data);
                } else {
                    throw new Error("Invalid data format");
                }
            } catch (err) {
                console.error(err);
                setError(err instanceof Error ? err.message : String(err));
            } finally {
                setLoading(false);
            }
        };

        fetchMessages();
    }, []);

    // Handle loading state
    if (loading) {
        return (
            <div className="flex justify-center items-center">
                <p className="text-yellow-500 text-xl">Loading messages...</p>
            </div>
        );
    }

    // Handle error state
    if (error) {
        return (
            <div className="flex justify-center items-center">
                <p className="text-red-500 text-xl">Error: {error}</p>
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            <h2 className="text-3xl font-bold text-white">Contact Messages</h2>
            {messages.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 gap-6">
                    {messages.map((message) => (
                        <div
                            key={message.id}
                            className="bg-gray-800 p-6 rounded-lg shadow-md hover:shadow-lg transition-shadow duration-300"
                        >
                            <p className="text-xl font-semibold text-white">
                                <strong>Name:</strong> {message.name}
                            </p>
                            <p className="text-lg text-gray-300">
                                <strong>Email:</strong> {message.email}
                            </p>
                            <p className="text-lg text-gray-300">
                                <strong>Message:</strong> {message.message}
                            </p>
                            <p className="text-sm text-gray-500">
                                <strong>Timestamp:</strong>{" "}
                                {message.timestamp
                                    ? new Date(message.timestamp).toLocaleString()
                                    : "N/A"}
                            </p>
                        </div>
                    ))}
                </div>
            ) : (
                <p className="text-lg text-gray-400">No messages available.</p>
            )}
        </div>
    );
};

export default ContactMessages;





