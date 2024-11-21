// import { useEffect, useState } from 'react';
// import { Bell, Share2, MessageSquare, BookmarkPlus, Clock, Eye, Filter } from 'lucide-react';

// const NewsUpdates = () => {
//   const [news, setNews] = useState([]);
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     const fetchNews = async () => {
//       try {
//         const response = await fetch(
//           `https://newsdata.io/api/1/news?apikey=pub_598959ac526e7cc1502500f3c44b17111d63b&q=emergencies `
//         );
//         const data = await response.json();
//         const formattedNews = data.results.map((article, index) => ({
//           id: index,
//           title: article.title,
//           content: article.description,
//           date: new Date(article.pubDate).toLocaleDateString(),
//           image: article.image_url || "https://via.placeholder.com/300",
//           category: article.category ? article.category[0] : "General",
//           readTime: "5 min",
//           views: Math.floor(Math.random() * 1000),
//           comments: Math.floor(Math.random() * 50),
//           shares: Math.floor(Math.random() * 30),
//           priority: "medium",
//         }));
//         setNews(formattedNews);
//       } catch (error) {
//         console.error("Error fetching news:", error);
//       } finally {
//         setLoading(false);
//       }
//     };

//     fetchNews();
//   }, []);

//   return (
//     <div className="p-6 max-w-6xl mx-auto">
//       <div className="flex items-center justify-between mb-8">
//         <div className="flex items-center gap-3">
//           <Bell className="w-8 h-8 text-yellow-500" />
//           <h1 className="text-3xl font-bold text-white">News & Updates</h1>
//         </div>
//         <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 rounded-lg text-gray-300 hover:bg-gray-600 transition-colors">
//           <Filter className="w-4 h-4" />
//           <span>Filter</span>
//         </button>
//       </div>

//       {loading ? (
//         <p className="text-center text-gray-300">Loading news updates...</p>
//       ) : (
//         <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
//           {news.map((item) => (
//             <div
//               key={item.id}
//               className="bg-gray-800 rounded-xl overflow-hidden text-white shadow-xl transform hover:scale-[1.02] transition-transform duration-300"
//             >
//               <div className="relative">
//                 <img
//                   src={item.image}
//                   alt={item.title}
//                   className="w-full h-56 object-cover"
//                 />
//                 <div className="absolute top-4 left-4">
//                   <span className={`px-3 py-1 rounded-full text-xs font-semibold
//                     ${item.priority === 'high' ? 'bg-red-500' : 'bg-blue-500'}`}>
//                     {item.category}
//                   </span>
//                 </div>
//               </div>

//               <div className="p-6">
//                 <div className="flex items-center gap-3 text-sm text-gray-400 mb-3">
//                   <div className="flex items-center gap-1">
//                     <Clock className="w-4 h-4" />
//                     <span>{item.readTime}</span>
//                   </div>
//                   <div className="flex items-center gap-1">
//                     <Eye className="w-4 h-4" />
//                     <span>{item.views.toLocaleString()}</span>
//                   </div>
//                 </div>

//                 <h2 className="text-xl font-bold mb-3 line-clamp-2">{item.title}</h2>
//                 <p className="text-gray-400 mb-4 line-clamp-3">{item.content}</p>

//                 <div className="flex items-center justify-between text-sm border-t border-gray-700 pt-4">
//                   <span className="text-gray-500">{item.date}</span>
//                   <div className="flex gap-4">
//                     <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
//                       <MessageSquare className="w-4 h-4" />
//                       <span>{item.comments}</span>
//                     </button>
//                     <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
//                       <Share2 className="w-4 h-4" />
//                       <span>{item.shares}</span>
//                     </button>
//                     <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
//                       <BookmarkPlus className="w-4 h-4" />
//                     </button>
//                   </div>
//                 </div>
//               </div>
//             </div>
//           ))}
//         </div>
//       )}
//     </div>
//   );
// };

// export default NewsUpdates;

import { useEffect, useState } from 'react';
import { Bell, Share2, MessageSquare, BookmarkPlus, Clock, Eye, Filter } from 'lucide-react';

const NewsUpdates = () => {
  const [news, setNews] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchNews = async () => {
      try {
        const response = await fetch(
          "https://newsapi.org/v2/everything?q=incident OR emergency OR safety&sortBy=publishedAt&apiKey=9f1e962146a842f18fd3bf07762f235e"
        );
        const data = await response.json();

        const formattedNews = data.articles.map((article, index) => ({
          id: index,
          title: article.title,
          content: article.description,
          date: new Date(article.publishedAt).toLocaleDateString(),
          image: article.urlToImage || "https://via.placeholder.com/300", // Fallback for missing images
          category: "Incident",
          readTime: "5 min",
          views: Math.floor(Math.random() * 1000),
          comments: Math.floor(Math.random() * 50),
          shares: Math.floor(Math.random() * 30),
          priority: "medium",
        }));

        setNews(formattedNews);
      } catch (error) {
        console.error("Error fetching news:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchNews();
  }, []);

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <Bell className="w-8 h-8 text-yellow-500" />
          <h1 className="text-3xl font-bold text-white">News & Updates</h1>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 rounded-lg text-gray-300 hover:bg-gray-600 transition-colors">
          <Filter className="w-4 h-4" />
          <span>Filter</span>
        </button>
      </div>

      {loading ? (
        <p className="text-center text-gray-300">Loading news updates...</p>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {news.map((item) => (
            <div
              key={item.id}
              className="bg-gray-800 rounded-xl overflow-hidden text-white shadow-xl transform hover:scale-[1.02] transition-transform duration-300"
            >
              <div className="relative">
                <img
                  src={item.image}
                  alt={item.title}
                  className="w-full h-56 object-cover"
                />
                <div className="absolute top-4 left-4">
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-semibold ${
                      item.priority === "high" ? "bg-red-500" : "bg-blue-500"
                    }`}
                  >
                    {item.category}
                  </span>
                </div>
              </div>

              <div className="p-6">
                <div className="flex items-center gap-3 text-sm text-gray-400 mb-3">
                  <div className="flex items-center gap-1">
                    <Clock className="w-4 h-4" />
                    <span>{item.readTime}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Eye className="w-4 h-4" />
                    <span>{item.views.toLocaleString()}</span>
                  </div>
                </div>

                <h2 className="text-xl font-bold mb-3 line-clamp-2">{item.title}</h2>
                <p className="text-gray-400 mb-4 line-clamp-3">{item.content}</p>

                <div className="flex items-center justify-between text-sm border-t border-gray-700 pt-4">
                  <span className="text-gray-500">{item.date}</span>
                  <div className="flex gap-4">
                    <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
                      <MessageSquare className="w-4 h-4" />
                      <span>{item.comments}</span>
                    </button>
                    <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
                      <Share2 className="w-4 h-4" />
                      <span>{item.shares}</span>
                    </button>
                    <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors">
                      <BookmarkPlus className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default NewsUpdates;

