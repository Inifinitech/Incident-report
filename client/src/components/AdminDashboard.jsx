// import React, { useEffect, useState } from 'react';
// import { Link } from 'react-router-dom';
// import { 
//   Users, 
//   AlertTriangle, 
//   BarChart2, 
//   CheckCircle,
//   XCircle,
//   Activity
// } from 'lucide-react';

// export default function AdminOverview() {
//   const [users, setUsers] = useState([]);
//   const [incidents, setIncidents] = useState([]);
  
//   const fetchUsers = async () => {
//     try {
//       const response = await fetch('http://127.0.0.1:5555/users');
//       if (!response.ok) throw new Error('Failed to fetch users');
//       const data = await response.json();
//       setUsers(data);
//     } catch (error) {
//       console.error('Error fetching users:', error);
//     }
//   };

//   const fetchIncidents = async () => {
//     try {
//       const response = await fetch('http://127.0.0.1:5555/incidents');
//       if (!response.ok) throw new Error('Failed to fetch incidents');
//       const data = await response.json();
//       setIncidents(data);
//     } catch (error) {
//       console.error('Error fetching incidents:', error);
//     }
//   };

//   useEffect(() => {
//     fetchUsers();
//     // fetchIncidents();
//   }, []);

//   useEffect(() => {
//     fetchIncidents()
//   }, [])

//   const stats = [
//     { label: 'Total Users', value: users.length, icon: <Users />, color: 'bg-blue-500' },
//     { label: 'Total Incidents', value: incidents.length, icon: <AlertTriangle />, color: 'bg-yellow-500' },
//     { label: 'Resolved', value: incidents.filter(i => i.status === 'resolved').length, icon: <CheckCircle />, color: 'bg-green-500' },
//     { label: 'Investigating', value: incidents.filter(i => i.status === 'under investigation').length, icon: <Activity />, color: 'bg-purple-500' },
//     { label: 'Rejected', value: incidents.filter(i => i.status === 'rejected').length, icon: <XCircle />, color: 'bg-red-500' },
//   ];

//   return (
//     <div className="space-y-6 text-white">
//       <div className="flex items-center justify-between">
//         <h1 className="text-2xl font-bold">Admin Dashboard</h1>
//         <Link
//           to="/admin/incidents"
//           className="px-4 py-6 bg-yellow-500 text-gray-900 rounded-lg hover:bg-yellow-600 transition-colors"
//         >
//           View All Incidents
//         </Link>
//       </div>

//       <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
//         {stats.map((stat) => (
//           <div key={stat.label} className="bg-gray-800 p-6 rounded-lg">
//             <div className="flex items-center gap-4">
//               <div className={`p-3 rounded-lg ${stat.color}`}>
//                 {stat.icon}
//               </div>
//               <div>
//                 <p className="text-gray-400">{stat.label}</p>
//                 <p className="text-2xl font-bold">{stat.value}</p>
//               </div>
//             </div>
//           </div>
//         ))}
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
//         <div className="bg-gray-800 p-6 rounded-lg">
//           <div className="flex items-center justify-between mb-6">
//             <h2 className="text-xl font-bold">Recent Incidents</h2>
//             <BarChart2 className="w-6 h-6 text-gray-400" />
//           </div>
//           <div className="space-y-4">
//             {incidents.slice(0, 3).map((incident) => (
//               <div key={incident.id} className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
//                 <span>{incident.description}</span>
//                 <span className="px-3 py-1 bg-yellow-500 text-gray-900 rounded-full text-sm">
//                   {incident.status}
//                 </span>
//               </div>
//             ))}
//           </div>
//         </div>

//         <div className="bg-gray-800 p-6 rounded-lg">
//           <div className="flex items-center justify-between mb-6">
//             <h2 className="text-xl font-bold">Active Users</h2>
//             <Users className="w-6 h-6 text-gray-400" />
//           </div>
//           <div className="space-y-4">
//             {users.slice(0, 3).map((user, index) => (
//               <div key={user.id} className="flex items-center gap-4 p-4 bg-gray-700 rounded-lg">
//                 <img
//                   src={`https://randomuser.me/api/portraits/${index % 2 === 0 ? 'men' : 'women'}/${index}.jpg`}
//                   alt={user.username}
//                   className="w-10 h-10 rounded-full"
//                 />
//                 <div>
//                   <p className="font-medium">{user.username}</p>
//                   <p className="text-sm text-gray-400">{user.email}</p>
//                 </div>
//               </div>
//             ))}
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// }
