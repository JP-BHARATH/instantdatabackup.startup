// document.addEventListener('DOMContentLoaded', async () => {
//     const userTableBody = document.getElementById('user-data-table');
//     const userMonitoringMessage = document.getElementById('user-monitoring-message');
//     const userCountSpan = document.getElementById('user-count');
//     const adminLogoutButton = document.getElementById('admin-logout-button');

//     // Check for admin token
//     const adminToken = localStorage.getItem('adminToken');
//     if (!adminToken) {
//         window.location.href = '/admin/admin_login.html'; // Redirect to login if no token
//         return;
//     }

//     adminLogoutButton.addEventListener('click', () => {
//         localStorage.removeItem('adminToken');
//         window.location.href = '/admin/admin_login.html';
//     });

//     async function fetchUsers() {
//         userMonitoringMessage.textContent = 'Loading users...';
//         userTableBody.innerHTML = '<tr><td colspan="6" class="empty-state">Loading users...</td></tr>';
        
//         try {
//             const usersResponse = await fetch('/admin/api/users', {
//                 headers: {
//                     'Authorization': `Bearer ${adminToken}`
//                 }
//             });
//             const usersData = await usersResponse.json();

//             if (!usersResponse.ok) {
//                 if (usersResponse.status === 403) {
//                     userMonitoringMessage.textContent = 'Session expired. Please log in again.';
//                     setTimeout(() => window.location.href = '/admin/admin_login.html', 2000);
//                 } else {
//                     userMonitoringMessage.textContent = usersData.message || 'Failed to load users.';
//                 }
//                 userTableBody.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading users.</td></tr>';
//                 return;
//             }

//             userCountSpan.textContent = usersData.length;
//             userTableBody.innerHTML = ''; // Clear loading message

//             if (usersData.length === 0) {
//                 userTableBody.innerHTML = '<tr><td colspan="6" class="empty-state">No users registered yet.</td></tr>';
//                 userMonitoringMessage.textContent = '';
//                 return;
//             }

//             for (const user of usersData) {
//                 const row = userTableBody.insertRow();
//                 row.insertCell().textContent = user.serial_number;
//                 row.insertCell().textContent = user.username;
//                 row.insertCell().textContent = user.email;
//                 row.insertCell().textContent = formatBytes(user.total_storage_used || 0);
//                 row.insertCell().textContent = user.last_login ? new Date(user.last_login).toLocaleString() : 'N/A';
                
//                 // Fetch recent activity for this user
//                 const activityCell = row.insertCell();
//                 try {
//                     const activitiesResponse = await fetch(`/admin/api/activities?serialNumber=${user.serial_number}`, {
//                         headers: {
//                             'Authorization': `Bearer ${adminToken}`
//                         }
//                     });
//                     const activitiesData = await activitiesResponse.json();
                    
//                     if (activitiesResponse.ok && activitiesData.length > 0) {
//                         const latestActivity = activitiesData[0]; // Get the most recent
//                         activityCell.textContent = `${new Date(latestActivity.timestamp).toLocaleTimeString()}: ${latestActivity.action} ${latestActivity.file_name || ''}`;
//                     } else {
//                         activityCell.textContent = 'No recent activity.';
//                     }
//                 } catch (activityError) {
//                     console.error('Error fetching activity for user:', user.username, activityError);
//                     activityCell.textContent = 'Error loading activity.';
//                 }
//             }
//             userMonitoringMessage.textContent = ''; // Clear message on success

//         } catch (error) {
//             console.error('Error fetching users:', error);
//             userMonitoringMessage.textContent = 'An error occurred while fetching user data.';
//             userMonitoringMessage.classList.add('error');
//             userTableBody.innerHTML = '<tr><td colspan="6" class="empty-state">Failed to load data.</td></tr>';
//         }
//     }

//     function formatBytes(bytes, decimals = 2) {
//         if (bytes === 0) return '0 Bytes';
//         const k = 1024;
//         const dm = decimals < 0 ? 0 : decimals;
//         const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
//         const i = Math.floor(Math.log(bytes) / Math.log(k));
//         return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
//     }

//     fetchUsers();
//     // Optional: Refresh data periodically for "real-time" feel
//     // setInterval(fetchUsers, 30000); // Refresh every 30 seconds
// });