// document.addEventListener('DOMContentLoaded', async () => {
//     const issueTableBody = document.getElementById('issue-data-table');
//     const issueTrackingMessage = document.getElementById('issue-tracking-message');
//     const issueCountSpan = document.getElementById('issue-count');
//     const statusFilter = document.getElementById('status-filter');
//     const adminLogoutButton = document.getElementById('admin-logout-button');

//     // Modal elements
//     const issueDetailModal = document.getElementById('issue-detail-modal');
//     const closeModalButton = issueDetailModal.querySelector('.close-button');
//     const issueUpdateForm = document.getElementById('issue-update-form');
//     let currentIssueId = null; // To store the ID of the issue being edited

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

//     async function fetchIssues() {
//         issueTrackingMessage.textContent = 'Loading issues...';
//         issueTableBody.innerHTML = '<tr><td colspan="9" class="empty-state">Loading issues...</td></tr>';
        
//         try {
//             const response = await fetch('/admin/api/issues', {
//                 headers: {
//                     'Authorization': `Bearer ${adminToken}`
//                 }
//             });
//             const issuesData = await response.json();

//             if (!response.ok) {
//                 if (response.status === 403) {
//                     issueTrackingMessage.textContent = 'Session expired. Please log in again.';
//                     setTimeout(() => window.location.href = '/admin/admin_login.html', 2000);
//                 } else {
//                     issueTrackingMessage.textContent = issuesData.message || 'Failed to load issues.';
//                 }
//                 issueTableBody.innerHTML = '<tr><td colspan="9" class="empty-state">Error loading issues.</td></tr>';
//                 return;
//             }

//             issueCountSpan.textContent = issuesData.length;
//             issueTableBody.innerHTML = ''; // Clear loading message

//             const filterStatus = statusFilter.value;
//             const filteredIssues = filterStatus ? issuesData.filter(issue => issue.status === filterStatus) : issuesData;

//             if (filteredIssues.length === 0) {
//                 issueTableBody.innerHTML = '<tr><td colspan="9" class="empty-state">No issues found for this filter.</td></tr>';
//                 issueTrackingMessage.textContent = '';
//                 return;
//             }

//             filteredIssues.forEach(issue => {
//                 const row = issueTableBody.insertRow();
//                 row.insertCell().textContent = issue._id.substring(0, 8) + '...'; // Shorten ID for display
//                 row.insertCell().textContent = issue.username;
//                 row.insertCell().textContent = issue.serial_number || 'N/A';
//                 row.insertCell().textContent = issue.subject;
//                 row.insertCell().textContent = issue.description.substring(0, 50) + (issue.description.length > 50 ? '...' : ''); // Truncate
//                 row.insertCell().textContent = issue.status;
//                 row.insertCell().textContent = new Date(issue.reported_at).toLocaleString();
//                 row.insertCell().textContent = issue.admin_notes || 'N/A';

//                 const actionsCell = row.insertCell();
//                 const viewButton = document.createElement('button');
//                 viewButton.textContent = 'View/Edit';
//                 viewButton.classList.add('btn', 'btn-secondary', 'btn-sm');
//                 viewButton.onclick = () => openIssueModal(issue);
//                 actionsCell.appendChild(viewButton);
//             });
//             issueTrackingMessage.textContent = ''; // Clear message on success

//         } catch (error) {
//             console.error('Error fetching issues:', error);
//             issueTrackingMessage.textContent = 'An error occurred while fetching issue data.';
//             issueTrackingMessage.classList.add('error');
//             issueTableBody.innerHTML = '<tr><td colspan="9" class="empty-state">Failed to load data.</td></tr>';
//         }
//     }

//     function openIssueModal(issue) {
//         currentIssueId = issue._id;
//         document.getElementById('modal-issue-id').textContent = issue._id.substring(0, 8);
//         document.getElementById('modal-reported-by').textContent = issue.username;
//         document.getElementById('modal-serial-no').textContent = issue.serial_number || 'N/A';
//         document.getElementById('modal-subject').textContent = issue.subject;
//         document.getElementById('modal-description').textContent = issue.description;
//         document.getElementById('modal-status').value = issue.status;
//         document.getElementById('modal-admin-notes').value = issue.admin_notes || '';
//         issueDetailModal.style.display = 'block';
//     }

//     closeModalButton.addEventListener('click', () => {
//         issueDetailModal.style.display = 'none';
//     });

//     window.addEventListener('click', (event) => {
//         if (event.target == issueDetailModal) {
//             issueDetailModal.style.display = 'none';
//         }
//     });

//     issueUpdateForm.addEventListener('submit', async (e) => {
//         e.preventDefault();
//         const status = document.getElementById('modal-status').value;
//         const admin_notes = document.getElementById('modal-admin-notes').value;

//         try {
//             const response = await fetch(`/admin/api/issues/${currentIssueId}`, {
//                 method: 'PUT',
//                 headers: {
//                     'Content-Type': 'application/json',
//                     'Authorization': `Bearer ${adminToken}`
//                 },
//                 body: JSON.stringify({ status, admin_notes })
//             });

//             const data = await response.json();
//             if (response.ok) {
//                 alert('Issue updated successfully!');
//                 issueDetailModal.style.display = 'none';
//                 fetchIssues(); // Refresh the list
//             } else {
//                 alert('Error updating issue: ' + (data.message || 'Unknown error'));
//             }
//         } catch (error) {
//             console.error('Error updating issue:', error);
//             alert('An error occurred while updating the issue.');
//         }
//     });

//     statusFilter.addEventListener('change', fetchIssues);

//     fetchIssues();
// });