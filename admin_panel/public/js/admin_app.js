// document.addEventListener('DOMContentLoaded', () => {
//     const adminLoginForm = document.getElementById('admin-login-form');
//     const loginMessage = document.getElementById('login-message');

//     if (adminLoginForm) {
//         adminLoginForm.addEventListener('submit', async (e) => {
//             e.preventDefault();
//             loginMessage.textContent = ''; // Clear previous messages

//             const username = document.getElementById('admin-username').value;
//             const password = document.getElementById('admin-password').value;

//             try {
//                 const response = await fetch('/admin/login', { // Admin login endpoint
//                     method: 'POST',
//                     headers: {
//                         'Content-Type': 'application/json',
//                     },
//                     body: JSON.stringify({ username, password }),
//                 });

//                 const data = await response.json();

//                 if (response.ok) {
//                     // Successful login, redirect to admin dashboard (e.g., user monitoring page)
//                     window.location.href = '/admin/user-monitoring.html';
//                 } else {
//                     loginMessage.textContent = data.message || 'Login failed. Please try again.';
//                     loginMessage.classList.add('error');
//                 }
//             } catch (error) {
//                 console.error('Error during admin login:', error);
//                 loginMessage.textContent = 'An error occurred during login. Please try again later.';
//                 loginMessage.classList.add('error');
//             }
//         });
//     }
// });