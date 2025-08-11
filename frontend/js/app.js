// frontend/js/app.js

const API_BASE_URL = '/api';

// --- Global State ---
let allFiles = []; // Stores all files fetched from the server for search/filter
let currentPreviewObjectUrl = null; // Stores the URL.createObjectURL for cleanup

// --- Helper Functions ---

/**
 * Displays a message in a specified HTML element.
 * @param {string} elementId - The ID of the HTML element to display the message in.
 * @param {string} message - The message content.
 * @param {boolean} isSuccess - True for a success message (green), false for an error message (red).
 */
function displayMessage(elementId, message, isSuccess = true) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.className = isSuccess ? 'message-area success' : 'message-area error';
        element.style.display = 'block';
        // Optional: Hide message after a few seconds
        setTimeout(() => {
            element.style.display = 'none';
            element.textContent = '';
        }, 5000);
    }
}

/**
 * Clears any message displayed in a specified HTML element.
 * @param {string} elementId - The ID of the HTML element to clear.
 */
function clearMessage(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = '';
        element.className = 'message-area'; // Reset class
        element.style.display = 'none';
    }
}

/**
 * Logs out the user by clearing the authentication token and redirecting to the login page.
 */
function logoutUser() {
    localStorage.removeItem('authToken'); // Clear token
    localStorage.removeItem('username'); // Clear username
    window.location.href = 'login.html'; // Redirect to login page
}

/**
 * Checks authentication status and redirects the user if they are on an inappropriate page
 * (e.g., logged in user on login page, or logged out user on dashboard).
 */
function checkAuthAndRedirect() {
    const authToken = localStorage.getItem('authToken');
    const currentPage = window.location.pathname.split('/').pop();

    // Pages that do NOT require authentication
    const publicPages = ['index.html', '', 'login.html', 'register.html', 'forgot-password.html'];
    // Reset password page has a specific URL structure, handle it separately
    const isResetPasswordPage = window.location.pathname.includes('resetpassword/');

    if (authToken) {
        // If logged in and on a public page (or reset password page which is for unauthenticated users), redirect to dashboard
        if (publicPages.includes(currentPage) || isResetPasswordPage) {
            window.location.href = 'dashboard.html';
            return; // Crucial: stop further execution
        }
        // If on a protected page and logged in, continue
    } else {
        // If NOT logged in, and on a protected page, redirect to login
        const protectedPages = ['dashboard.html', 'upload.html', 'profile.html', 'settings.html', 'report-issue.html', 'user-activity.html'];
        if (protectedPages.includes(currentPage)) {
            window.location.href = 'login.html';
            return; // Crucial: stop further execution
        }
    }
    // If none of the above, proceed normally (e.g., public user on public page)
}

/**
 * Makes an authenticated API request by adding the auth token to headers.
 * Handles 401/403 responses by logging out the user.
 * @param {string} url - The API endpoint URL.
 * @param {Object} options - Fetch API options.
 * @returns {Promise<Response|null>} - The fetch response or null if authentication fails.
 */
async function makeAuthenticatedRequest(url, options = {}) {
    const authToken = localStorage.getItem('authToken');
    if (!authToken) {
        // Only display message if not already on the login page or about to redirect
        if (!window.location.pathname.endsWith('login.html') && !window.location.pathname.includes('resetpassword/')) {
            displayMessage('auth-message', 'Error: Not logged in. Please log in.', false);
        }
        logoutUser(); // Redirect to login
        return null;
    }

    // Use 'Authorization' header with 'Bearer' token for consistency with server-side JWT best practices
    const headers = {
        'Authorization': `Bearer ${authToken}`, // Changed from 'x-auth-token'
        ...options.headers, // Merge other headers if provided
    };

    try {
        const response = await fetch(url, { ...options, headers });
        if (response.status === 401 || response.status === 403) {
            const errorData = await response.json().catch(() => ({ message: 'Session expired or unauthorized.' }));
            displayMessage('auth-message', errorData.message || 'Session expired or unauthorized. Please log in again.', false);
            logoutUser();
            return null;
        }
        return response;
    } catch (error) {
        console.error('Network or request error:', error);
        // Determine the appropriate message area for the current page
        const messageAreaId =
            document.getElementById('auth-message') ? 'auth-message' :
            document.getElementById('list-message') ? 'list-message' :
            document.getElementById('upload-message') ? 'upload-message' :
            null;

        if (messageAreaId) {
            displayMessage(messageAreaId, `Network error: ${error.message}. Please check your internet connection.`, false);
        }
        return null;
    }
}

/**
 * Renders the list of files in the dashboard table.
 * @param {Array<Object>} filesToDisplay - An array of file objects to display.
 */
function renderFiles(filesToDisplay) {
    const filesList = document.getElementById('files-list');
    if (!filesList) return;

    filesList.innerHTML = ''; // Clear previous list

    if (filesToDisplay && filesToDisplay.length > 0) {
        filesToDisplay.forEach(file => {
            const listItem = document.createElement('tr');
            // Determine file icon based on type for better UX
            let iconClass = 'fas fa-file';
            const fileExtension = file.originalName.split('.').pop().toLowerCase();
            const mimeTypeCategory = file.mimeType ? file.mimeType.split('/')[0] : '';

            if (mimeTypeCategory === 'image') {
                iconClass = 'fas fa-file-image';
            } else if (mimeTypeCategory === 'video') {
                iconClass = 'fas fa-file-video';
            } else if (mimeTypeCategory === 'audio') {
                iconClass = 'fas fa-file-audio';
            } else if (fileExtension === 'pdf') {
                iconClass = 'fas fa-file-pdf';
            } else if (['doc', 'docx'].includes(fileExtension)) {
                iconClass = 'fas fa-file-word';
            } else if (['xls', 'xlsx'].includes(fileExtension)) {
                iconClass = 'fas fa-file-excel';
            } else if (['ppt', 'pptx'].includes(fileExtension)) {
                iconClass = 'fas fa-file-powerpoint';
            } else if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(fileExtension)) { // Added bz2
                iconClass = 'fas fa-file-archive';
            } else if (['txt', 'log', 'csv', 'js', 'html', 'css', 'json', 'xml', 'md'].includes(fileExtension) || mimeTypeCategory === 'text') { // Added md, check mimeTypeCategory for generic text
                iconClass = 'fas fa-file-alt'; // Generic text file or code
            }

            listItem.innerHTML = `
                <td><i class="${iconClass}" style="margin-right: 8px;"></i>${file.originalName}</td>
                <td>${(file.fileSize / (1024 * 1024)).toFixed(2)} MB</td>
                <td>${new Date(file.uploadDate).toLocaleString()}</td>
                <td class="actions-cell">
                    <button class="btn btn-info preview-button"
                            data-encrypted-filename="${file.encryptedFileName}"
                            data-original-name="${file.originalName}"
                            data-mime-type="${file.mimeType || ''}"><i class="fas fa-eye"></i> Preview</button>
                    <button class="btn btn-primary download-button"
                            data-encrypted-filename="${file.encryptedFileName}"
                            data-original-name="${file.originalName}"><i class="fas fa-download"></i> Restore</button>
                    <button class="btn btn-danger delete-button"
                            data-encrypted-filename="${file.encryptedFileName}"
                            data-original-name="${file.originalName}"><i class="fas fa-trash-alt"></i> Delete</button>
                </td>
            `;
            filesList.appendChild(listItem);
        });
    } else {
        filesList.innerHTML = '<tr><td colspan="4" class="empty-state">No files found matching your criteria.</td></tr>';
    }
}

// --- Search & Filter Logic ---
/**
 * Applies search and filter criteria to the global `allFiles` array and re-renders the file list.
 */
function applySearchAndFilters() {
    const searchInput = document.getElementById('search-input');
    const fileTypeFilter = document.getElementById('file-type-filter');
    const fileSizeFilter = document.getElementById('file-size-filter');
    const startDateFilter = document.getElementById('start-date-filter');
    const endDateFilter = document.getElementById('end-date-filter');

    let filteredFiles = [...allFiles]; // Start with a copy of all files

    const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const selectedFileType = fileTypeFilter ? fileTypeFilter.value : '';
    const selectedFileSize = fileSizeFilter ? fileSizeFilter.value : '';
    const startDate = startDateFilter && startDateFilter.value ? new Date(startDateFilter.value) : null;
    const endDate = endDateFilter && endDateFilter.value ? new Date(endDateFilter.value) : null;

    // Apply Search
    if (searchTerm) {
        filteredFiles = filteredFiles.filter(file =>
            file.originalName.toLowerCase().includes(searchTerm) ||
            (file.mimeType && file.mimeType.toLowerCase().includes(searchTerm))
        );
    }

    // Apply File Type Filter
    if (selectedFileType) {
        filteredFiles = filteredFiles.filter(file => {
            const mimeTypeCategory = file.mimeType ? file.mimeType.split('/')[0] : '';
            const fileExtension = file.originalName.split('.').pop().toLowerCase();
            const mimeType = file.mimeType;

            switch (selectedFileType) {
                case 'image': return mimeTypeCategory === 'image';
                case 'video': return mimeTypeCategory === 'video';
                case 'audio': return mimeTypeCategory === 'audio';
                case 'document':
                    return ['pdf', 'txt', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv'].includes(fileExtension) ||
                           (mimeType && (
                               mimeType.includes('pdf') ||
                               mimeType.includes('msword') ||
                               mimeType.includes('officedocument.wordprocessingml') ||
                               mimeType.includes('ms-excel') ||
                               mimeType.includes('officedocument.spreadsheetml') ||
                               mimeType.includes('ms-powerpoint') ||
                               mimeType.includes('officedocument.presentationml') ||
                               mimeType.includes('text/csv') ||
                               mimeType.startsWith('text/')
                           ));
                case 'archive':
                    return ['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(fileExtension) ||
                           (mimeType && (
                               mimeType.includes('zip') ||
                               mimeType.includes('x-rar-compressed') ||
                               mimeType.includes('gzip') ||
                               mimeType.includes('x-tar') ||
                               mimeType.includes('x-bzip2')
                           ));
                case 'other':
                    // Check if it falls into any of the above categories. If not, it's 'other'.
                    return !(['image', 'video', 'audio'].includes(mimeTypeCategory)) &&
                           !(
                               (['pdf', 'txt', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(fileExtension)) ||
                               (mimeType && (
                                   mimeType.includes('pdf') || mimeType.includes('msword') || mimeType.includes('officedocument.wordprocessingml') ||
                                   mimeType.includes('ms-excel') || mimeType.includes('officedocument.spreadsheetml') ||
                                   mimeType.includes('ms-powerpoint') || mimeType.includes('officedocument.presentationml') ||
                                   mimeType.includes('text/csv') || mimeType.startsWith('text/') ||
                                   mimeType.includes('zip') || mimeType.includes('x-rar-compressed') ||
                                   mimeType.includes('gzip') || mimeType.includes('x-tar') || mimeType.includes('x-bzip2')
                               ))
                           );
                default: return true; // 'All Types' selected
            }
        });
    }

    // Apply File Size Filter
    if (selectedFileSize) {
        filteredFiles = filteredFiles.filter(file => {
            const sizeMB = file.fileSize / (1024 * 1024);
            switch (selectedFileSize) {
                case 'small': return sizeMB < 1;
                case 'medium': return sizeMB >= 1 && sizeMB < 10;
                case 'large': return sizeMB >= 10;
                default: return true; // 'All Sizes' selected
            }
        });
    }

    // Apply Date Range Filter
    if (startDate || endDate) {
        filteredFiles = filteredFiles.filter(file => {
            const uploadDate = new Date(file.uploadDate);
            let passesDateFilter = true;

            if (startDate && uploadDate < startDate) {
                passesDateFilter = false;
            }
            // For end date, include the entire day. So, check if uploadDate is before the start of the next day.
            if (endDate) {
                const endOfDay = new Date(endDate);
                endOfDay.setDate(endOfDay.getDate() + 1); // Move to the beginning of the next day
                if (uploadDate >= endOfDay) {
                    passesDateFilter = false;
                }
            }
            return passesDateFilter;
        });
    }

    renderFiles(filteredFiles);
}

// --- File Preview Logic ---
// Ensure these elements exist on dashboard.html for this to work
const previewModal = document.getElementById('file-preview-modal');
const previewFilenameDisplay = document.getElementById('preview-filename');
const previewArea = document.getElementById('preview-area');
const closeButton = document.querySelector('#file-preview-modal .close-button');
const downloadFromPreviewButton = document.getElementById('download-from-preview');

// Only add event listeners if the elements exist (i.e., on dashboard.html)
if (previewModal) { // Check if we are on a page where preview modal elements exist
    function hideFilePreview() {
        previewModal.style.display = 'none';
        previewArea.innerHTML = ''; // Clear content
        if (currentPreviewObjectUrl) {
            URL.revokeObjectURL(currentPreviewObjectUrl); // Clean up temporary URL
            currentPreviewObjectUrl = null;
        }
        document.body.style.overflow = ''; // Re-enable body scrolling
    }

    async function showFilePreview(file) {
        document.body.style.overflow = 'hidden'; // Disable body scrolling

        clearMessage('list-message');
        previewFilenameDisplay.textContent = file.originalName;
        previewArea.innerHTML = '<p class="loading-spinner"><i class="fas fa-spinner fa-spin"></i> Loading preview...</p>'; // Show loading message

        // Set up download button within preview modal
        downloadFromPreviewButton.onclick = () => downloadFile(file.encryptedFileName, file.originalName);

        try {
            const response = await makeAuthenticatedRequest(`${API_BASE_URL}/restore/${file.encryptedFileName}`);
            if (!response) {
                previewArea.innerHTML = '<p class="message-area error">Failed to load preview: Authentication issue.</p>';
                previewModal.style.display = 'flex'; // Show modal even with error
                return;
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
                previewArea.innerHTML = `<p class="message-area error">Failed to load preview: ${errorData.message || 'Server error'}.</p>`;
                previewModal.style.display = 'flex'; // Show modal even with error
                return;
            }

            const blob = await response.blob();
            const url = URL.createObjectURL(blob); // Create a temporary URL for the blob
            currentPreviewObjectUrl = url; // Store for cleanup

            previewArea.innerHTML = ''; // Clear loading message

            // Prefer the mimeType from the file object, fallback to blob.type if needed
            const mimeType = file.mimeType || blob.type;
            const mimeTypeCategory = mimeType.split('/')[0];
            const fileExtension = file.originalName.split('.').pop().toLowerCase();

            if (mimeTypeCategory === 'image') {
                const img = document.createElement('img');
                img.src = url;
                img.alt = file.originalName;
                img.style.maxWidth = '100%'; // Ensure image fits
                img.style.maxHeight = 'calc(80vh - 150px)'; // Adjust max height
                img.style.objectFit = 'contain';
                previewArea.appendChild(img);
            } else if (mimeTypeCategory === 'video') {
                const video = document.createElement('video');
                video.src = url;
                video.controls = true;
                video.autoplay = false;
                video.style.maxWidth = '100%';
                video.style.maxHeight = 'calc(80vh - 150px)';
                previewArea.appendChild(video);
            } else if (mimeTypeCategory === 'audio') {
                const audio = document.createElement('audio');
                audio.src = url;
                audio.controls = true;
                audio.autoplay = false;
                audio.style.width = '100%';
                previewArea.appendChild(audio);
            } else if (fileExtension === 'pdf' || mimeType === 'application/pdf') {
                const iframe = document.createElement('iframe');
                iframe.src = url;
                iframe.style.width = '100%';
                iframe.style.height = 'calc(80vh - 100px)'; // Adjust height for iframe
                iframe.frameBorder = '0';
                previewArea.appendChild(iframe);
            } else if (mimeType.startsWith('text/') || ['txt', 'log', 'csv', 'js', 'html', 'css', 'json', 'xml', 'md'].includes(fileExtension)) { // Added json, xml, md
                const textContent = await blob.text();
                const pre = document.createElement('pre');
                pre.textContent = textContent;
                pre.style.whiteSpace = 'pre-wrap'; // Allows long lines to wrap
                pre.style.wordBreak = 'break-word'; // Breaks words if necessary
                pre.style.maxHeight = 'calc(80vh - 100px)'; // Max height for scrollable content
                pre.style.overflowY = 'auto'; // Enable vertical scrolling
                previewArea.appendChild(pre);
            } else {
                previewArea.innerHTML = `<p class="message-area info">No direct preview available for this file type (<b>${mimeType || 'unknown'}</b>). Please download to view.</p>`;
            }

            previewModal.style.display = 'flex'; // Show modal (using flex for centering)
        } catch (error) {
            console.error('Error showing preview:', error);
            previewArea.innerHTML = `<p class="message-area error">Error loading preview: ${error.message}</p>`;
            previewModal.style.display = 'flex'; // Still show modal with error
        }
    }

    // Event listener for closing modal
    if (closeButton) {
        closeButton.addEventListener('click', hideFilePreview);
    }

    // Close modal when clicking outside
    if (previewModal) {
        window.addEventListener('click', (event) => {
            if (event.target === previewModal) {
                hideFilePreview();
            }
        });
    }
}


// --- Page-Specific Logic ---

// Logic for Login Page (login.html)
// Handles login form submission.
if (window.location.pathname.endsWith('login.html') || window.location.pathname === '/' || window.location.pathname.endsWith('index.html')) {
    document.addEventListener('DOMContentLoaded', () => {
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                clearMessage('auth-message');
                const username = document.getElementById('login-username').value;
                const email = document.getElementById('login-email').value;
                const password = document.getElementById('login-password').value;

                try {
                    const response = await fetch(`${API_BASE_URL}/login`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, email, password }),
                    });
                    const data = await response.json();
                    if (response.ok) {
                        localStorage.setItem('authToken', data.token);
                        // Store username if returned by the server (recommended)
                        if (data.username) {
                            localStorage.setItem('username', data.username);
                        }
                        displayMessage('auth-message', data.message, true);
                        // Delay the redirect slightly to allow message to be seen, then redirect
                        setTimeout(() => {
                            window.location.href = 'dashboard.html';
                        }, 500); // Redirect after 0.5 seconds
                    } else {
                        displayMessage('auth-message', data.message, false);
                    }
                } catch (error) {
                    displayMessage('auth-message', `Error logging in: ${error.message}`, false);
                }
            });
        }
    });
}

// Logic for Register Page (register.html)
// Handles registration form submission.
if (window.location.pathname.endsWith('register.html')) {
    document.addEventListener('DOMContentLoaded', () => {
        const registerForm = document.getElementById('register-form');
        if (registerForm) {
            registerForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                clearMessage('auth-message');
                const username = document.getElementById('register-username').value; // Assuming you have this input
                const email = document.getElementById('register-email').value;
                const password = document.getElementById('register-password').value;
                const confirmPassword = document.getElementById('register-confirm-password').value;

                if (password !== confirmPassword) {
                    displayMessage('auth-message', 'Passwords do not match.', false);
                    return;
                }

                try {
                    const response = await fetch(`${API_BASE_URL}/register`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, email, password }), // Send username to backend
                    });
                    const data = await response.json();
                    if (response.ok) {
                        displayMessage('auth-message', data.message + ' You can now log in.', true);
                        // Optional: Redirect to login page after successful registration
                        setTimeout(() => {
                            window.location.href = 'login.html';
                        }, 2000);
                    } else {
                        displayMessage('auth-message', data.message, false);
                    }
                } catch (error) {
                    displayMessage('auth-message', `Error registering: ${error.message}`, false);
                }
            });
        }
    });
}

// Logic for Forgot Password Page (forgot-password.html)
// Handles forgot password request.
if (window.location.pathname.endsWith('forgot-password.html')) {
    document.addEventListener('DOMContentLoaded', () => {
        const forgotPasswordForm = document.getElementById('forgot-password-form');
        if (forgotPasswordForm) {
            forgotPasswordForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                clearMessage('auth-message');
                const email = document.getElementById('forgot-email').value;

                try {
                    const response = await fetch(`${API_BASE_URL}/forgotpassword`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email }),
                    });
                    const data = await response.json();
                    if (response.ok) {
                        displayMessage('auth-message', data.message, true);
                    } else {
                        // Backend is designed to give a generic success message even if email not found
                        // to prevent enumeration. So, this else block might not be hit if backend always ok.
                        displayMessage('auth-message', data.message, false);
                    }
                } catch (error) {
                    displayMessage('auth-message', `Error requesting reset: ${error.message}`, false);
                }
            });
        }
    });
}

// Logic for Reset Password Page (reset-password.html)
// Handles new password submission with token from URL.
if (window.location.pathname.includes('resetpassword/')) { // Check for URL path segment
    document.addEventListener('DOMContentLoaded', () => {
        const resetPasswordForm = document.getElementById('reset-password-form');
        const returnToLoginLink = document.getElementById('return-to-login-link');
        const pathSegments = window.location.pathname.split('/');
        const token = pathSegments[pathSegments.length - 1]; // Get token from URL

        // Ensure a token exists in the URL
        if (!token || token.length < 32) { // A basic check for token presence and reasonable length
            displayMessage('auth-message', 'Invalid or missing reset token in URL.', false);
            if (resetPasswordForm) resetPasswordForm.style.display = 'none'; // Hide the form
            if (returnToLoginLink) returnToLoginLink.style.display = 'block';
            return;
        }

        if (resetPasswordForm) {
            resetPasswordForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                clearMessage('auth-message');
                const newPassword = document.getElementById('new-password').value;
                const confirmNewPassword = document.getElementById('confirm-new-password').value;

                if (newPassword !== confirmNewPassword) {
                    displayMessage('auth-message', 'Passwords do not match.', false);
                    return;
                }
                if (newPassword.length < 6) { // Client-side check for password length
                    displayMessage('auth-message', 'Password must be 6 or more characters.', false);
                    return;
                }


                try {
                    const response = await fetch(`${API_BASE_URL}/resetpassword/${token}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: newPassword }),
                    });
                    const data = await response.json();
                    if (response.ok) {
                        displayMessage('auth-message', data.message + ' You can now log in with your new password.', true);
                        if (returnToLoginLink) returnToLoginLink.style.display = 'block'; // Show login link
                        resetPasswordForm.reset(); // Clear form
                        resetPasswordForm.style.display = 'none'; // Hide the form after success
                    } else {
                        displayMessage('auth-message', data.message, false);
                    }
                } catch (error) {
                    displayMessage('auth-message', `Error resetting password: ${error.message}`, false);
                }
            });
        }
    });
}


// Logic for Dashboard Page (dashboard.html)
// Handles file uploads, listing, searching, filtering, download, delete, and preview.
if (window.location.pathname.endsWith('dashboard.html')) {
    document.addEventListener('DOMContentLoaded', () => {
        checkAuthAndRedirect(); // Ensure user is authenticated

        const logoutButton = document.getElementById('logout-button');
        if (logoutButton) {
            logoutButton.addEventListener('click', logoutUser);
        }

        // Dashboard specific DOM elements
        const fileuploadForm = document.getElementById('upload-form');
        const fileInput = document.getElementById('file-input');
        const fileNameDisplay = document.getElementById('file-name-display');
        const refreshFilesButton = document.getElementById('refresh-files-button');
        const filesList = document.getElementById('files-list');
        const userDisplay = document.getElementById('user-display');
        const totalStorageDisplay = document.getElementById('total-storage-used');
        // Assuming 'auth-message' is a generic message area,
        // but for upload specific messages, we'll use 'upload-message' if it exists.
        const uploadMessage = document.getElementById('upload-message') || document.getElementById('auth-message');


        // --- File Upload Form Submission Handler ---
        if (fileuploadForm) {
            fileuploadForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const files = fileInput.files; // Get all selected files
                if (files.length === 0) {
                    displayMessage('upload-message', 'Please select at least one file to upload.', false);
                    return;
                }
                await uploadFiles(files); // Call the new uploadFiles function
            });
        }

        // Display user's username from localStorage (set during login)
        const username = localStorage.getItem('username');
        if (userDisplay && username) {
            userDisplay.textContent = `Welcome, ${username}!`;
        } else if (userDisplay) {
            userDisplay.textContent = 'Welcome!'; // Fallback
        }

        // Event listener for file input change to display selected file name
        if (fileInput) {
            fileInput.addEventListener('change', () => {
                if (fileInput.files.length > 0) {
                    if (fileInput.files.length === 1) {
                        fileNameDisplay.textContent = fileInput.files[0].name;
                    } else {
                        fileNameDisplay.textContent = `${fileInput.files.length} files selected`;
                    }
                } else {
                    fileNameDisplay.textContent = 'No file chosen';
                }
            });
        }
        
        // Removed the duplicate and incorrect upload form listener from here


        if (refreshFilesButton) {
            refreshFilesButton.addEventListener('click', fetchUserFiles);
        }

        // --- Search & Filter Event Listeners ---
        const searchInput = document.getElementById('search-input');
        const fileTypeFilter = document.getElementById('file-type-filter');
        const fileSizeFilter = document.getElementById('file-size-filter');
        const startDateFilter = document.getElementById('start-date-filter');
        const endDateFilter = document.getElementById('end-date-filter');

        if (searchInput) searchInput.addEventListener('input', applySearchAndFilters);
        if (fileTypeFilter) fileTypeFilter.addEventListener('change', applySearchAndFilters);
        if (fileSizeFilter) fileSizeFilter.addEventListener('change', applySearchAndFilters);
        if (startDateFilter) startDateFilter.addEventListener('change', applySearchAndFilters);
        if (endDateFilter) endDateFilter.addEventListener('change', applySearchAndFilters);


        // Delegation for download, delete, and preview buttons within the file list table
        if (filesList) {
            filesList.addEventListener('click', async (e) => {
                const targetButton = e.target.closest('button');
                if (!targetButton) return;

                const encryptedFileName = targetButton.dataset.encryptedFilename;
                const originalName = targetButton.dataset.originalName;
                const mimeType = targetButton.dataset.mimeType;

                if (targetButton.classList.contains('download-button')) {
                    await downloadFile(encryptedFileName, originalName);
                } else if (targetButton.classList.contains('delete-button')) {
                    // Pass originalName to deleteFile for better confirmation message
                    await deleteFile(encryptedFileName, originalName);
                } else if (targetButton.classList.contains('preview-button')) {
                    await showFilePreview({ encryptedFileName, originalName, mimeType });
                }
            });
        }

        // Initial fetch of files when dashboard loads
        fetchUserFiles();
        fetchStorageUsage(); // Fetch and display storage usage on dashboard load
    });
}


async function downloadSelectedFiles(fileIds) {
    try {
        const response = await fetch('/api/download-multiple', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer YOUR_JWT_TOKEN` // Make sure to send the auth token
            },
            body: JSON.stringify({ fileIds: fileIds })
        });

        if (response.ok) {
            // Get the filename from the Content-Disposition header
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'download.zip';
            if (contentDisposition && contentDisposition.includes('filename=')) {
                filename = contentDisposition.split('filename=')[1].replace(/"/g, '');
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename; // Set the download filename
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url); // Clean up the URL object

            alert('Files downloaded successfully!');
        } else {
            const errorData = await response.json();
            alert(`Download failed: ${errorData.message || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error initiating download:', error);
        alert('An error occurred during download.');
    }
}

// Example usage:
// Call this function when a user clicks a "Download Selected" button
// after selecting files. fileIds would be an array like ['6670e...', '6670f...', '66710...']
// downloadSelectedFiles(['file_id_1', 'file_id_2']);

// Logic for User Activity Page (user-activity.html)
if (window.location.pathname.endsWith('user-activity.html')) {
    document.addEventListener('DOMContentLoaded', () => {
        checkAuthAndRedirect();

        const activityList = document.getElementById('activity-list');
        const activityMessage = document.getElementById('activity-message') || document.getElementById('auth-message'); // Fallback

        async function fetchUserActivities() {
            clearMessage('activity-message');
            if (activityList) {
                activityList.innerHTML = '<tr><td colspan="3" class="empty-state"><i class="fas fa-spinner fa-spin"></i> Loading activities...</td></tr>';
            }

            const response = await makeAuthenticatedRequest(`${API_BASE_URL}/user/activities`);
            if (!response) {
                if (activityList) activityList.innerHTML = '<tr><td colspan="3" class="empty-state">Failed to load activities.</td></tr>';
                return;
            }

            const data = await response.json();
            if (response.ok) {
                renderActivities(data.activities);
            } else {
                displayMessage('activity-message', data.message, false);
                if (activityList) activityList.innerHTML = '<tr><td colspan="3" class="empty-state">Error loading activities.</td></tr>';
            }
        }

        function renderActivities(activities) {
            if (!activityList) return;
            activityList.innerHTML = '';

            if (activities && activities.length > 0) {
                activities.forEach(activity => {
                    const listItem = document.createElement('tr');
                    listItem.innerHTML = `
                        <td>${new Date(activity.timestamp).toLocaleString()}</td>
                        <td>${activity.action}</td>
                        <td>${activity.description}</td>
                    `;
                    activityList.appendChild(listItem);
                });
            } else {
                activityList.innerHTML = '<tr><td colspan="3" class="empty-state">No activities found.</td></tr>';
            }
        }

        fetchUserActivities();
    });
}

// Logic for Report Issue Page (report-issue.html)
if (window.location.pathname.endsWith('report-issue.html')) {
    document.addEventListener('DOMContentLoaded', () => {
        checkAuthAndRedirect();

        const reportIssueForm = document.getElementById('report-issue-form');
        if (reportIssueForm) {
            reportIssueForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                clearMessage('issue-message');

                const subject = document.getElementById('issue-subject').value;
                const description = document.getElementById('issue-description').value;

                if (!subject || !description) {
                    displayMessage('issue-message', 'Please fill in both subject and description.', false);
                    return;
                }

                try {
                    const response = await makeAuthenticatedRequest(`${API_BASE_URL}/report-issue`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ subject, description }),
                    });

                    if (!response) return; // makeAuthenticatedRequest handled the error/redirect

                    const data = await response.json();
                    if (response.ok) {
                        displayMessage('issue-message', data.message, true);
                        reportIssueForm.reset(); // Clear the form
                    } else {
                        displayMessage('issue-message', data.message, false);
                    }
                } catch (error) {
                    displayMessage('issue-message', `Error reporting issue: ${error.message}`, false);
                }
            });
        }
    });
}

// --- File Management Functions (Common) ---

/**
 * Handles file upload to the server.
 * @param {FileList} files - The file object to upload.
 */
async function uploadFiles(files) {
    const uploadButton = document.getElementById('upload-button');
    const uploadMessageElementId = document.getElementById('upload-message') ? 'upload-message' : 'auth-message';

    if (!files || files.length === 0) {
        displayMessage(uploadMessageElementId, 'No files selected for upload.', false);
        return;
    }

    if (uploadButton) {
        uploadButton.disabled = true;
        uploadButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';
    }

    let successfulUploads = 0;
    let failedUploads = 0;
    let totalFiles = files.length;

    // Clear previous messages
    clearMessage(uploadMessageElementId);
    displayMessage(uploadMessageElementId, `Uploading ${totalFiles} file(s)...`, true);

    for (let i = 0; i < totalFiles; i++) {
        const file = files[i];
        const formData = new FormData();
        formData.append('file', file);

        try {
            // We'll use makeAuthenticatedRequest directly inside the loop
            const response = await makeAuthenticatedRequest(`${API_BASE_URL}/upload`, {
                method: 'POST',
                body: formData,
            });

            if (response && response.ok) {
                successfulUploads++;
                // Optionally display progress for each file
                // displayMessage(uploadMessageElementId, `Uploaded <span class="math-inline">\{successfulUploads\}/</span>{totalFiles}: ${file.name}`, true);
            } else {
                failedUploads++;
                const data = response ? await response.json().catch(() => ({ message: 'Unknown error' })) : { message: 'Network or authentication error.' };
                console.error(`Failed to upload ${file.name}: ${data.message}`);
                // Optionally display error for each file
                // displayMessage(uploadMessageElementId, `Failed to upload ${file.name}: ${data.message}`, false);
            }
        } catch (error) {
            failedUploads++;
            console.error(`Error uploading ${file.name}:`, error);
            // displayMessage(uploadMessageElementId, `Error uploading ${file.name}: ${error.message}`, false);
        }
    }

    if (uploadButton) {
        uploadButton.disabled = false;
        uploadButton.innerHTML = '<i class="fas fa-upload"></i> Upload File(s)';
    }

    if (successfulUploads === totalFiles) {
        displayMessage(uploadMessageElementId, `Successfully uploaded all ${successfulUploads} file(s)!`, true);
    } else if (failedUploads === totalFiles) {
        displayMessage(uploadMessageElementId, `Failed to upload any files.`, false);
    } else {
        displayMessage(uploadMessageElementId, `Uploaded ${successfulUploads} of ${totalFiles} file(s). ${failedUploads} failed. Check console for details.`, false);
    }

    // Always re-fetch files and storage usage after an upload attempt
    fetchUserFiles();
    fetchStorageUsage();

    // Clear the file input display
    document.getElementById('file-input').value = '';
    document.getElementById('file-name-display').textContent = 'No file chosen';
}

/**
 * Fetches the current user's file list from the server.
 */
async function fetchUserFiles() {
    const filesList = document.getElementById('files-list');
    const listMessageElement = document.getElementById('list-message') || document.getElementById('auth-message'); // Fallback
    clearMessage('list-message');

    if (filesList) {
        filesList.innerHTML = '<tr><td colspan="4" class="empty-state"><i class="fas fa-spinner fa-spin"></i> Loading files...</td></tr>';
    }

    const response = await makeAuthenticatedRequest(`${API_BASE_URL}/user/files`);
    if (!response) {
        // Error already handled by makeAuthenticatedRequest
        if (filesList) filesList.innerHTML = '<tr><td colspan="4" class="empty-state">Failed to load files.</td></tr>';
        return;
    }

    const data = await response.json();
    if (response.ok) {
        allFiles = data.files || []; // Store all fetched files globally
        applySearchAndFilters(); // Apply current search/filters to newly fetched data
        // No need to display a success message here, as renderFiles will populate the table
    } else {
        displayMessage('list-message', data.message || 'Failed to fetch files.', false);
        allFiles = []; // Clear files on error
        renderFiles([]); // Render empty table
    }
}

/**
 * Initiates the download of a specific file.
 * @param {string} encryptedFileName - The encrypted file name on the server.
 * @param {string} originalName - The original name of the file for the download prompt.
 */
async function downloadFile(encryptedFileName, originalName) {
    const response = await makeAuthenticatedRequest(`${API_BASE_URL}/restore/${encryptedFileName}`);
    if (!response) {
        // Error already handled by makeAuthenticatedRequest
        return;
    }

    if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = originalName; // Set the download filename
        document.body.appendChild(a); // Append to body (important for Firefox)
        a.click(); // Programmatically click the link to trigger download
        document.body.removeChild(a); // Clean up the element
        window.URL.revokeObjectURL(url); // Clean up the temporary URL
        displayMessage('list-message', `File "${originalName}" restored successfully.`, true);
    } else {
        const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
        displayMessage('list-message', `Error restoring "${originalName}": ${errorData.message || 'Unknown error'}`, false);
    }
}

/**
 * Handles the deletion of a file.
 * @param {string} encryptedFileName - The encrypted file name on the server.
 * @param {string} originalName - The original name of the file for the confirmation message.
 */
async function deleteFile(encryptedFileName, originalName) {
    // IMPORTANT: Replace confirm() with a custom modal for better UX and consistency
    if (!confirm(`Are you sure you want to delete "${originalName}"? This action cannot be undone.`)) {
        return;
    }
    clearMessage('list-message');

    const response = await makeAuthenticatedRequest(`${API_BASE_URL}/delete/${encryptedFileName}`, {
        method: 'DELETE',
    });

    if (!response) {
        // Error already handled by makeAuthenticatedRequest
        return;
    }

    const data = await response.json();
    if (response.ok) {
        displayMessage('list-message', data.message, true);
        fetchUserFiles(); // Re-fetch to update the list
        fetchStorageUsage(); // Update storage usage
    } else {
        displayMessage('list-message', `Error deleting file: ${data.message || 'Unknown error'}`, false);
    }
}

/**
 * Fetches and displays the user's total storage usage.
 */
async function fetchStorageUsage() {
    const totalStorageDisplay = document.getElementById('total-storage-used');
    if (!totalStorageDisplay) return; // Exit if element not on page

    // Show a loading state
    totalStorageDisplay.textContent = 'Loading storage...';
    totalStorageDisplay.style.color = '#555';

    const response = await makeAuthenticatedRequest(`${API_BASE_URL}/user/storage-usage`);

    if (!response) {
        totalStorageDisplay.textContent = 'Failed to load storage.';
        totalStorageDisplay.style.color = 'red';
        return;
    }

    const data = await response.json();
    if (response.ok) {
        const storageMB = (data.total_storage_used / (1024 * 1024)).toFixed(2);
        totalStorageDisplay.textContent = `Total Storage Used: ${storageMB} MB`;
        totalStorageDisplay.style.color = '#333'; // Reset color
    } else {
        totalStorageDisplay.textContent = `Error: ${data.message || 'Unknown error'}`;
        totalStorageDisplay.style.color = 'red';
    }
}



// --- Initial Setup (runs on every page load) ---
// This ensures authentication checks run as soon as the DOM is ready.
document.addEventListener('DOMContentLoaded', checkAuthAndRedirect);