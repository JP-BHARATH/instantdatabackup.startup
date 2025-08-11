// frontend/js/profile.js

document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const profileForm = document.getElementById('profile-form');
    const nameInput = document.getElementById('profile-name');
    const emailInput = document.getElementById('profile-email');
    const passwordForm = document.getElementById('password-form');
    const currentPasswordInput = document.getElementById('current-password');
    const newPasswordInput = document.getElementById('new-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const feedbackForm = document.getElementById('feedback-form');
    const feedbackSubjectInput = document.getElementById('feedback-subject');
    const feedbackDescriptionInput = document.getElementById('feedback-description');
    const dataUsageText = document.getElementById('data-usage-text');
    const dataUsageBar = document.getElementById('data-usage-bar');
    const dataUsagePercentage = document.getElementById('data-usage-percentage');
    const recentActivityList = document.getElementById('recent-activity-list');

    // Helper functions
    function getAuthToken() {
        return localStorage.getItem('authToken');
    }

    function showAlert(message, isSuccess = true) {
        alert(message);
    }

    // Fetch profile info
    async function fetchProfile() {
        try {
            const res = await fetch('/api/profile', {
                headers: { 'Authorization': 'Bearer ' + getAuthToken() }
            });
            if (!res.ok) throw new Error('Failed to fetch profile');
            const data = await res.json();

            if (data.profile) {
                nameInput.value = data.profile.username || "";
                emailInput.value = data.profile.email || '';
            }
            if (data.storageStats) {
                updateDataUsage({
                    totalUsed: data.storageStats.used,
                    limit: data.storageStats.limit
                });
            }
            renderRecentActivity(data.activities || []);
            loadFeedbackList(); // Load feedback when profile loads
        } catch (err) {
            showAlert('Error loading profile: ' + err.message, false);
        }
    }

   // Feedback form submission
feedbackForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const subject = feedbackSubjectInput.value.trim();
    const description = feedbackDescriptionInput.value.trim();
    
    if (!subject || !description) {
        showAlert('Please fill in both subject and description fields', false);
        return;
    }

    try {
        const response = await fetch('/api/profile/feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + getAuthToken()
            },
            body: JSON.stringify({ subject, description })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Failed to submit feedback');
        }

        showAlert('Feedback submitted successfully!');
        feedbackForm.reset();
        loadFeedbackList();
    } catch (error) {
        console.error('Feedback submission error:', error);
        showAlert('Error submitting feedback: ' + error.message, false);
    }
});

// Load feedback list with better error handling
async function loadFeedbackList() {
    try {
        const response = await fetch('/api/profile/feedback', {
            headers: {
                'Authorization': 'Bearer ' + getAuthToken()
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to load feedback');
        }

        const feedbacks = await response.json();
        renderFeedbackList(feedbacks);
    } catch (error) {
        console.error('Error loading feedback:', error);
        const feedbackListContainer = document.getElementById('feedback-list');
        if (feedbackListContainer) {
            feedbackListContainer.innerHTML = `
                <div class="error-message">
                    Error loading feedback: ${error.message}
                </div>
            `;
        }
    }
}

    // Render feedback list
    function renderFeedbackList(feedbacks) {
        const feedbackListContainer = document.getElementById('feedback-list');
        if (!feedbackListContainer) return;

        feedbackListContainer.innerHTML = feedbacks.length > 0 
            ? feedbacks.map(feedback => `
                <div class="feedback-item">
                    <h4>${feedback.subject}</h4>
                    <p>${feedback.description}</p>
                    <div class="feedback-meta">
                        <span>Status: ${feedback.status}</span>
                        <span>Submitted: ${new Date(feedback.createdAt).toLocaleString()}</span>
                    </div>
                    ${feedback.adminResponse ? `
                        <div class="admin-response">
                            <strong>Admin Response:</strong>
                            <p>${feedback.adminResponse}</p>
                        </div>
                    ` : ''}
                </div>
            `).join('')
            : '<p>No feedback submissions yet.</p>';
    }
    // Update profile
    profileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            const res = await fetch('/api/profile', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + getAuthToken()
                },
                body: JSON.stringify({ name: nameInput.value })
            });
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.errors?.[0]?.msg || 'Failed to update profile');
            }
            showAlert('Profile updated successfully');
        } catch (err) {
            showAlert('Error updating profile: ' + err.message, false);
        }
    });

    // Update password
    passwordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (newPasswordInput.value !== confirmPasswordInput.value) {
            showAlert('New passwords do not match', false);
            return;
        }
        try {
            const res = await fetch('/api/profile/password', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + getAuthToken()
                },
                body: JSON.stringify({
                    currentPassword: currentPasswordInput.value,
                    newPassword: newPasswordInput.value
                })
            });
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.errors?.[0]?.msg || 'Failed to update password');
            }
            showAlert('Password updated successfully');
            passwordForm.reset();
        } catch (err) {
            showAlert('Error updating password: ' + err.message, false);
        }
    });

  
   

   

    

   
    // Data Usage Chart
    let dataUsageChart;
    function updateDataUsage(dataUsage) {
        const used = dataUsage.totalUsed || 0;
        const limit = dataUsage.limit || 1;
        const percent = Math.round((used / limit) * 100);
        dataUsageText.textContent = `${used} MB / ${limit} MB`;
        dataUsageBar.style.width = percent + '%';
        dataUsagePercentage.textContent = percent + '%';
        // Chart.js
        if (!dataUsageChart) {
            const ctx = document.getElementById('dataUsageChart').getContext('2d');
            dataUsageChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Used', 'Remaining'],
                    datasets: [{
                        data: [used, limit - used],
                        backgroundColor: ['#4e73df', '#eaeaea'],
                        hoverBackgroundColor: ['#2e59d9', '#d4d4d4'],
                        borderWidth: 1
                    }]
                },
                options: {
                    cutout: '80%',
                    plugins: { legend: { display: false } },
                    maintainAspectRatio: false
                }
            });
        } else {
            dataUsageChart.data.datasets[0].data = [used, limit - used];
            dataUsageChart.update();
        }
    }

    // Render recent activity (placeholder)
    function renderRecentActivity(activities = []) {
        recentActivityList.innerHTML = '';
        activities.slice(0, 3).forEach(act => {
            const li = document.createElement('li');
            li.className = 'flex items-center';
            li.innerHTML = `<span class="w-2 h-2 bg-blue-500 rounded-full mr-2"></span><span>${act.description}</span>`;
            recentActivityList.appendChild(li);
        });
    }

    // Initial load
    fetchProfile();
});