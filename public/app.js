// Application state
let currentUser = null;
let authToken = null;
let currentSection = 'dashboard';

// Dynamic base URL for Home Assistant Ingress support
let baseURL = '';

// Initialize base URL based on environment
function initializeBaseURL() {
    // Check if we're running in Home Assistant Ingress
    const currentPath = window.location.pathname;
    
    if (currentPath.includes('/api/hassio_ingress/')) {
        // Extract ingress path for Home Assistant
        const ingressMatch = currentPath.match(/\/api\/hassio_ingress\/[^\/]+/);
        if (ingressMatch) {
            baseURL = ingressMatch[0];
        }
    } else if (currentPath !== '/' && !currentPath.endsWith('/')) {
        // Handle other proxy setups
        baseURL = currentPath.replace(/\/$/, '');
    }
    
    console.log('Base URL detected:', baseURL || '(none - direct access)');
}

// DOM elements
const elements = {};

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeBaseURL();
    initializeElements();
    checkAuthToken();
    setupEventListeners();
});

function initializeElements() {
    // Login elements
    elements.loginScreen = document.getElementById('loginScreen');
    elements.mainApp = document.getElementById('mainApp');
    elements.loginForm = document.getElementById('loginForm');
    elements.loginError = document.getElementById('loginError');
    elements.username = document.getElementById('username');
    elements.password = document.getElementById('password');

    // Main app elements
    elements.userName = document.getElementById('userName');
    elements.userRole = document.getElementById('userRole');
    elements.totalPoints = document.getElementById('totalPoints');
    elements.logoutBtn = document.getElementById('logoutBtn');

    // Navigation
    elements.navButtons = document.querySelectorAll('.nav-btn');
    elements.contentSections = document.querySelectorAll('.content-section');

    // Dashboard
    elements.completedToday = document.getElementById('completedToday');
    elements.pendingChores = document.getElementById('pendingChores');
    elements.totalRewards = document.getElementById('totalRewards');
    elements.recentChores = document.getElementById('recentChores');

    // Chores
    elements.choresList = document.getElementById('choresList');
    elements.filterButtons = document.querySelectorAll('.filter-btn');

    // Rewards
    elements.rewardsGrid = document.getElementById('rewardsGrid');

    // Admin
    elements.createUserForm = document.getElementById('createUserForm');
    elements.usersList = document.getElementById('usersList');
    elements.createChoreTemplateForm = document.getElementById('createChoreTemplateForm');

    // Modal
    elements.notificationModal = document.getElementById('notificationModal');
    elements.notificationTitle = document.getElementById('notificationTitle');
    elements.notificationMessage = document.getElementById('notificationMessage');
}

function setupEventListeners() {
    // Login form
    elements.loginForm.addEventListener('submit', handleLogin);
    
    // Logout button
    elements.logoutBtn.addEventListener('click', handleLogout);
    
    // Navigation
    elements.navButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const section = e.currentTarget.dataset.section;
            switchSection(section);
        });
    });

    // Filter buttons
    elements.filterButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const filter = e.currentTarget.dataset.filter;
            filterChores(filter);
        });
    });

    // Admin forms
    if (elements.createUserForm) {
        elements.createUserForm.addEventListener('submit', handleCreateUser);
    }
    if (elements.createChoreTemplateForm) {
        elements.createChoreTemplateForm.addEventListener('submit', handleCreateChoreTemplate);
    }
    
    // Add event listener for create reward form
    const createRewardForm = document.getElementById('createRewardForm');
    if (createRewardForm) {
        createRewardForm.addEventListener('submit', handleCreateReward);
    }

    // Modal clicks
    elements.notificationModal.addEventListener('click', (e) => {
        if (e.target === elements.notificationModal) {
            closeNotificationModal();
        }
    });
}

function checkAuthToken() {
    const token = localStorage.getItem('authToken');
    if (token) {
        authToken = token;
        // Verify token with server
        fetch(`${baseURL}/api/me`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error('Token neveljaven');
            }
        })
        .then(user => {
            currentUser = user;
            showMainApp();
        })
        .catch(() => {
            localStorage.removeItem('authToken');
            authToken = null;
            showLoginScreen();
        });
    } else {
        showLoginScreen();
    }
}

async function handleLogin(e) {
    e.preventDefault();
    
    const username = elements.username.value.trim();
    const password = elements.password.value;

    if (!username || !password) {
        showError('Prosim vnesite uporabniško ime in geslo.');
        return;
    }

    try {
        const response = await fetch(`${baseURL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('authToken', authToken);
            showMainApp();
        } else {
            showError(data.error || 'Napaka pri prijavi');
        }
    } catch (error) {
        showError('Napaka povezave s strežnikom');
    }
}

function handleLogout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    showLoginScreen();
}

function showLoginScreen() {
    elements.loginScreen.style.display = 'flex';
    elements.mainApp.style.display = 'none';
    elements.username.focus();
}

function showMainApp() {
    elements.loginScreen.style.display = 'none';
    elements.mainApp.style.display = 'block';
    
    updateUserInfo();
    setupRoleBasedUI();
    loadDashboardData();
}

function updateUserInfo() {
    elements.userName.textContent = currentUser.full_name;
    elements.userRole.textContent = getRoleDisplayName(currentUser.role);
    elements.totalPoints.textContent = currentUser.points || 0;
}

function getRoleDisplayName(role) {
    const roleNames = {
        'admin': 'Administrator',
        'superuser': 'Super uporabnik',
        'normaluser': 'Uporabnik'
    };
    return roleNames[role] || role;
}

function setupRoleBasedUI() {
    // Show/hide navigation based on role
    const adminButtons = document.querySelectorAll('.admin-only');
    const adminSuperuserButtons = document.querySelectorAll('.admin-superuser');

    adminButtons.forEach(btn => {
        btn.style.display = currentUser.role === 'admin' ? 'flex' : 'none';
    });

    adminSuperuserButtons.forEach(btn => {
        btn.style.display = ['admin', 'superuser'].includes(currentUser.role) ? 'flex' : 'none';
    });
}

function switchSection(section) {
    // Update navigation
    elements.navButtons.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.section === section);
    });

    // Update content sections
    elements.contentSections.forEach(sec => {
        sec.classList.toggle('active', sec.id === section + 'Section');
    });

    currentSection = section;

    // Load section data
    switch (section) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'chores':
            loadChores();
            break;
        case 'rewards':
            loadRewards();
            break;
        case 'users':
            if (currentUser.role === 'admin') {
                loadUsers();
            }
            break;
        case 'chore-templates':
            if (currentUser.role === 'admin') {
                loadChoreTemplates();
            }
            break;
        case 'manage-rewards':
            if (currentUser.role === 'admin') {
                loadRewardsManagement();
            }
            break;
        case 'assign':
            if (['admin', 'superuser'].includes(currentUser.role)) {
                loadAssignmentData();
                loadRecurringAssignmentData();
            }
            break;
        case 'statistics':
            loadStatistics('week');
            loadLeaderboard('week');
            loadAdvancedCharts('week');
            break;
        case 'others':
            loadOthersChores();
            loadUsersForOthersSection();
            break;
    }
}

async function loadDashboardData() {
    try {
        // Load user's current data
        const userResponse = await apiCall('/api/me');
        currentUser = userResponse;
        updateUserInfo();

        // Load chores for stats
        const choresResponse = await apiCall('/api/my-chores');
        updateDashboardStats(choresResponse);
        updateRecentActivity(choresResponse);

    } catch (error) {
        console.error('Napaka pri nalaganju podatkov:', error);
    }
}

function updateDashboardStats(chores) {
    const today = new Date().toDateString();
    const completedToday = chores.filter(chore => 
        chore.status === 'completed' && 
        new Date(chore.completed_at).toDateString() === today
    ).length;

    const pendingChores = chores.filter(chore => chore.status === 'pending').length;

    elements.completedToday.textContent = completedToday;
    elements.pendingChores.textContent = pendingChores;
    // Total rewards will be loaded separately if needed
}

function updateRecentActivity(chores) {
    const recentChores = chores
        .filter(chore => chore.status === 'completed')
        .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at))
        .slice(0, 5);

    if (recentChores.length === 0) {
        elements.recentChores.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">Ni nedavno opravljenih opravil</p>';
        return;
    }

    elements.recentChores.innerHTML = recentChores.map(chore => `
        <div class="activity-item" style="display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: var(--bg-secondary); border-radius: var(--radius-md); margin-bottom: 0.5rem;">
            <div class="activity-info">
                <strong>${chore.name}</strong>
                <div class="activity-meta" style="font-size: 0.875rem; color: var(--text-secondary);">+${chore.points} točk • ${formatDate(chore.completed_at)}</div>
            </div>
            <div class="activity-points" style="color: var(--success-color); font-weight: 600;">+${chore.points}</div>
        </div>
    `).join('');
}

async function loadChores(filter = 'all') {
    try {
        const params = filter !== 'all' ? `?status=${filter}` : '';
        const chores = await apiCall(`/api/my-chores${params}`);
        renderChores(chores, filter);
    } catch (error) {
        console.error('Napaka pri nalaganju opravil:', error);
        elements.choresList.innerHTML = '<p class="loading">Napaka pri nalaganju opravil</p>';
    }
}

function renderChores(chores, filter) {
    if (chores.length === 0) {
        elements.choresList.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                <i class="fas fa-tasks" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                <p>Ni ${filter === 'all' ? '' : filter + 'ih '}opravil.</p>
            </div>
        `;
        return;
    }

    // Group chores by frequency
    const groupedChores = {
        'once': chores.filter(c => c.frequency === 'once'),
        'daily': chores.filter(c => c.frequency === 'daily'),
        'weekly': chores.filter(c => c.frequency === 'weekly'),
        'monthly': chores.filter(c => c.frequency === 'monthly')
    };

    const frequencyLabels = {
        'once': '📅 Enkratna opravila',
        'daily': '🔄 Dnevna opravila',
        'weekly': '📊 Tedenska opravila',
        'monthly': '📈 Mesečna opravila'
    };

    let html = '';

    Object.keys(groupedChores).forEach(frequency => {
        const choreGroup = groupedChores[frequency];
        if (choreGroup.length > 0) {
            html += `
                <div class="chore-group" style="margin-bottom: 2rem;">
                    <h3 class="chore-group-title" style="color: var(--primary-color); margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--primary-color);">
                        ${frequencyLabels[frequency]} (${choreGroup.length})
                    </h3>
                    <div class="chore-group-items">
                        ${choreGroup.map(chore => `
                            <div class="chore-item ${chore.status}" style="margin-bottom: 1rem;">
                                <div class="chore-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                                    <h4>${chore.name}</h4>
                                    <div class="chore-actions" style="display: flex; align-items: center; gap: 1rem;">
                                        <span class="chore-points" style="background: var(--primary-color); color: white; padding: 0.25rem 0.75rem; border-radius: var(--radius-sm); font-size: 0.875rem;">${chore.points} točk</span>
                                        ${chore.status === 'pending' ? `
                                            <button class="btn btn-primary btn-sm" onclick="completeChore(${chore.id})">
                                                <i class="fas fa-check"></i>
                                                Opravi
                                            </button>
                                        ` : ''}
                                    </div>
                                </div>
                                <div class="chore-details">
                                    ${chore.description ? `<p style="margin-bottom: 1rem; color: var(--text-secondary);">${chore.description}</p>` : ''}
                                    <div class="chore-meta" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                                        <span><i class="fas fa-tag"></i> ${chore.category}</span>
                                        <span><i class="fas fa-clock"></i> ${formatDate(chore.due_date)}</span>
                                        ${chore.assigned_by_name ? `<span><i class="fas fa-user"></i> Dodeljeno: ${chore.assigned_by_name}</span>` : ''}
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
    });

    elements.choresList.innerHTML = html || `
        <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
            <p>Ni opravil v tej kategoriji.</p>
        </div>
    `;
}

async function completeChore(choreId) {
    try {
        const response = await apiCall(`/api/complete-chore/${choreId}`, 'POST');
        showNotification('Uspeh', `Opravilo opravljeno! +${response.pointsAwarded} točk`);
        
        // Refresh data
        loadDashboardData();
        if (currentSection === 'chores') {
            loadChores();
        }
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri opravljanju opravila');
    }
}

function filterChores(filter) {
    // Update filter buttons
    elements.filterButtons.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });

    loadChores(filter);
}

async function loadRewards() {
    try {
        const rewards = await apiCall('/api/rewards');
        renderRewards(rewards);
    } catch (error) {
        console.error('Napaka pri nalaganju nagrad:', error);
        elements.rewardsGrid.innerHTML = '<p class="loading">Napaka pri nalaganju nagrad</p>';
    }
}

function renderRewards(rewards) {
    elements.rewardsGrid.innerHTML = rewards.map(reward => {
        const canAfford = currentUser.points >= reward.cost;
        return `
            <div class="reward-card">
                <div class="reward-icon">${reward.icon}</div>
                <h4>${reward.name}</h4>
                <p class="reward-description">${reward.description}</p>
                <div class="reward-cost">${reward.cost} točk</div>
                <button 
                    class="btn ${canAfford ? 'btn-primary' : 'btn-secondary'}" 
                    onclick="redeemReward(${reward.id})"
                    ${!canAfford ? 'disabled' : ''}
                >
                    ${canAfford ? 'Odkupi' : 'Premalo točk'}
                </button>
            </div>
        `;
    }).join('');
}

async function redeemReward(rewardId) {
    try {
        const response = await apiCall(`/api/redeem-reward/${rewardId}`, 'POST');
        showNotification('Čestitamo!', `Nagrada "${response.reward.name}" odkupljena! ${response.reward.icon}`);
        
        // Refresh data
        loadDashboardData();
        loadRewards();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri odkupu nagrade');
    }
}

async function loadUsers() {
    if (currentUser.role !== 'admin') return;

    try {
        const users = await apiCall('/api/users');
        renderUsers(users);
    } catch (error) {
        console.error('Napaka pri nalaganju uporabnikov:', error);
    }
}

function renderUsers(users) {
    elements.usersList.innerHTML = users.map(user => `
        <div class="user-card">
            <div class="user-info-card">
                <h5>${user.full_name}</h5>
                <p>@${user.username} • ${user.points} točk</p>
                ${user.email ? `<p>${user.email}</p>` : ''}
            </div>
            <div class="user-role-badge ${user.role}">${getRoleDisplayName(user.role)}</div>
        </div>
    `).join('');
}

async function handleCreateUser(e) {
    e.preventDefault();

    const userData = {
        username: document.getElementById('newUsername').value,
        password: document.getElementById('newPassword').value,
        full_name: document.getElementById('newFullName').value,
        email: document.getElementById('newEmail').value,
        role: document.getElementById('newRole').value
    };

    try {
        await apiCall('/api/users', 'POST', userData);
        showNotification('Uspeh', 'Uporabnik uspešno ustvarjen');
        e.target.reset();
        loadUsers();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri ustvarjanju uporabnika');
    }
}

async function handleCreateChoreTemplate(e) {
    e.preventDefault();

    const templateData = {
        name: document.getElementById('choreName').value,
        description: document.getElementById('choreDescription').value,
        points: parseInt(document.getElementById('chorePoints').value),
        negative_points: parseInt(document.getElementById('choreNegativePoints').value),
        category: document.getElementById('choreCategory').value,
        frequency: document.getElementById('choreFrequency').value,
        time_limit_days: parseInt(document.getElementById('choreTimeLimit').value)
    };

    try {
        await apiCall('/api/chore-templates', 'POST', templateData);
        showNotification('Uspeh', 'Predloga opravila uspešno ustvarjena');
        e.target.reset();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri ustvarjanju predloge');
    }
}

// Assignment functionality
async function loadAssignmentData() {
    try {
        const data = await apiCall('/api/assignment-data');
        // Filter only one-time templates for the one-time tab
        const oneTimeTemplates = data.templates.filter(t => t.frequency === 'once');
        renderAssignmentTemplates(oneTimeTemplates, data.users);
        window.assignmentUsers = data.users; // Store for modal use
    } catch (error) {
        console.error('Napaka pri nalaganju podatkov za dodeljevanje:', error);
        document.getElementById('assignmentTemplatesList').innerHTML = '<p class="loading">Napaka pri nalaganju podatkov</p>';
    }
}

function renderAssignmentTemplates(templates, users) {
    const list = document.getElementById('assignmentTemplatesList');
    
    if (templates.length === 0) {
        list.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);"><p>Ni predlog opravil za dodeljevanje.</p></div>';
        return;
    }

    list.innerHTML = templates.map(template => `
        <div class="assignment-template-card" style="background: var(--bg-secondary); border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 1rem;">
            <div class="template-header" style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                <div>
                    <h4 style="margin: 0 0 0.5rem 0;">${template.name}</h4>
                    ${template.description ? `<p style="color: var(--text-secondary); margin: 0;">${template.description}</p>` : ''}
                </div>
                <button class="btn btn-primary btn-sm" onclick="openAssignChoreModal(${template.id}, '${template.name}')">
                    <i class="fas fa-user-plus"></i>
                    Dodeli
                </button>
            </div>
            <div class="template-details" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                <span><i class="fas fa-coins"></i> ${template.points} točk</span>
                <span><i class="fas fa-minus-circle"></i> -${template.negative_points} kazni</span>
                <span><i class="fas fa-tag"></i> ${template.category}</span>
                <span><i class="fas fa-repeat"></i> ${template.frequency}</span>
                <span><i class="fas fa-clock"></i> ${template.time_limit_days} dni</span>
            </div>
        </div>
    `).join('');
}

// Modal functions for chore templates
let currentEditingChoreId = null;

async function openEditChoreModal(templateId) {
    try {
        const templates = await apiCall('/api/chore-templates');
        const template = templates.find(t => t.id === templateId);
        
        if (template) {
            currentEditingChoreId = templateId;
            
            // Fill modal form
            document.getElementById('editChoreName').value = template.name;
            document.getElementById('editChoreDescription').value = template.description || '';
            document.getElementById('editChorePoints').value = template.points;
            document.getElementById('editChoreNegativePoints').value = template.negative_points;
            document.getElementById('editChoreCategory').value = template.category;
            document.getElementById('editChoreFrequency').value = template.frequency;
            document.getElementById('editChoreTimeLimit').value = template.time_limit_days;
            
            // Show modal
            document.getElementById('editChoreModal').classList.add('show');
        }
    } catch (error) {
        showNotification('Napaka', 'Napaka pri nalaganju predloge');
    }
}

function closeEditChoreModal() {
    document.getElementById('editChoreModal').classList.remove('show');
    currentEditingChoreId = null;
}

async function saveChoreTemplate() {
    if (!currentEditingChoreId) return;
    
    const templateData = {
        name: document.getElementById('editChoreName').value,
        description: document.getElementById('editChoreDescription').value,
        points: parseInt(document.getElementById('editChorePoints').value),
        negative_points: parseInt(document.getElementById('editChoreNegativePoints').value),
        category: document.getElementById('editChoreCategory').value,
        frequency: document.getElementById('editChoreFrequency').value,
        time_limit_days: parseInt(document.getElementById('editChoreTimeLimit').value)
    };

    try {
        await apiCall(`/api/chore-templates/${currentEditingChoreId}`, 'PUT', templateData);
        showNotification('Uspeh', 'Predloga uspešno posodobljena');
        closeEditChoreModal();
        loadChoreTemplates();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri posodabljanju predloge');
    }
}

// Modal functions for rewards
let currentEditingRewardId = null;

async function openEditRewardModal(rewardId) {
    try {
        const rewards = await apiCall('/api/rewards');
        const reward = rewards.find(r => r.id === rewardId);
        
        if (reward) {
            currentEditingRewardId = rewardId;
            
            // Fill modal form
            document.getElementById('editRewardName').value = reward.name;
            document.getElementById('editRewardDescription').value = reward.description || '';
            document.getElementById('editRewardCost').value = reward.cost;
            document.getElementById('editRewardIcon').value = reward.icon;
            document.getElementById('editRewardCategory').value = reward.category;
            
            // Show modal
            document.getElementById('editRewardModal').classList.add('show');
        }
    } catch (error) {
        showNotification('Napaka', 'Napaka pri nalaganju nagrade');
    }
}

function closeEditRewardModal() {
    document.getElementById('editRewardModal').classList.remove('show');
    currentEditingRewardId = null;
}

async function saveReward() {
    if (!currentEditingRewardId) return;
    
    const rewardData = {
        name: document.getElementById('editRewardName').value,
        description: document.getElementById('editRewardDescription').value,
        cost: parseInt(document.getElementById('editRewardCost').value),
        icon: document.getElementById('editRewardIcon').value || '🎁',
        category: document.getElementById('editRewardCategory').value,
        active: true
    };

    try {
        await apiCall(`/api/rewards/${currentEditingRewardId}`, 'PUT', rewardData);
        showNotification('Uspeh', 'Nagrada uspešno posodobljena');
        closeEditRewardModal();
        loadRewardsManagement();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri posodabljanju nagrade');
    }
}

// Modal functions for assignment
let currentAssignTemplateId = null;

function openAssignChoreModal(templateId, templateName) {
    currentAssignTemplateId = templateId;
    
    // Update modal title
    document.getElementById('assignChoreModalTitle').textContent = `Dodeli opravilo: ${templateName}`;
    
    // Populate users dropdown
    const userSelect = document.getElementById('assignToUser');
    userSelect.innerHTML = '<option value="">Izberite uporabnika</option>';
    
    if (window.assignmentUsers) {
        window.assignmentUsers.forEach(user => {
            userSelect.innerHTML += `<option value="${user.id}">${user.full_name} (@${user.username})</option>`;
        });
    }
    
    // Clear date
    document.getElementById('assignDueDate').value = '';
    
    // Show modal
    document.getElementById('assignChoreModal').classList.add('show');
}

function closeAssignChoreModal() {
    document.getElementById('assignChoreModal').classList.remove('show');
    currentAssignTemplateId = null;
}

async function assignChoreToUser() {
    if (!currentAssignTemplateId) return;
    
    const assignData = {
        template_id: currentAssignTemplateId,
        assigned_to: parseInt(document.getElementById('assignToUser').value),
        due_date: document.getElementById('assignDueDate').value || null
    };

    if (!assignData.assigned_to) {
        showNotification('Napaka', 'Prosim izberite uporabnika');
        return;
    }

    try {
        await apiCall('/api/assign-chore', 'POST', assignData);
        showNotification('Uspeh', 'Opravilo uspešno dodeljeno');
        closeAssignChoreModal();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri dodeljevanju opravila');
    }
}

// Utility functions
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        }
    };

    if (data) {
        options.body = JSON.stringify(data);
    }

    const response = await fetch(`${baseURL}${endpoint}`, options);
    const responseData = await response.json();

    if (!response.ok) {
        throw new Error(responseData.error || 'Napaka API klica');
    }

    return responseData;
}

function showError(message) {
    elements.loginError.textContent = message;
    elements.loginError.style.display = 'block';
    setTimeout(() => {
        elements.loginError.style.display = 'none';
    }, 5000);
}

function showNotification(title, message) {
    elements.notificationTitle.textContent = title;
    elements.notificationMessage.textContent = message;
    elements.notificationModal.classList.add('show');
}

function closeNotificationModal() {
    elements.notificationModal.classList.remove('show');
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 1) {
        return 'danes';
    } else if (diffDays === 2) {
        return 'včeraj';
    } else if (diffDays <= 7) {
        return `pred ${diffDays - 1} dnevi`;
    } else {
        return date.toLocaleDateString('sl-SI');
    }
}

// Chore Templates Management
async function loadChoreTemplates() {
    try {
        const templates = await apiCall('/api/chore-templates');
        renderChoreTemplates(templates);
    } catch (error) {
        console.error('Napaka pri nalaganju predlog:', error);
        document.getElementById('choreTemplatesList').innerHTML = '<p class="loading">Napaka pri nalaganju predlog</p>';
    }
}

function renderChoreTemplates(templates) {
    const list = document.getElementById('choreTemplatesList');
    
    if (templates.length === 0) {
        list.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);"><p>Ni predlog opravil.</p></div>';
        return;
    }

    list.innerHTML = templates.map(template => `
        <div class="template-card" style="background: var(--bg-secondary); border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 1rem;">
            <div class="template-header" style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                <div>
                    <h4 style="margin: 0 0 0.5rem 0;">${template.name}</h4>
                    ${template.description ? `<p style="color: var(--text-secondary); margin: 0;">${template.description}</p>` : ''}
                </div>
                <div class="template-actions" style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-sm btn-secondary" onclick="openEditChoreModal(${template.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteChoreTemplate(${template.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <div class="template-details" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                <span><i class="fas fa-coins"></i> ${template.points} točk</span>
                <span><i class="fas fa-minus-circle"></i> -${template.negative_points} kazni</span>
                <span><i class="fas fa-tag"></i> ${template.category}</span>
                <span><i class="fas fa-repeat"></i> ${template.frequency}</span>
                <span><i class="fas fa-clock"></i> ${template.time_limit_days} dni</span>
                <span><i class="fas fa-user"></i> Ustvaril: ${template.created_by_name || 'N/A'}</span>
            </div>
        </div>
    `).join('');
}

async function editChoreTemplate(templateId) {
    try {
        const templates = await apiCall('/api/chore-templates');
        const template = templates.find(t => t.id === templateId);
        
        if (template) {
            // Fill form with template data
            document.getElementById('choreName').value = template.name;
            document.getElementById('choreDescription').value = template.description || '';
            document.getElementById('chorePoints').value = template.points;
            document.getElementById('choreNegativePoints').value = template.negative_points;
            document.getElementById('choreCategory').value = template.category;
            document.getElementById('choreFrequency').value = template.frequency;
            document.getElementById('choreTimeLimit').value = template.time_limit_days;
            
            // Store template ID for update
            document.getElementById('createChoreTemplateForm').dataset.editId = templateId;
            document.querySelector('#createChoreTemplateForm button[type="submit"]').innerHTML = '<i class="fas fa-save"></i> Posodobi predlogo';
        }
    } catch (error) {
        showNotification('Napaka', 'Napaka pri nalaganju predloge');
    }
}

async function deleteChoreTemplate(templateId) {
    if (!confirm('Ali ste prepričani, da želite obrisati to predlogo?')) return;
    
    try {
        await apiCall(`/api/chore-templates/${templateId}`, 'DELETE');
        showNotification('Uspeh', 'Predloga uspešno obrisana');
        loadChoreTemplates();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri brisanju predloge');
    }
}

// Rewards Management
async function loadRewardsManagement() {
    try {
        const rewards = await apiCall('/api/rewards');
        renderRewardsManagement(rewards);
    } catch (error) {
        console.error('Napaka pri nalaganju nagrad:', error);
        document.getElementById('rewardsManagementList').innerHTML = '<p class="loading">Napaka pri nalaganju nagrad</p>';
    }
}

function renderRewardsManagement(rewards) {
    const list = document.getElementById('rewardsManagementList');
    
    if (rewards.length === 0) {
        list.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);"><p>Ni nagrad.</p></div>';
        return;
    }

    list.innerHTML = rewards.map(reward => `
        <div class="reward-management-card" style="background: var(--bg-secondary); border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 1rem;">
            <div class="reward-header" style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                <div style="display: flex; align-items: center; gap: 1rem;">
                    <div class="reward-icon" style="font-size: 2rem;">${reward.icon}</div>
                    <div>
                        <h4 style="margin: 0 0 0.5rem 0;">${reward.name}</h4>
                        ${reward.description ? `<p style="color: var(--text-secondary); margin: 0;">${reward.description}</p>` : ''}
                    </div>
                </div>
                <div class="reward-actions" style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-sm btn-secondary" onclick="openEditRewardModal(${reward.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteReward(${reward.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <div class="reward-details" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                <span><i class="fas fa-coins"></i> ${reward.cost} točk</span>
                <span><i class="fas fa-tag"></i> ${reward.category}</span>
                <span><i class="fas fa-eye"></i> ${reward.active ? 'Aktivna' : 'Neaktivna'}</span>
            </div>
        </div>
    `).join('');
}

async function editReward(rewardId) {
    try {
        const rewards = await apiCall('/api/rewards');
        const reward = rewards.find(r => r.id === rewardId);
        
        if (reward) {
            // Fill form with reward data
            document.getElementById('rewardName').value = reward.name;
            document.getElementById('rewardDescription').value = reward.description || '';
            document.getElementById('rewardCost').value = reward.cost;
            document.getElementById('rewardIcon').value = reward.icon;
            document.getElementById('rewardCategory').value = reward.category;
            
            // Store reward ID for update
            document.getElementById('createRewardForm').dataset.editId = rewardId;
            document.querySelector('#createRewardForm button[type="submit"]').innerHTML = '<i class="fas fa-save"></i> Posodobi nagrado';
        }
    } catch (error) {
        showNotification('Napaka', 'Napaka pri nalaganju nagrade');
    }
}

async function deleteReward(rewardId) {
    if (!confirm('Ali ste prepričani, da želite obrisati to nagrado?')) return;
    
    try {
        await apiCall(`/api/rewards/${rewardId}`, 'DELETE');
        showNotification('Uspeh', 'Nagrada uspešno obrisana');
        loadRewardsManagement();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri brisanju nagrade');
    }
}

async function handleCreateReward(e) {
    e.preventDefault();
    
    const formData = {
        name: document.getElementById('rewardName').value.trim(),
        description: document.getElementById('rewardDescription').value.trim(),
        cost: parseInt(document.getElementById('rewardCost').value),
        icon: document.getElementById('rewardIcon').value.trim() || '🎁',
        category: document.getElementById('rewardCategory').value
    };

    if (!formData.name || !formData.cost) {
        showNotification('Napaka', 'Prosim izpolnite vsa obvezna polja');
        return;
    }

    try {
        const editId = e.target.dataset.editId;
        const method = editId ? 'PUT' : 'POST';
        const endpoint = editId ? `/api/rewards/${editId}` : '/api/rewards';
        
        await apiCall(endpoint, method, formData);
        
        showNotification('Uspeh', editId ? 'Nagrada uspešno posodobljena' : 'Nagrada uspešno ustvarjena');
        
        // Reset form
        e.target.reset();
        delete e.target.dataset.editId;
        document.querySelector('#createRewardForm button[type="submit"]').innerHTML = '<i class="fas fa-plus"></i> Ustvari nagrado';
        
        loadRewardsManagement();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri upravljanju nagrade');
    }
}

// Update the handleCreateChoreTemplate function
async function handleCreateChoreTemplate(e) {
    e.preventDefault();

    const templateData = {
        name: document.getElementById('choreName').value,
        description: document.getElementById('choreDescription').value,
        points: parseInt(document.getElementById('chorePoints').value),
        negative_points: parseInt(document.getElementById('choreNegativePoints').value),
        category: document.getElementById('choreCategory').value,
        frequency: document.getElementById('choreFrequency').value,
        time_limit_days: parseInt(document.getElementById('choreTimeLimit').value)
    };

    try {
        const editId = e.target.dataset.editId;
        const method = editId ? 'PUT' : 'POST';
        const endpoint = editId ? `/api/chore-templates/${editId}` : '/api/chore-templates';
        
        await apiCall(endpoint, method, templateData);
        
        showNotification('Uspeh', editId ? 'Predloga uspešno posodobljena' : 'Predloga opravila uspešno ustvarjena');
        
        // Reset form
        e.target.reset();
        delete e.target.dataset.editId;
        document.querySelector('#createChoreTemplateForm button[type="submit"]').innerHTML = '<i class="fas fa-plus"></i> Ustvari predlogo';
        
        loadChoreTemplates();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri ustvarjanju predloge');
    }
}

// Statistics functionality
let currentStatsPeriod = 'week';

async function loadStatistics(period = 'week') {
    currentStatsPeriod = period;
    
    // Update period buttons
    document.querySelectorAll('.stats-period-buttons .filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.period === period);
    });

    try {
        const stats = await apiCall(`/api/user-stats?period=${period}`);
        renderStatistics(stats);
    } catch (error) {
        console.error('Napaka pri nalaganju statistik:', error);
        showNotification('Napaka', 'Napaka pri nalaganju statistik');
    }
}

function renderStatistics(stats) {
    // Update overview cards
    document.getElementById('statsCompleted').textContent = stats.overall.total_completed || 0;
    document.getElementById('statsPending').textContent = stats.pending.pending_count || 0;
    document.getElementById('statsPoints').textContent = stats.overall.total_points || 0;
    document.getElementById('statsHelped').textContent = stats.helpGiven.helped_others_count || 0;

    // Render category breakdown
    const categoryStatsEl = document.getElementById('categoryStats');
    
    if (stats.byCategory.length === 0) {
        categoryStatsEl.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">Ni podatkov za izbrano obdobje.</p>';
        return;
    }

    categoryStatsEl.innerHTML = stats.byCategory.map(category => `
        <div class="category-stat-item" style="background: var(--bg-secondary); padding: 1rem; border-radius: var(--radius-md); margin-bottom: 0.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h4 style="margin: 0 0 0.25rem 0;">${category.category}</h4>
                    <p style="margin: 0; color: var(--text-secondary); font-size: 0.875rem;">${category.frequency} • ${category.count_by_category} opravil</p>
                </div>
                <div style="text-align: right;">
                    <div style="color: var(--primary-color); font-weight: 600;">${category.total_points || 0} točk</div>
                    <div style="color: var(--text-secondary); font-size: 0.875rem;">povprečno ${Math.round(category.avg_points || 0)} točk</div>
                </div>
            </div>
        </div>
    `).join('');
}

// Leaderboard functionality
async function loadLeaderboard(period = 'week') {
    try {
        const data = await apiCall(`/api/all-users-stats?period=${period}`);
        renderLeaderboard(data.users);
    } catch (error) {
        console.error('Napaka pri nalaganju lestvice:', error);
        showNotification('Napaka', 'Napaka pri nalaganju lestvice');
    }
}

function renderLeaderboard(users) {
    const leaderboard = document.getElementById('leaderboard');
    
    if (users.length === 0) {
        leaderboard.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">Ni podatkov za lestvico.</p>';
        return;
    }

    leaderboard.innerHTML = users.map((user, index) => {
        const position = index + 1;
        const isCurrentUser = user.id === currentUser.id;
        
        // Medal/trophy for top 3
        let positionIcon = '';
        if (position === 1) positionIcon = '🥇';
        else if (position === 2) positionIcon = '🥈';
        else if (position === 3) positionIcon = '🥉';
        else positionIcon = `#${position}`;

        return `
            <div class="leaderboard-item ${isCurrentUser ? 'current-user' : ''}" style="
                background: ${isCurrentUser ? 'var(--primary-color)' : 'var(--bg-secondary)'};
                color: ${isCurrentUser ? 'white' : 'var(--text-primary)'};
                padding: 1rem 1.5rem;
                border-radius: var(--radius-md);
                margin-bottom: 0.5rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border: ${position <= 3 ? '2px solid var(--primary-color)' : '1px solid var(--border-color)'};
            ">
                <div class="leaderboard-left" style="display: flex; align-items: center; gap: 1rem;">
                    <div class="position" style="font-size: 1.5rem; font-weight: 600; min-width: 3rem;">
                        ${positionIcon}
                    </div>
                    <div class="user-details">
                        <h4 style="margin: 0; font-size: 1.1rem;">${user.full_name}</h4>
                        <div style="font-size: 0.875rem; opacity: 0.8;">
                            ${user.completed_count} opravljenih • ${user.pending_count} na čakanju • ${user.helped_others} pomagal
                        </div>
                    </div>
                </div>
                <div class="leaderboard-right" style="text-align: right;">
                    <div style="font-size: 1.5rem; font-weight: 600;">
                        ${user.points_earned || 0} točk
                    </div>
                    <div style="font-size: 0.875rem; opacity: 0.8;">
                        skupaj: ${user.total_lifetime_points || 0}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Others chores functionality
let currentOthersTab = 'pending';
let currentOthersUser = null;
let currentOthersPeriod = 'week';

async function loadOthersChores() {
    try {
        const response = await apiCall('/api/others-chores');
        
        if (!response.canHelpOthers) {
            document.getElementById('helpStatus').innerHTML = `
                <div class="help-blocked" style="background: var(--warning-color); color: white; padding: 1rem; border-radius: var(--radius-md); margin-bottom: 1rem;">
                    <i class="fas fa-exclamation-triangle"></i>
                    ${response.error}
                </div>
            `;
            document.getElementById('othersChoresList').innerHTML = '';
            return;
        }

        document.getElementById('helpStatus').innerHTML = `
            <div class="help-available" style="background: var(--success-color); color: white; padding: 1rem; border-radius: var(--radius-md); margin-bottom: 1rem;">
                <i class="fas fa-check-circle"></i>
                Odlično! Opravili ste vsa svoja opravila in lahko pomagate drugim.
            </div>
        `;

        renderOthersChores(response.chores);
    } catch (error) {
        console.error('Napaka pri nalaganju opravil drugih:', error);
        document.getElementById('helpStatus').innerHTML = `
            <div class="help-error" style="background: var(--danger-color); color: white; padding: 1rem; border-radius: var(--radius-md); margin-bottom: 1rem;">
                <i class="fas fa-times-circle"></i>
                Napaka pri nalaganju opravil.
            </div>
        `;
    }
}

async function loadUsersForOthersSection() {
    try {
        const data = await apiCall('/api/assignment-data');
        const userSelect = document.getElementById('userSelect');
        userSelect.innerHTML = '<option value="">Izberi uporabnika...</option>';
        
        data.users.forEach(user => {
            if (user.id !== currentUser.id) {
                userSelect.innerHTML += `<option value="${user.id}">${user.full_name}</option>`;
            }
        });
    } catch (error) {
        console.error('Napaka pri nalaganju uporabnikov:', error);
    }
}

async function loadOthersCompletedChores(userId, period = 'week') {
    if (!userId) {
        document.getElementById('othersCompletedList').innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Izberi uporabnika za prikaz opravljenih opravil.</p>';
        return;
    }

    try {
        const chores = await apiCall(`/api/others-completed-chores/${userId}?period=${period}`);
        renderOthersCompletedChores(chores);
    } catch (error) {
        console.error('Napaka pri nalaganju opravljenih opravil:', error);
        document.getElementById('othersCompletedList').innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Napaka pri nalaganju podatkov.</p>';
    }
}

function renderOthersCompletedChores(chores) {
    const completedList = document.getElementById('othersCompletedList');
    
    if (chores.length === 0) {
        completedList.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Ni opravljenih opravil v tem obdobju.</p>';
        return;
    }

    // Group by frequency
    const groupedChores = {
        'once': chores.filter(c => c.frequency === 'once'),
        'daily': chores.filter(c => c.frequency === 'daily'),
        'weekly': chores.filter(c => c.frequency === 'weekly'),
        'monthly': chores.filter(c => c.frequency === 'monthly')
    };

    const frequencyLabels = {
        'once': '📅 Enkratna opravila',
        'daily': '🔄 Dnevna opravila',
        'weekly': '📊 Tedenska opravila',
        'monthly': '📈 Mesečna opravila'
    };

    let html = '';

    Object.keys(groupedChores).forEach(frequency => {
        const choreGroup = groupedChores[frequency];
        if (choreGroup.length > 0) {
            html += `
                <div class="chore-group" style="margin-bottom: 2rem;">
                    <h4 class="chore-group-title" style="color: var(--primary-color); margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--primary-color);">
                        ${frequencyLabels[frequency]} (${choreGroup.length})
                    </h4>
                    <div class="chore-group-items">
                        ${choreGroup.map(chore => `
                            <div class="completed-chore-item" style="background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 1rem; margin-bottom: 0.5rem;">
                                <div class="chore-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                                    <h5 style="margin: 0;">${chore.name}</h5>
                                    <div style="display: flex; align-items: center; gap: 1rem;">
                                        <span class="chore-points" style="background: var(--success-color); color: white; padding: 0.25rem 0.75rem; border-radius: var(--radius-sm); font-size: 0.875rem;">
                                            ${chore.points} točk
                                        </span>
                                        ${chore.completed_by_name && chore.completed_by_name !== chore.assigned_to_name ? `
                                            <span style="color: var(--primary-color); font-size: 0.875rem;">
                                                <i class="fas fa-hands-helping"></i> ${chore.completed_by_name}
                                            </span>
                                        ` : ''}
                                    </div>
                                </div>
                                ${chore.description ? `<p style="margin-bottom: 0.5rem; color: var(--text-secondary);">${chore.description}</p>` : ''}
                                <div class="chore-meta" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                                    <span><i class="fas fa-tag"></i> ${chore.category}</span>
                                    <span><i class="fas fa-calendar-check"></i> ${formatDate(chore.completed_at)}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
    });

    completedList.innerHTML = html || '<p style="text-align: center; color: var(--text-secondary);">Ni opravil v tej kategoriji.</p>';
}

function renderOthersChores(chores) {
    const choresList = document.getElementById('othersChoresList');
    
    if (chores.length === 0) {
        choresList.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                <i class="fas fa-smile" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                <p>Vsi uporabniki so opravili svoja opravila! 🎉</p>
            </div>
        `;
        return;
    }

    // Group by user
    const groupedByUser = {};
    chores.forEach(chore => {
        if (!groupedByUser[chore.assigned_to_name]) {
            groupedByUser[chore.assigned_to_name] = [];
        }
        groupedByUser[chore.assigned_to_name].push(chore);
    });

    choresList.innerHTML = Object.keys(groupedByUser).map(userName => `
        <div class="user-chores-group" style="margin-bottom: 2rem;">
            <h3 style="color: var(--primary-color); margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--primary-color);">
                👤 ${userName} (${groupedByUser[userName].length} opravil)
            </h3>
            <div class="user-chores-list">
                ${groupedByUser[userName].map(chore => `
                    <div class="other-chore-item" style="background: var(--bg-secondary); border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 1rem; border: 1px solid var(--border-color);">
                        <div class="chore-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                            <h4 style="margin: 0;">${chore.name}</h4>
                            <div style="display: flex; align-items: center; gap: 1rem;">
                                <span class="chore-points" style="background: var(--primary-color); color: white; padding: 0.25rem 0.75rem; border-radius: var(--radius-sm); font-size: 0.875rem;">
                                    ${chore.points} točk → vi ${Math.floor(chore.points * 0.7)} točk
                                </span>
                                <button class="btn btn-primary btn-sm" onclick="helpWithChore(${chore.id})">
                                    <i class="fas fa-hands-helping"></i>
                                    Pomagaj
                                </button>
                            </div>
                        </div>
                        ${chore.description ? `<p style="margin-bottom: 1rem; color: var(--text-secondary);">${chore.description}</p>` : ''}
                        <div class="chore-meta" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                            <span><i class="fas fa-tag"></i> ${chore.category}</span>
                            <span><i class="fas fa-clock"></i> ${formatDate(chore.due_date)}</span>
                            <span><i class="fas fa-repeat"></i> ${chore.frequency}</span>
                            ${chore.assigned_by_name ? `<span><i class="fas fa-user"></i> Dodeljeno: ${chore.assigned_by_name}</span>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

async function helpWithChore(choreId) {
    if (!confirm('Ali ste prepričani, da želite opraviti to opravilo za svojega sorodnika?')) return;
    
    try {
        const response = await apiCall(`/api/complete-chore-for-other/${choreId}`, 'POST');
        showNotification('Odlično!', response.message);
        
        // Refresh data
        loadDashboardData();
        loadOthersChores();
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri opravljanju opravila');
    }
}

// Icon picker functionality
const availableIcons = [
    '🎁', '🏆', '🎮', '🎬', '🍕', '🍔', '🍟', '🌮', '🍺', '☕', '🍰', '🍪', '🍫', '🍭',
    '🎵', '🎸', '🎤', '🎧', '📚', '📖', '✏️', '🖊️', '📝', '🎨', '🖼️', '🏃', '🚴', '🏊',
    '⚽', '🏀', '🎾', '🏐', '🏓', '🎯', '🎲', '🧩', '🃏', '🎪', '🎭', '🎨', '🎪', '🎢',
    '🏠', '🏡', '🏢', '🏣', '🏤', '🏥', '🏦', '🏧', '🏨', '🏩', '🏪', '🏫', '🏬', '🏭',
    '🚗', '🚕', '🚙', '🚌', '🚎', '🚐', '🚑', '🚒', '🚓', '🚔', '🚘', '🚖', '🚆', '🚇',
    '✈️', '🚀', '🛸', '🚁', '🛥️', '⛵', '🚤', '🚢', '⚓', '🏖️', '🏝️', '🗻', '🏔️', '🗾',
    '🌟', '⭐', '🌠', '🌙', '☀️', '⛅', '☁️', '🌈', '❄️', '⛄', '🔥', '💧', '🌊', '💎',
    '💰', '💵', '💴', '💶', '💷', '💳', '💸', '🏪', '🛒', '🛍️', '🎁', '🎀', '🎉', '🎊',
    '❤️', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💕', '💖', '💗', '💘', '💝', '💞',
    '🔧', '🔨', '⚒️', '🛠️', '⚙️', '🔩', '⚡', '🔋', '🔌', '💡', '🔦', '🕯️', '🧹', '🧽'
];

let currentIconTarget = null;

function openIconPicker(targetInputId) {
    currentIconTarget = targetInputId;
    
    const iconsGrid = document.getElementById('iconsGrid');
    iconsGrid.innerHTML = availableIcons.map(icon => `
        <button class="icon-option" onclick="selectIcon('${icon}')" style="
            border: none; 
            background: var(--bg-secondary); 
            padding: 0.75rem; 
            border-radius: var(--radius-sm); 
            font-size: 1.5rem; 
            cursor: pointer; 
            transition: all 0.2s ease;
            margin: 0.25rem;
        " onmouseover="this.style.background='var(--primary-color)'; this.style.transform='scale(1.1)'" 
           onmouseout="this.style.background='var(--bg-secondary)'; this.style.transform='scale(1)'">
            ${icon}
        </button>
    `).join('');
    
    document.getElementById('iconSearch').value = '';
    document.getElementById('iconPickerModal').classList.add('show');
}

function closeIconPicker() {
    document.getElementById('iconPickerModal').classList.remove('show');
    currentIconTarget = null;
}

function selectIcon(icon) {
    if (currentIconTarget) {
        document.getElementById(currentIconTarget).value = icon;
    }
    closeIconPicker();
}

function filterIcons() {
    const searchTerm = document.getElementById('iconSearch').value.toLowerCase();
    const iconsGrid = document.getElementById('iconsGrid');
    
    // Simple keyword mapping for Slovenian
    const iconKeywords = {
        'darilo': ['🎁', '🎀', '🎉'],
        'hrana': ['🍕', '🍔', '🍟', '🌮', '🍰', '🍪'],
        'zabava': ['🎮', '🎬', '🎵', '🎸', '🎤'],
        'šport': ['🏃', '🚴', '🏊', '⚽', '🏀', '🎾'],
        'dom': ['🏠', '🏡', '🔧', '🔨', '🧹'],
        'transport': ['🚗', '✈️', '🚀', '🚁'],
        'narava': ['🌟', '☀️', '🌈', '🔥', '💧'],
        'denar': ['💰', '💵', '💳', '💎'],
        'srce': ['❤️', '💛', '💚', '💙', '💜']
    };
    
    let filteredIcons = availableIcons;
    
    if (searchTerm) {
        // Check keyword mapping first
        const matchedKeywords = Object.keys(iconKeywords).filter(keyword => 
            keyword.includes(searchTerm)
        );
        
        if (matchedKeywords.length > 0) {
            filteredIcons = matchedKeywords.flatMap(keyword => iconKeywords[keyword]);
        } else {
            // If no keyword match, show all (can't really search emoji by text)
            filteredIcons = availableIcons;
        }
    }
    
    iconsGrid.innerHTML = filteredIcons.map(icon => `
        <button class="icon-option" onclick="selectIcon('${icon}')" style="
            border: none; 
            background: var(--bg-secondary); 
            padding: 0.75rem; 
            border-radius: var(--radius-sm); 
            font-size: 1.5rem; 
            cursor: pointer; 
            transition: all 0.2s ease;
            margin: 0.25rem;
        " onmouseover="this.style.background='var(--primary-color)'; this.style.transform='scale(1.1)'" 
           onmouseout="this.style.background='var(--bg-secondary)'; this.style.transform='scale(1)'">
            ${icon}
        </button>
    `).join('');
}

// Event listeners for statistics period buttons
document.addEventListener('DOMContentLoaded', function() {
            // Add event listeners for period buttons in statistics
        setTimeout(() => {
            const periodButtons = document.querySelectorAll('.stats-period-buttons .filter-btn');
            periodButtons.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const period = e.currentTarget.dataset.period;
                    loadStatistics(period);
                    loadLeaderboard(period);
                });
            });

            // Assignment tabs
            const assignmentTabs = document.querySelectorAll('.assignment-tabs .filter-btn');
            assignmentTabs.forEach(tab => {
                tab.addEventListener('click', (e) => {
                    const tabName = e.currentTarget.dataset.tab;
                    
                    // Update active tab
                    assignmentTabs.forEach(t => t.classList.remove('active'));
                    e.currentTarget.classList.add('active');
                    
                    // Show/hide content
                    document.querySelectorAll('.assignment-tab-content').forEach(content => {
                        content.classList.remove('active');
                    });
                    
                    if (tabName === 'oneTime') {
                        document.getElementById('oneTimeAssignmentTab').classList.add('active');
                    } else if (tabName === 'recurring') {
                        document.getElementById('recurringAssignmentTab').classList.add('active');
                        loadRecurringAssignmentData();
                    }
                });
            });

            // Others tabs
            const othersTabs = document.querySelectorAll('.others-tabs .filter-btn');
            othersTabs.forEach(tab => {
                tab.addEventListener('click', (e) => {
                    const tabName = e.currentTarget.dataset.tab;
                    
                    // Update active tab
                    othersTabs.forEach(t => t.classList.remove('active'));
                    e.currentTarget.classList.add('active');
                    
                    // Show/hide content
                    document.querySelectorAll('.others-tab-content').forEach(content => {
                        content.classList.remove('active');
                    });
                    
                    if (tabName === 'pending') {
                        document.getElementById('othersPendingTab').classList.add('active');
                        loadOthersChores();
                    } else if (tabName === 'completed') {
                        document.getElementById('othersCompletedTab').classList.add('active');
                    }
                });
            });

            // User select change
            const userSelect = document.getElementById('userSelect');
            if (userSelect) {
                userSelect.addEventListener('change', (e) => {
                    const userId = e.target.value;
                    currentOthersUser = userId;
                    if (userId) {
                        loadOthersCompletedChores(userId, currentOthersPeriod);
                    }
                });
            }

            // Others completed period buttons
            const othersPeriodButtons = document.querySelectorAll('#othersCompletedTab .period-buttons .filter-btn');
            othersPeriodButtons.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const period = e.currentTarget.dataset.period;
                    currentOthersPeriod = period;
                    
                    // Update active button
                    othersPeriodButtons.forEach(b => b.classList.remove('active'));
                    e.currentTarget.classList.add('active');
                    
                    if (currentOthersUser) {
                        loadOthersCompletedChores(currentOthersUser, period);
                    }
                });
            });
        }, 100);
});

// Recurring assignment functionality
async function loadRecurringAssignmentData() {
    try {
        const assignmentStatus = await apiCall('/api/assignment-status');
        const data = await apiCall('/api/assignment-data');
        
        renderUnassignedTemplates(assignmentStatus.unassigned);
        renderAssignedTemplates(assignmentStatus.assigned);
        populateRecurringUserSelects(data.users);
    } catch (error) {
        console.error('Napaka pri nalaganju podatkov za ponavljajoče dodeljevanje:', error);
        showNotification('Napaka', 'Napaka pri nalaganju podatkov');
    }
}

function renderUnassignedTemplates(templates) {
    const container = document.getElementById('unassignedTemplates');
    
    if (templates.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Vse ponavljajoče naloge so že dodeljene.</p>';
        return;
    }

    container.innerHTML = templates.map(template => `
        <div class="template-card" style="background: var(--bg-secondary); border-radius: var(--radius-md); padding: 1.5rem; border: 1px solid var(--border-color); margin-bottom: 1rem;">
            <div class="template-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                <div>
                    <h4 style="margin: 0 0 0.5rem 0;">${template.name}</h4>
                    ${template.description ? `<p style="margin: 0; color: var(--text-secondary);">${template.description}</p>` : ''}
                </div>
                <button class="btn btn-primary btn-sm" onclick="openAssignRecurringModal(${template.id}, '${template.name}')">
                    <i class="fas fa-user-plus"></i>
                    Dodeli
                </button>
            </div>
            <div class="template-details" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                <span><i class="fas fa-tag"></i> ${template.category}</span>
                <span><i class="fas fa-repeat"></i> ${template.frequency}</span>
                <span><i class="fas fa-coins"></i> ${template.points} točk</span>
            </div>
        </div>
    `).join('');
}

function renderAssignedTemplates(templates) {
    const container = document.getElementById('assignedTemplates');
    
    if (templates.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Ni dodeljenih ponavljajočih nalog.</p>';
        return;
    }

    container.innerHTML = templates.map(template => `
        <div class="template-card" style="background: var(--bg-secondary); border-radius: var(--radius-md); padding: 1.5rem; border: 1px solid var(--border-color); margin-bottom: 1rem;">
            <div class="template-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                <div>
                    <h4 style="margin: 0 0 0.5rem 0;">${template.name}</h4>
                    ${template.description ? `<p style="margin: 0; color: var(--text-secondary);">${template.description}</p>` : ''}
                    <p style="margin: 0.5rem 0 0 0; color: var(--primary-color); font-weight: 600;">
                        <i class="fas fa-user"></i> Dodeljeno: ${template.assigned_to_name}
                    </p>
                </div>
                <div style="display: flex; gap: 0.5rem; flex-direction: column;">
                    <button class="btn btn-secondary btn-sm" onclick="openAssignRecurringModal(${template.id}, '${template.name}', ${template.assigned_to})">
                        <i class="fas fa-user-edit"></i>
                        Zamenjaj
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="removeRecurringAssignment(${template.id}, '${template.name}')">
                        <i class="fas fa-user-times"></i>
                        Odstrani
                    </button>
                </div>
            </div>
            <div class="template-details" style="display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                <span><i class="fas fa-tag"></i> ${template.category}</span>
                <span><i class="fas fa-repeat"></i> ${template.frequency}</span>
                <span><i class="fas fa-coins"></i> ${template.points} točk</span>
            </div>
        </div>
    `).join('');
}

function populateRecurringUserSelects(users) {
    const select = document.getElementById('recurringAssignToUser');
    select.innerHTML = '<option value="">Izberite uporabnika</option>';
    
    users.forEach(user => {
        select.innerHTML += `<option value="${user.id}">${user.full_name}</option>`;
    });
}

// Modal functions for recurring assignment
let currentRecurringTemplateId = null;

function openAssignRecurringModal(templateId, templateName, currentUserId = null) {
    currentRecurringTemplateId = templateId;
    
    document.getElementById('assignRecurringTitle').textContent = 
        currentUserId ? `Zamenjaj dodelitev: ${templateName}` : `Dodeli ponavljajočo nalogo: ${templateName}`;
    
    if (currentUserId) {
        document.getElementById('recurringAssignToUser').value = currentUserId;
    } else {
        document.getElementById('recurringAssignToUser').value = '';
    }
    
    document.getElementById('assignRecurringModal').classList.add('show');
}

function closeAssignRecurringModal() {
    document.getElementById('assignRecurringModal').classList.remove('show');
    currentRecurringTemplateId = null;
}

async function assignRecurringTemplate() {
    const userId = document.getElementById('recurringAssignToUser').value;
    
    if (!userId || !currentRecurringTemplateId) {
        showNotification('Napaka', 'Prosimo, izberite uporabnika.');
        return;
    }

    try {
        await apiCall(`/api/assign-recurring/${currentRecurringTemplateId}`, 'POST', { userId });
        showNotification('Uspeh', 'Ponavljajoča naloga je bila uspešno dodeljena.');
        closeAssignRecurringModal();
        loadRecurringAssignmentData(); // Refresh the data
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri dodeljevanju ponavljajoče naloge.');
    }
}

async function removeRecurringAssignment(templateId, templateName) {
    if (!confirm(`Ali ste prepričani, da želite odstraniti avtomatsko dodeljevanje za "${templateName}"?`)) {
        return;
    }

    try {
        await apiCall(`/api/assign-recurring/${templateId}`, 'DELETE');
        showNotification('Uspeh', 'Avtomatska dodelitev je bila odstranjena.');
        loadRecurringAssignmentData(); // Refresh the data
    } catch (error) {
        showNotification('Napaka', error.message || 'Napaka pri odstranjevanju dodelitve.');
    }
}

// Advanced Charts Functionality
let currentCharts = {};

async function loadAdvancedCharts(period = 'week') {
    // Destroy existing charts
    Object.values(currentCharts).forEach(chart => {
        if (chart) chart.destroy();
    });
    currentCharts = {};

    // Load trend chart by default
    await loadPointsTrendChart(period);
}

async function loadPointsTrendChart(period = 'week') {
    try {
        const data = await apiCall(`/api/analytics/points-trend?period=${period}`);
        
        const ctx = document.getElementById('pointsTrendChart').getContext('2d');
        
        // Prepare data
        const labels = data.map(item => {
            const date = new Date(item.date);
            return period === 'year' ? 
                date.toLocaleDateString('sl-SI', { year: 'numeric', month: 'short' }) :
                date.toLocaleDateString('sl-SI', { month: 'short', day: 'numeric' });
        });
        
        const pointsData = data.map(item => item.points || 0);
        const completedData = data.map(item => item.completed_count || 0);

        currentCharts.pointsTrend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Pridobljene točke',
                        data: pointsData,
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Opravljenih opravil',
                        data: completedData,
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        fill: false,
                        tension: 0.4,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                scales: {
                    x: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Datum'
                        }
                    },
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {
                            display: true,
                            text: 'Točke'
                        }
                    },
                    y1: {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {
                            display: true,
                            text: 'Št. opravil'
                        },
                        grid: {
                            drawOnChartArea: false,
                        },
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Napredek skozi čas'
                    },
                    legend: {
                        display: true
                    }
                }
            }
        });
    } catch (error) {
        console.error('Napaka pri nalaganju trend grafikona:', error);
    }
}

async function loadCategoryChart(period = 'week') {
    try {
        const data = await apiCall(`/api/analytics/category-distribution?period=${period}`);
        
        const ctx = document.getElementById('categoryPieChart').getContext('2d');
        
        const colors = [
            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
            '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1'
        ];

        currentCharts.categoryPie = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.map(item => item.category),
                datasets: [{
                    data: data.map(item => item.completed_count),
                    backgroundColor: colors.slice(0, data.length),
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Opravljenih opravil po kategorijah'
                    },
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${label}: ${value} opravil (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Napaka pri nalaganju kategory grafikona:', error);
    }
}

async function loadProductivityChart(period = 'week') {
    try {
        const data = await apiCall(`/api/analytics/weekly-productivity?period=${period}`);
        
        const ctx = document.getElementById('weeklyProductivityChart').getContext('2d');
        
        // Ensure all days are represented
        const allDays = [
            { day_name: 'Nedelja', day_number: 0 },
            { day_name: 'Ponedeljek', day_number: 1 },
            { day_name: 'Torek', day_number: 2 },
            { day_name: 'Sreda', day_number: 3 },
            { day_name: 'Četrtek', day_number: 4 },
            { day_name: 'Petek', day_number: 5 },
            { day_name: 'Sobota', day_number: 6 }
        ];

        const chartData = allDays.map(day => {
            const found = data.find(d => d.day_number === day.day_number);
            return {
                day_name: day.day_name,
                completed_count: found ? found.completed_count : 0,
                total_points: found ? found.total_points : 0
            };
        });

        currentCharts.productivity = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: chartData.map(item => item.day_name),
                datasets: [
                    {
                        label: 'Opravljenih opravil',
                        data: chartData.map(item => item.completed_count),
                        backgroundColor: 'rgba(59, 130, 246, 0.8)',
                        borderColor: '#3b82f6',
                        borderWidth: 1,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Pridobljenih točk',
                        data: chartData.map(item => item.total_points),
                        backgroundColor: 'rgba(16, 185, 129, 0.8)',
                        borderColor: '#10b981',
                        borderWidth: 1,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {
                            display: true,
                            text: 'Št. opravil'
                        }
                    },
                    y1: {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {
                            display: true,
                            text: 'Točke'
                        },
                        grid: {
                            drawOnChartArea: false,
                        },
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Produktivnost po dnevih v tednu'
                    }
                }
            }
        });
    } catch (error) {
        console.error('Napaka pri nalaganju productivity grafikona:', error);
    }
}

async function loadActivityHeatmap() {
    try {
        const data = await apiCall('/api/analytics/activity-heatmap');
        
        const container = document.getElementById('activityHeatmap');
        container.innerHTML = ''; // Clear existing content
        
        if (data.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Ni podatkov za prikaz.</p>';
            return;
        }

        // Create heatmap
        const maxActivity = Math.max(...data.map(d => d.activity_count));
        const today = new Date();
        const startDate = new Date(today);
        startDate.setDate(startDate.getDate() - 90);

        let html = '<div class="heatmap-grid" style="display: grid; grid-template-columns: repeat(13, 1fr); gap: 3px; max-width: 800px;">';
        
        // Generate last 90 days
        for (let i = 0; i < 90; i++) {
            const currentDate = new Date(startDate);
            currentDate.setDate(startDate.getDate() + i);
            const dateStr = currentDate.toISOString().split('T')[0];
            
            const dayData = data.find(d => d.date === dateStr);
            const activity = dayData ? dayData.activity_count : 0;
            const points = dayData ? dayData.points : 0;
            
            // Calculate intensity (0-4 levels)
            const intensity = maxActivity > 0 ? Math.min(4, Math.floor((activity / maxActivity) * 4)) : 0;
            
            html += `
                <div class="heatmap-day" 
                     style="
                        width: 12px; 
                        height: 12px; 
                        background-color: ${getHeatmapColor(intensity)}; 
                        border-radius: 2px;
                        cursor: pointer;
                     " 
                     title="${dateStr}: ${activity} opravil, ${points} točk"
                     data-date="${dateStr}"
                     data-activity="${activity}"
                     data-points="${points}">
                </div>
            `;
        }
        
        html += '</div>';
        html += `
            <div class="heatmap-legend" style="display: flex; align-items: center; gap: 0.5rem; margin-top: 1rem; font-size: 0.875rem;">
                <span>Manj</span>
                ${[0,1,2,3,4].map(level => 
                    `<div style="width: 12px; height: 12px; background-color: ${getHeatmapColor(level)}; border-radius: 2px;"></div>`
                ).join('')}
                <span>Več</span>
            </div>
        `;
        
        container.innerHTML = html;
        
    } catch (error) {
        console.error('Napaka pri nalaganju heatmap:', error);
    }
}

function getHeatmapColor(intensity) {
    const colors = [
        '#ebedf0', // Level 0 - no activity
        '#9be9a8', // Level 1 - low activity  
        '#40c463', // Level 2 - medium activity
        '#30a14e', // Level 3 - high activity
        '#216e39'  // Level 4 - very high activity
    ];
    return colors[intensity] || colors[0];
}

async function loadPerformanceCharts(period = 'week') {
    try {
        const data = await apiCall(`/api/analytics/performance?period=${period}`);
        
        // Completion Rate Chart
        const completionCtx = document.getElementById('completionRateChart').getContext('2d');
        currentCharts.completionRate = new Chart(completionCtx, {
            type: 'doughnut',
            data: {
                labels: ['Opravljeno', 'Ostalo'],
                datasets: [{
                    data: [data.user.completion_rate, 100 - data.user.completion_rate],
                    backgroundColor: ['#10b981', '#e5e7eb'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.label + ': ' + context.parsed.toFixed(1) + '%';
                            }
                        }
                    }
                },
                cutout: '70%'
            }
        });

        // Average Points Chart
        const avgPointsCtx = document.getElementById('averagePointsChart').getContext('2d');
        currentCharts.avgPoints = new Chart(avgPointsCtx, {
            type: 'bar',
            data: {
                labels: ['Tvoje', 'Povprečje'],
                datasets: [{
                    data: [data.user.avg_points_per_task, data.average.avg_points_per_task],
                    backgroundColor: ['#3b82f6', '#94a3b8'],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });

        // Streak Chart (simple number display)
        const streakCtx = document.getElementById('streakChart').getContext('2d');
        currentCharts.streak = new Chart(streakCtx, {
            type: 'doughnut',
            data: {
                labels: ['Doseženo', 'Do cilja'],
                datasets: [{
                    data: [data.user.longest_streak, Math.max(0, 7 - data.user.longest_streak)],
                    backgroundColor: ['#f59e0b', '#e5e7eb'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                if (context.dataIndex === 0) {
                                    return 'Najdaljši niz: ' + context.parsed + ' dni';
                                }
                                return '';
                            }
                        }
                    }
                },
                cutout: '70%'
            }
        });

    } catch (error) {
        console.error('Napaka pri nalaganju performance grafikov:', error);
    }
}

// Chart tab switching
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(() => {
        // Chart tabs
        const chartTabs = document.querySelectorAll('.chart-tabs .filter-btn');
        chartTabs.forEach(tab => {
            tab.addEventListener('click', async (e) => {
                const chartType = e.currentTarget.dataset.chart;
                
                // Update active tab
                chartTabs.forEach(t => t.classList.remove('active'));
                e.currentTarget.classList.add('active');
                
                // Show/hide chart sections
                document.querySelectorAll('.chart-section').forEach(section => {
                    section.classList.remove('active');
                });
                
                const targetSection = document.getElementById(`${chartType}Chart`);
                if (targetSection) {
                    targetSection.classList.add('active');
                }
                
                // Load appropriate chart
                const currentPeriod = document.querySelector('.stats-period-buttons .filter-btn.active')?.dataset.period || 'week';
                
                switch(chartType) {
                    case 'trend':
                        await loadPointsTrendChart(currentPeriod);
                        break;
                    case 'categories':
                        await loadCategoryChart(currentPeriod);
                        break;
                    case 'productivity':
                        await loadProductivityChart(currentPeriod);
                        break;
                    case 'heatmap':
                        await loadActivityHeatmap();
                        break;
                    case 'performance':
                        await loadPerformanceCharts(currentPeriod);
                        break;
                }
            });
        });

        // Update stats period buttons to also reload charts
        const periodButtons = document.querySelectorAll('.stats-period-buttons .filter-btn');
        periodButtons.forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const period = e.currentTarget.dataset.period;
                
                // Reload charts for current active chart type
                const activeChartTab = document.querySelector('.chart-tabs .filter-btn.active');
                const chartType = activeChartTab?.dataset.chart || 'trend';
                
                switch(chartType) {
                    case 'trend':
                        await loadPointsTrendChart(period);
                        break;
                    case 'categories':
                        await loadCategoryChart(period);
                        break;
                    case 'productivity':
                        await loadProductivityChart(period);
                        break;
                    case 'performance':
                        await loadPerformanceCharts(period);
                        break;
                    // Heatmap doesn't use period
                }
            });
        });
    }, 200);
});

// Keep old functions for backwards compatibility (deprecated)
async function editChoreTemplate(templateId) {
    return openEditChoreModal(templateId);
}

async function editReward(rewardId) {
    return openEditRewardModal(rewardId);
}

// Global functions for onclick handlers
window.completeChore = completeChore;
window.redeemReward = redeemReward;
window.closeNotificationModal = closeNotificationModal;
window.editChoreTemplate = editChoreTemplate;
window.deleteChoreTemplate = deleteChoreTemplate;
window.editReward = editReward;
window.deleteReward = deleteReward;
window.openEditChoreModal = openEditChoreModal;
window.closeEditChoreModal = closeEditChoreModal;
window.saveChoreTemplate = saveChoreTemplate;
window.openEditRewardModal = openEditRewardModal;
window.closeEditRewardModal = closeEditRewardModal;
window.saveReward = saveReward;
window.openAssignChoreModal = openAssignChoreModal;
window.closeAssignChoreModal = closeAssignChoreModal;
window.assignChoreToUser = assignChoreToUser;
