const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super-secret-key-change-in-production';

// Express Middleware
app.use(express.json());
app.use(cors());

// --- IN-MEMORY DATA STORAGE (Acts as our Database) ---
const users = [];
const teams = [];
const tasks = [];

// Seed Initial Data for instant testing
const hashedAdminPassword = bcrypt.hashSync('admin123', 10);
const hashedUserPassword = bcrypt.hashSync('user123', 10);

users.push(
  { id: 1, name: 'Alice Admin', email: 'admin@task.com', password: hashedAdminPassword, role: 'Admin', teamId: 1 },
  { id: 2, name: 'Bob Developer', email: 'dev@task.com', password: hashedUserPassword, role: 'Member', teamId: 1 }
);

teams.push({ id: 1, name: 'Alpha Engineering Team' });

tasks.push(
  { id: 1, title: 'Set up cloud database', description: 'Configure PostgreSQL production instance on Render.', status: 'To Do', priority: 'High', assignedTo: 2, teamId: 1 },
  { id: 2, title: 'Implement JWT logic', description: 'Secure endpoints using standard header checks.', status: 'In Progress', priority: 'Medium', assignedTo: 1, teamId: 1 },
  { id: 3, title: 'Design system layout', description: 'Draft components using basic Tailwind grid.', status: 'Done', priority: 'Low', assignedTo: 2, teamId: 1 }
);

// --- SECURITY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Permission denied. Level insufficient.' });
    }
    next();
  };
};

// --- AUTHENTICATION API ROUTES ---
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role, teamId } = req.body;
  if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email already exists' });

  const newUser = {
    id: users.length + 1,
    name,
    email,
    password: bcrypt.hashSync(password, 10),
    role: role || 'Member',
    teamId: teamId ? parseInt(teamId) : 1
  };
  users.push(newUser);
  res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role, teamId: user.teamId }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token, user: { name: user.name, email: user.email, role: user.role, teamId: user.teamId } });
});

// --- TASK CRUD ROUTES ---
app.get('/api/tasks', authenticateToken, (req, res) => {
  // Users only see tasks belonging to their team
  let filteredTasks = tasks.filter(t => t.teamId === req.user.teamId);
  res.json(filteredTasks);
});

app.post('/api/tasks', authenticateToken, authorizeRole(['Admin']), (req, res) => {
  const { title, description, status, priority, assignedTo } = req.body;
  const newTask = {
    id: tasks.length + 1,
    title,
    description,
    status: status || 'To Do',
    priority: priority || 'Medium',
    assignedTo: assignedTo ? parseInt(assignedTo) : req.user.id,
    teamId: req.user.teamId
  };
  tasks.push(newTask);
  res.status(201).json(newTask);
});

app.put('/api/tasks/:id', authenticateToken, (req, res) => {
  const task = tasks.find(t => t.id === parseInt(req.params.id));
  if (!task) return res.status(404).json({ error: 'Task not found' });
  if (task.teamId !== req.user.teamId) return res.status(403).json({ error: 'Unauthorized asset access' });

  // Regular users can only update task status; Admins can update everything
  if (req.user.role === 'Admin') {
    task.title = req.body.title || task.title;
    task.description = req.body.description || task.description;
    task.priority = req.body.priority || task.priority;
    task.assignedTo = req.body.assignedTo ? parseInt(req.body.assignedTo) : task.assignedTo;
  }
  task.status = req.body.status || task.status;

  res.json(task);
});

app.delete('/api/tasks/:id', authenticateToken, authorizeRole(['Admin']), (req, res) => {
  const index = tasks.findIndex(t => t.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Task not found' });
  
  tasks.splice(index, 1);
  res.json({ message: 'Task deleted successfully' });
});

// --- USER DIRECTORY ROUTE ---
app.get('/api/users', authenticateToken, (req, res) => {
  res.json(users.filter(u => u.teamId === req.user.teamId).map(u => ({ id: u.id, name: u.name, role: u.role })));
});

// --- FRONTEND EMBEDDED DELIVERY ---
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>FlowTask Enterprise</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-gray-100 min-h-screen font-sans">
      <div id="app" class="p-6"></div>

      <script>
        const state = {
          token: localStorage.getItem('token') || null,
          user: JSON.parse(localStorage.getItem('user')) || null,
          tasks: [],
          users: [],
          activeView: 'dashboard'
        };

        const api = {
          async request(endpoint, options = {}) {
            options.headers = options.headers || {};
            if (state.token) options.headers['Authorization'] = 'Bearer ' + state.token;
            options.headers['Content-Type'] = 'application/json';
            
            const response = await fetch('/api' + endpoint, options);
            if (!response.ok) {
              const errData = await response.json();
              throw new Error(errData.error || 'API Error');
            }
            return response.json();
          }
        };

        function logout() {
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          state.token = null;
          state.user = null;
          render();
        }

        async function handleLogin(e) {
          e.preventDefault();
          const email = e.target.email.value;
          const password = e.target.password.value;
          try {
            const data = await api.request('/auth/login', {
              method: 'POST',
              body: JSON.stringify({ email, password })
            });
            state.token = data.token;
            state.user = data.user;
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            await loadDashboardData();
            render();
          } catch (err) {
            alert(err.message);
          }
        }

        async function loadDashboardData() {
          if (!state.token) return;
          try {
            state.tasks = await api.request('/tasks');
            state.users = await api.request('/users');
          } catch(err) {
            console.error(err);
          }
        }

        async function createTask(e) {
          e.preventDefault();
          const body = {
            title: e.target.title.value,
            description: e.target.description.value,
            priority: e.target.priority.value,
            assignedTo: e.target.assignedTo.value
          };
          try {
            await api.request('/tasks', { method: 'POST', body: JSON.stringify(body) });
            await loadDashboardData();
            render();
          } catch(err) { alert(err.message); }
        }

        async function changeStatus(taskId, nextStatus) {
          try {
            await api.request('/tasks/' + taskId, {
              method: 'PUT',
              body: JSON.stringify({ status: nextStatus })
            });
            await loadDashboardData();
            render();
          } catch(err) { alert(err.message); }
        }

        async function deleteTask(taskId) {
          if(!confirm('Delete this task?')) return;
          try {
            await api.request('/tasks/' + taskId, { method: 'DELETE' });
            await loadDashboardData();
            render();
          } catch(err) { alert(err.message); }
        }

        function renderView() {
          const container = document.getElementById('app');
          if (!state.token) {
            container.innerHTML = \`
              <div class="max-w-md mx-auto mt-20 bg-gray-800 p-8 rounded-xl shadow-2xl border border-gray-700">
                <h2 class="text-3xl font-bold mb-6 text-center text-indigo-400">FlowTask Core</h2>
                <form onsubmit="handleLogin(event)" class="space-y-4">
                  <div>
                    <label class="block text-sm mb-1 text-gray-400">Email Address</label>
                    <input type="email" name="email" required class="w-full bg-gray-900 border border-gray-600 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
                  </div>
                  <div>
                    <label class="block text-sm mb-1 text-gray-400">Password</label>
                    <input type="password" name="password" required class="w-full bg-gray-900 border border-gray-600 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
                  </div>
                  <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2 rounded transition">Sign In</button>
                </form>
                <div class="mt-6 text-xs text-gray-500 bg-gray-900 p-3 rounded border border-gray-700 space-y-1">
                  <p class="font-bold text-gray-400">Available Sandbox Accounts:</p>
                  <p>• Admin Access: <span class="text-indigo-300 font-mono">admin@task.com</span> / password: <span class="text-indigo-300 font-mono">admin123</span></p>
                  <p>• Member Access: <span class="text-indigo-300 font-mono">dev@task.com</span> / password: <span class="text-indigo-300 font-mono">user123</span></p>
                </div>
              </div>
            \`;
            return;
          }

          const columns = ['To Do', 'In Progress', 'Done'];
          let columnsHtml = '';

          columns.forEach(status => {
            const currentTasks = state.tasks.filter(t => t.status === status);
            let cardsHtml = '';

            currentTasks.forEach(task => {
              const assignee = state.users.find(u => u.id === task.assignedTo)?.name || 'Unassigned';
              const priorityColors = task.priority === 'High' ? 'bg-red-900/50 text-red-300 border-red-700' : task.priority === 'Medium' ? 'bg-amber-900/50 text-amber-300 border-amber-700' : 'bg-emerald-900/50 text-emerald-300 border-emerald-700';
              
              let adminControls = state.user.role === 'Admin' ? \`<button onclick="deleteTask(\${task.id})" class="text-xs text-red-400 hover:text-red-300">Delete</button>\` : '';
              
              let moveButtons = '';
              if (status === 'To Do') moveButtons += \`<button onclick="changeStatus(\${task.id}, 'In Progress')" class="bg-gray-700 text-xs px-2 py-1 rounded hover:bg-gray-600">Start ➔</button>\`;
              if (status === 'In Progress') {
                moveButtons += \`<button onclick="changeStatus(\${task.id}, 'To Do')" class="bg-gray-700 text-xs px-2 py-1 rounded hover:bg-gray-600 text-gray-400">➔ Back</button>\`;
                moveButtons += \`<button onclick="changeStatus(\${task.id}, 'Done')" class="bg-indigo-600 text-xs px-2 py-1 rounded hover:bg-indigo-500 ml-2">Complete ✓</button>\`;
              }
              if (status === 'Done') moveButtons += \`<button onclick="changeStatus(\${task.id}, 'In Progress')" class="bg-gray-700 text-xs px-2 py-1 rounded hover:bg-gray-600 text-gray-400">Reopen</button>\`;

              cardsHtml += \`
                <div class="bg-gray-900 p-4 rounded-lg border border-gray-700 shadow flex flex-col justify-between space-y-3">
                  <div>
                    <div class="flex justify-between items-start mb-1">
                      <span class="text-xs px-2 py-0.5 rounded border \${priorityColors}">\${task.priority}</span>
                      \${adminControls}
                    </div>
                    <h4 class="font-bold text-gray-100 text-md">\${task.title}</h4>
                    <p class="text-xs text-gray-400 mt-1">\${task.description}</p>
                  </div>
                  <div class="pt-2 border-t border-gray-800 flex justify-between items-center">
                    <span class="text-[11px] text-indigo-300 font-medium">👤 \${assignee}</span>
                    <div class="flex space-x-1">\${moveButtons}</div>
                  </div>
                </div>
              \`;
            });

            columnsHtml += \`
              <div class="bg-gray-800/60 p-4 rounded-xl border border-gray-700 flex flex-col space-y-3 min-h-[400px]">
                <div class="flex justify-between items-center mb-2">
                  <h3 class="font-bold text-lg text-gray-300">\${status}</h3>
                  <span class="bg-gray-700 text-xs px-2 py-0.5 rounded-full text-gray-300">\${currentTasks.length}</span>
                </div>
                <div class="space-y-3 flex-1 overflow-y-auto">\n\${cardsHtml || '<p class="text-xs text-gray-500 text-center py-8">No tasks</p>'}\n</div>
              </div>
            \`;
          });

          let adminFormHtml = '';
          if (state.user.role === 'Admin') {
            let assigneeOptions = state.users.map(u => \`<option value="\${u.id}">\${u.name} (\${u.role})</option>\`).join('');
            adminFormHtml = \`
              <div class="bg-gray-800 p-5 rounded-xl border border-gray-700 mb-8">
                <h3 class="text-lg font-bold mb-4 text-indigo-400">⚡ Create Team Task (Admin Access)</h3>
                <form onsubmit="createTask(event)" class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
                  <div>
                    <label class="block text-xs mb-1 text-gray-400">Task Title</label>
                    <input type="text" name="title" required class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm text-white focus:outline-none focus:border-indigo-500">
                  </div>
                  <div>
                    <label class="block text-xs mb-1 text-gray-400">Description</label>
                    <input type="text" name="description" required class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm text-white focus:outline-none focus:border-indigo-500">
                  </div>
                  <div>
                    <label class="block text-xs mb-1 text-gray-400">Priority</label>
                    <select name="priority" class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm text-white focus:outline-none focus:border-indigo-500">
                      <option value="Low">Low</option>
                      <option value="Medium" selected>Medium</option>
                      <option value="High">High</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-xs mb-1 text-gray-400">Assign Worker</label>
                    <select name="assignedTo" class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm text-white focus:outline-none focus:border-indigo-500">
                      \${assigneeOptions}
                    </select>
                  </div>
                  <div class="md:col-span-4 flex justify-end">
                    <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-6 py-2 rounded text-sm transition shadow-lg shadow-indigo-900/20">Add Task to Board</button>
                  </div>
                </form>
              </div>
            \`;
          }

          container.innerHTML = \`
            <header class="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-gray-800 pb-5 mb-6 gap-4">
              <div>
                <h1 class="text-2xl font-black text-white tracking-wide">FlowTask Management Console</h1>
                <p class="text-xs text-gray-400 mt-0.5">Logged in as: <span class="text-indigo-400 font-semibold">\${state.user.name}</span> (\${state.user.role})</p>
              </div>
              <button onclick="logout()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 font-medium px-4 py-2 rounded text-sm border border-gray-700 transition">Log Out</button>
            </header>
            
            \${adminFormHtml}

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
              \${columnsHtml}
            </div>
          \`;
        }

        async function render() {
          renderView();
        }

        // Run bootstrap operations
        (async () => {
          if(state.token) await loadDashboardData();
          render();
        })();
      </script>
    </body>
    </html>
  `);
});

// Start Server
app.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`🚀 Task Manager System Active at http://localhost:${PORT}`);
  console.log(`===================================================`);
});