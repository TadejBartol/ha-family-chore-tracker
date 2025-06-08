const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const cron = require('node-cron');
const rateLimit = require('express-rate-limit');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tvoja_skrivna_kljuc_za_jwt';

// Home Assistant configuration
const DATABASE_PATH = process.env.DATABASE_PATH || 'chores.db';
const HASSIO = process.env.HASSIO === 'true';

// Home Assistant Ingress support
if (HASSIO) {
  // Trust proxy headers from Home Assistant
  app.set('trust proxy', true);
  
  // Handle Home Assistant Ingress headers
  app.use((req, res, next) => {
    // Set base URL from Ingress headers
    if (req.headers['x-ingress-path']) {
      req.baseUrl = req.headers['x-ingress-path'];
    }
    
    // Handle real IP from proxy
    if (req.headers['x-forwarded-for']) {
      req.ip = req.headers['x-forwarded-for'].split(',')[0].trim();
    }
    
    next();
  });
}

// Middleware
app.use(cors({
  origin: HASSIO ? true : '*',
  credentials: true
}));
app.use(bodyParser.json());

// Session configuration
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Database initialization
const db = new sqlite3.Database(DATABASE_PATH);

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT UNIQUE,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'superuser', 'normaluser')),
    points INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Chore templates table
  db.run(`CREATE TABLE IF NOT EXISTS chore_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    points INTEGER NOT NULL,
    negative_points INTEGER DEFAULT 0,
    category TEXT NOT NULL,
    frequency TEXT NOT NULL CHECK(frequency IN ('daily', 'weekly', 'monthly', 'once')),
    time_limit_days INTEGER DEFAULT 1,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
  )`);

  // Chore instances table (actual assigned chores)
  db.run(`CREATE TABLE IF NOT EXISTS chore_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    assigned_to INTEGER NOT NULL,
    assigned_by INTEGER,
    due_date DATETIME NOT NULL,
    completed_at DATETIME,
    completed_by INTEGER,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'overdue', 'excused')),
    points_awarded INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES chore_templates (id),
    FOREIGN KEY (assigned_to) REFERENCES users (id),
    FOREIGN KEY (assigned_by) REFERENCES users (id),
    FOREIGN KEY (completed_by) REFERENCES users (id)
  )`);

  // Add completed_by column if it doesn't exist (migration)
  db.run(`ALTER TABLE chore_instances ADD COLUMN completed_by INTEGER REFERENCES users(id)`, (err) => {
    // Ignore error if column already exists
  });

  // Rewards table
  db.run(`CREATE TABLE IF NOT EXISTS rewards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    cost INTEGER NOT NULL,
    icon TEXT,
    category TEXT,
    created_by INTEGER,
    active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
  )`);

  // Reward redemptions table
  db.run(`CREATE TABLE IF NOT EXISTS reward_redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    reward_id INTEGER NOT NULL,
    points_spent INTEGER NOT NULL,
    redeemed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (reward_id) REFERENCES rewards (id)
  )`);

  // Automatic assignments table (for recurring chores)
  db.run(`CREATE TABLE IF NOT EXISTS automatic_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL,
    assigned_to INTEGER NOT NULL,
    assigned_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES chore_templates (id),
    FOREIGN KEY (assigned_to) REFERENCES users (id),
    FOREIGN KEY (assigned_by) REFERENCES users (id),
    UNIQUE(template_id)
  )`);

  // Create default admin user if no users exist
  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (err) {
      console.error('Napaka pri preverjanju uporabnikov:', err);
      return;
    }
    
    if (row.count === 0) {
      const hashedPassword = bcrypt.hashSync('admin123', 10);
      db.run(
        "INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)",
        ['admin', hashedPassword, 'Administrator', 'admin'],
        function(err) {
          if (err) {
            console.error('Napaka pri ustvarjanju admin uporabnika:', err);
          } else {
            console.log('Ustvarjen privzeti admin uporabnik: admin/admin123');
          }
        }
      );
    }
  });

  // Insert default rewards
  db.get("SELECT COUNT(*) as count FROM rewards", (err, row) => {
    if (err) return;
    
    if (row.count === 0) {
      const defaultRewards = [
        ['Filmski večer', 'Oglej si svoj najljubši film z prigrizki', 50, '🎬', 'zabava'],
        ['Naročilo hrane', 'Naroči iz svoje najljubše restavracije', 75, '🍕', 'hrana'],
        ['Igralna seja', '2 uri brezskrbnega igranja', 40, '🎮', 'zabava'],
        ['Nakupovanje', '50€ proračuna za nakupovanje', 100, '🛍️', 'nakupovanje'],
        ['Spa dan', 'Sproščujoča spa oskrba ali masaža', 120, '💆', 'počitek'],
        ['Prost dan', 'Cel dan za početi karkoli želiš', 80, '🏖️', 'čas'],
        ['Obisk kavarne', 'Privoščite si premium kavo in pecivo', 25, '☕', 'hrana'],
        ['Nova knjiga', 'Kupi tisto knjigo, ki si jo že dolgo želel', 30, '📚', 'zabava']
      ];

      defaultRewards.forEach(reward => {
        db.run(
          "INSERT INTO rewards (name, description, cost, icon, category) VALUES (?, ?, ?, ?, ?)",
          reward,
          (err) => {
            if (err) console.error('Napaka pri vstavljanju nagrade:', err);
          }
        );
      });
    }
  });
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Dostop zavrnjen. Žeton je potreben.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Neveljaven žeton.' });
    }
    req.user = user;
    next();
  });
};

// Role checking middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Nimaste dovoljenj za to dejanje.' });
    }
    next();
  };
};

// Debug middleware for Ingress
if (HASSIO) {
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    next();
  });
}

// Health check endpoint for Home Assistant
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    hassio: HASSIO,
    database: DATABASE_PATH,
    ingress_path: req.headers['x-ingress-path'] || 'none'
  });
});

// Authentication routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Uporabniško ime in geslo sta obvezna.' });
  }

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: 'Napačno uporabniško ime ali geslo.' });
      }

      const token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          role: user.role,
          full_name: user.full_name 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        message: 'Uspešna prijava',
        token,
        user: {
          id: user.id,
          username: user.username,
          full_name: user.full_name,
          role: user.role,
          points: user.points
        }
      });
    }
  );
});

// Get current user info
app.get('/api/me', authenticateToken, (req, res) => {
  db.get(
    "SELECT id, username, full_name, role, points, email FROM users WHERE id = ?",
    [req.user.id],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(user);
    }
  );
});

// User management routes (Admin only)
app.post('/api/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { username, password, full_name, email, role } = req.body;

  if (!username || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Vsa obvezna polja morajo biti izpolnjena.' });
  }

  if (!['admin', 'superuser', 'normaluser'].includes(role)) {
    return res.status(400).json({ error: 'Neveljavna vloga uporabnika.' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, password, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
    [username, hashedPassword, full_name, email, role],
    function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(400).json({ error: 'Uporabniško ime ali email že obstaja.' });
        }
        return res.status(500).json({ error: 'Napaka pri ustvarjanju uporabnika.' });
      }

      res.status(201).json({
        message: 'Uporabnik uspešno ustvarjen',
        userId: this.lastID
      });
    }
  );
});

// Get all users (Admin and Superuser)
app.get('/api/users', authenticateToken, requireRole(['admin', 'superuser']), (req, res) => {
  db.all(
    "SELECT id, username, full_name, email, role, points, created_at FROM users ORDER BY created_at DESC",
    (err, users) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(users);
    }
  );
});

// Complete chore
app.post('/api/complete-chore/:id', authenticateToken, (req, res) => {
  const choreId = req.params.id;

  db.get(
    "SELECT ci.*, ct.points, ct.frequency FROM chore_instances ci JOIN chore_templates ct ON ci.template_id = ct.id WHERE ci.id = ? AND ci.assigned_to = ?",
    [choreId, req.user.id],
    (err, chore) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      if (!chore) {
        return res.status(404).json({ error: 'Opravilo ni najdeno.' });
      }

      if (chore.status === 'completed') {
        return res.status(400).json({ error: 'Opravilo je že opravljeno.' });
      }

      const now = new Date().toISOString();
      const pointsToAward = chore.points;

      // Mark chore as completed
      db.run(
        "UPDATE chore_instances SET status = 'completed', completed_at = ?, points_awarded = ?, completed_by = ? WHERE id = ?",
        [now, pointsToAward, req.user.id, choreId],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Napaka pri označevanju opravila kot opravljeno.' });
          }

          // Update user points
          db.run(
            "UPDATE users SET points = points + ? WHERE id = ?",
            [pointsToAward, req.user.id],
            (err) => {
              if (err) {
                console.error('Napaka pri posodabljanju točk:', err);
              }

              res.json({
                message: 'Opravilo uspešno opravljeno',
                pointsAwarded: pointsToAward
              });
            }
          );
        }
      );
    }
  );
});

// Get user's chores
app.get('/api/my-chores', authenticateToken, (req, res) => {
  const { status } = req.query;
  
  let whereClause = 'WHERE ci.assigned_to = ?';
  let params = [req.user.id];

  if (status) {
    whereClause += ' AND ci.status = ?';
    params.push(status);
  }

  // Filter out old one-time chores (older than today)
  whereClause += ` AND (ct.frequency != 'once' OR DATE(ci.created_at) = DATE('now'))`;

  db.all(
    `SELECT ci.*, ct.name, ct.description, ct.points, ct.negative_points, ct.category, ct.frequency,
            u1.full_name as assigned_by_name
     FROM chore_instances ci
     JOIN chore_templates ct ON ci.template_id = ct.id
     LEFT JOIN users u1 ON ci.assigned_by = u1.id
     ${whereClause}
     ORDER BY ct.frequency, ci.due_date ASC`,
    params,
    (err, chores) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(chores);
    }
  );
});

// Get all users' chores (for "Others" tab)
app.get('/api/others-chores', authenticateToken, (req, res) => {
  // First check if user has completed all their own chores
  db.all(
    `SELECT COUNT(*) as pending_count
     FROM chore_instances ci
     JOIN chore_templates ct ON ci.template_id = ct.id
     WHERE ci.assigned_to = ? AND ci.status = 'pending'
     AND (ct.frequency != 'once' OR DATE(ci.created_at) = DATE('now'))`,
    [req.user.id],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      const userHasPendingChores = result[0].pending_count > 0;

      if (userHasPendingChores) {
        return res.status(403).json({ 
          error: 'Najprej morate opraviti vsa svoja opravila, preden lahko pomagate drugim.',
          canHelpOthers: false
        });
      }

      // Get other users' pending chores
      db.all(
        `SELECT ci.*, ct.name, ct.description, ct.points, ct.negative_points, ct.category, ct.frequency,
                u1.full_name as assigned_to_name, u2.full_name as assigned_by_name
         FROM chore_instances ci
         JOIN chore_templates ct ON ci.template_id = ct.id
         JOIN users u1 ON ci.assigned_to = u1.id
         LEFT JOIN users u2 ON ci.assigned_by = u2.id
         WHERE ci.assigned_to != ? AND ci.status = 'pending'
         AND (ct.frequency != 'once' OR DATE(ci.created_at) = DATE('now'))
         ORDER BY u1.full_name, ct.frequency, ci.due_date ASC`,
        [req.user.id],
        (err, chores) => {
          if (err) {
            return res.status(500).json({ error: 'Napaka strežnika.' });
          }
          res.json({ chores, canHelpOthers: true });
        }
      );
    }
  );
});

// Complete chore for another user
app.post('/api/complete-chore-for-other/:id', authenticateToken, (req, res) => {
  const choreId = req.params.id;

  // First check if user has completed all their own chores
  db.all(
    `SELECT COUNT(*) as pending_count
     FROM chore_instances ci
     JOIN chore_templates ct ON ci.template_id = ct.id
     WHERE ci.assigned_to = ? AND ci.status = 'pending'
     AND (ct.frequency != 'once' OR DATE(ci.created_at) = DATE('now'))`,
    [req.user.id],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      const userHasPendingChores = result[0].pending_count > 0;

      if (userHasPendingChores) {
        return res.status(403).json({ 
          error: 'Najprej morate opraviti vsa svoja opravila, preden lahko pomagate drugim.'
        });
      }

      // Get chore details
      db.get(
        `SELECT ci.*, ct.points, ct.frequency, u.full_name as assigned_to_name
         FROM chore_instances ci 
         JOIN chore_templates ct ON ci.template_id = ct.id
         JOIN users u ON ci.assigned_to = u.id
         WHERE ci.id = ? AND ci.assigned_to != ? AND ci.status = 'pending'`,
        [choreId, req.user.id],
        (err, chore) => {
          if (err) {
            return res.status(500).json({ error: 'Napaka strežnika.' });
          }

          if (!chore) {
            return res.status(404).json({ error: 'Opravilo ni najdeno ali ni na voljo.' });
          }

          const now = new Date().toISOString();
          const pointsToAward = Math.floor(chore.points * 0.7); // Helper gets 70% of points

          // Mark chore as completed
          db.run(
            `UPDATE chore_instances 
             SET status = 'completed', completed_at = ?, points_awarded = ?, completed_by = ?
             WHERE id = ?`,
            [now, chore.points, req.user.id, choreId],
            (err) => {
              if (err) {
                return res.status(500).json({ error: 'Napaka pri označevanju opravila.' });
              }

              // Award points to original assignee
              db.run(
                "UPDATE users SET points = points + ? WHERE id = ?",
                [chore.points, chore.assigned_to],
                (err) => {
                  if (err) {
                    console.error('Napaka pri posodabljanju točk za izvirnega uporabnika:', err);
                  }

                  // Award helper points
                  db.run(
                    "UPDATE users SET points = points + ? WHERE id = ?",
                    [pointsToAward, req.user.id],
                    (err) => {
                      if (err) {
                        console.error('Napaka pri posodabljanju točk za pomagača:', err);
                      }

                      res.json({
                        message: `Opravilo opravljeno za ${chore.assigned_to_name}! Vi ste dobili ${pointsToAward} točk, ${chore.assigned_to_name} pa ${chore.points} točk.`,
                        pointsAwarded: pointsToAward,
                        originalPoints: chore.points
                      });
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
});

// Get user statistics
app.get('/api/user-stats/:userId?', authenticateToken, (req, res) => {
  const userId = req.params.userId || req.user.id;
  const { period = 'month' } = req.query; // week, month, year

  let dateFilter = '';
  let currentDateFilter = '';
  switch (period) {
    case 'week':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-7 days')";
      currentDateFilter = "AND DATE(ci.created_at) >= DATE('now', '-7 days')";
      break;
    case 'month':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-30 days')";
      currentDateFilter = "AND DATE(ci.created_at) >= DATE('now', '-30 days')";
      break;
    case 'year':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-365 days')";
      currentDateFilter = "AND DATE(ci.created_at) >= DATE('now', '-365 days')";
      break;
  }

  // Get completed chores stats
  db.all(
    `SELECT 
       COUNT(*) as total_completed,
       SUM(CASE WHEN ci.completed_by IS NULL OR ci.completed_by = ci.assigned_to THEN 1 ELSE 0 END) as self_completed,
       SUM(CASE WHEN ci.completed_by IS NOT NULL AND ci.completed_by != ci.assigned_to THEN 1 ELSE 0 END) as helped_by_others,
       SUM(ci.points_awarded) as total_points,
       AVG(ci.points_awarded) as avg_points,
       ct.category,
       ct.frequency,
       COUNT(*) as count_by_category
     FROM chore_instances ci
     JOIN chore_templates ct ON ci.template_id = ct.id
     WHERE ci.assigned_to = ? AND ci.status = 'completed' ${dateFilter}
     GROUP BY ct.category, ct.frequency
     ORDER BY count_by_category DESC`,
    [userId],
    (err, categoryStats) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      // Get overall completed stats
      db.get(
        `SELECT 
           COUNT(*) as total_completed,
           SUM(CASE WHEN ci.completed_by IS NULL OR ci.completed_by = ci.assigned_to THEN 1 ELSE 0 END) as self_completed,
           SUM(CASE WHEN ci.completed_by IS NOT NULL AND ci.completed_by != ci.assigned_to THEN 1 ELSE 0 END) as helped_by_others,
           SUM(ci.points_awarded) as total_points,
           AVG(ci.points_awarded) as avg_points
         FROM chore_instances ci
         WHERE ci.assigned_to = ? AND ci.status = 'completed' ${dateFilter}`,
        [userId],
        (err, overallStats) => {
          if (err) {
            return res.status(500).json({ error: 'Napaka strežnika.' });
          }

          // Get pending chores count
          db.get(
            `SELECT COUNT(*) as pending_count
             FROM chore_instances ci
             JOIN chore_templates ct ON ci.template_id = ct.id
             WHERE ci.assigned_to = ? AND ci.status = 'pending' ${currentDateFilter}
             AND (ct.frequency != 'once' OR DATE(ci.created_at) = DATE('now'))`,
            [userId],
            (err, pendingStats) => {
              if (err) {
                return res.status(500).json({ error: 'Napaka strežnika.' });
              }

              // Get help given to others
              db.get(
                `SELECT 
                   COUNT(*) as helped_others_count,
                   SUM(ci.points_awarded * 0.7) as points_from_helping
                 FROM chore_instances ci
                 WHERE ci.completed_by = ? AND ci.completed_by != ci.assigned_to AND ci.status = 'completed' ${dateFilter}`,
                [userId],
                (err, helpStats) => {
                  if (err) {
                    return res.status(500).json({ error: 'Napaka strežnika.' });
                  }

                  res.json({
                    period,
                    overall: overallStats || { total_completed: 0, self_completed: 0, helped_by_others: 0, total_points: 0, avg_points: 0 },
                    pending: pendingStats || { pending_count: 0 },
                    helpGiven: helpStats || { helped_others_count: 0, points_from_helping: 0 },
                    byCategory: categoryStats || []
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

// Get all users statistics for leaderboard
app.get('/api/all-users-stats', authenticateToken, (req, res) => {
  const { period = 'month' } = req.query;

  let dateFilter = '';
  let currentDateFilter = '';
  switch (period) {
    case 'week':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-7 days')";
      currentDateFilter = "AND DATE(ci.created_at) >= DATE('now', '-7 days')";
      break;
    case 'month':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-30 days')";
      currentDateFilter = "AND DATE(ci.created_at) >= DATE('now', '-30 days')";
      break;
    case 'year':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-365 days')";
      currentDateFilter = "AND DATE(ci.created_at) >= DATE('now', '-365 days')";
      break;
  }

  db.all(
    `SELECT 
       u.id, u.full_name, u.points as total_lifetime_points,
       COALESCE(completed.total_completed, 0) as completed_count,
       COALESCE(completed.points_earned, 0) as points_earned,
       COALESCE(pending.pending_count, 0) as pending_count,
       COALESCE(helped.helped_count, 0) as helped_others
     FROM users u
     LEFT JOIN (
       SELECT ci.assigned_to,
              COUNT(*) as total_completed,
              SUM(ci.points_awarded) as points_earned
       FROM chore_instances ci
       WHERE ci.status = 'completed' ${dateFilter}
       GROUP BY ci.assigned_to
     ) completed ON u.id = completed.assigned_to
     LEFT JOIN (
       SELECT ci.assigned_to,
              COUNT(*) as pending_count
       FROM chore_instances ci
       JOIN chore_templates ct ON ci.template_id = ct.id
       WHERE ci.status = 'pending' ${currentDateFilter}
       AND (ct.frequency != 'once' OR DATE(ci.created_at) = DATE('now'))
       GROUP BY ci.assigned_to
     ) pending ON u.id = pending.assigned_to
     LEFT JOIN (
       SELECT ci.completed_by,
              COUNT(*) as helped_count
       FROM chore_instances ci
       WHERE ci.completed_by IS NOT NULL 
       AND ci.completed_by != ci.assigned_to 
       AND ci.status = 'completed' ${dateFilter}
       GROUP BY ci.completed_by
     ) helped ON u.id = helped.completed_by
     WHERE u.role != 'admin'
     ORDER BY points_earned DESC, completed_count DESC`,
    [],
    (err, usersStats) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json({ period, users: usersStats });
    }
  );
});

// Get completed chores for other users (for "Others" tab)
app.get('/api/others-completed-chores/:userId', authenticateToken, (req, res) => {
  const userId = req.params.userId;
  const { period = 'week' } = req.query;

  let dateFilter = '';
  switch (period) {
    case 'week':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-7 days')";
      break;
    case 'month':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-30 days')";
      break;
    case 'year':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-365 days')";
      break;
  }

  db.all(
    `SELECT ci.*, ct.name, ct.description, ct.points, ct.category, ct.frequency,
            u1.full_name as assigned_to_name, u2.full_name as completed_by_name
     FROM chore_instances ci
     JOIN chore_templates ct ON ci.template_id = ct.id
     JOIN users u1 ON ci.assigned_to = u1.id
     LEFT JOIN users u2 ON ci.completed_by = u2.id
     WHERE ci.assigned_to = ? AND ci.status = 'completed' ${dateFilter}
     ORDER BY ct.frequency, ci.completed_at DESC`,
    [userId],
    (err, chores) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(chores);
    }
  );
});

// Get assignment status (already assigned vs not assigned templates)
app.get('/api/assignment-status', authenticateToken, requireRole(['admin', 'superuser']), (req, res) => {
  // Get all recurring templates
  db.all(
    `SELECT ct.*, aa.assigned_to, u.full_name as assigned_to_name
     FROM chore_templates ct
     LEFT JOIN automatic_assignments aa ON ct.id = aa.template_id
     LEFT JOIN users u ON aa.assigned_to = u.id
     WHERE ct.frequency != 'once'
     ORDER BY ct.frequency, ct.name`,
    [],
    (err, templates) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      const assigned = templates.filter(t => t.assigned_to);
      const unassigned = templates.filter(t => !t.assigned_to);

      res.json({
        assigned,
        unassigned
      });
    }
  );
});

// Assign recurring template to user
app.post('/api/assign-recurring/:templateId', authenticateToken, requireRole(['admin', 'superuser']), (req, res) => {
  const { templateId } = req.params;
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'ID uporabnika je obvezen.' });
  }

  // Check if template exists and is recurring
  db.get(
    "SELECT * FROM chore_templates WHERE id = ? AND frequency != 'once'",
    [templateId],
    (err, template) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      if (!template) {
        return res.status(404).json({ error: 'Predloga ni najdena ali ni ponavljajoča.' });
      }

      // Insert or update automatic assignment
      db.run(
        `INSERT OR REPLACE INTO automatic_assignments (template_id, assigned_to, assigned_by)
         VALUES (?, ?, ?)`,
        [templateId, userId, req.user.id],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Napaka pri dodeljevanju.' });
          }

          res.json({ message: 'Ponavljajoča naloga uspešno dodeljena.' });
        }
      );
    }
  );
});

// Remove automatic assignment
app.delete('/api/assign-recurring/:templateId', authenticateToken, requireRole(['admin', 'superuser']), (req, res) => {
  const { templateId } = req.params;

  db.run(
    "DELETE FROM automatic_assignments WHERE template_id = ?",
    [templateId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Dodelitev ni najdena.' });
      }

      res.json({ message: 'Avtomatska dodelitev odstranjena.' });
    }
  );
});

// Advanced analytics APIs
// Get points trend data
app.get('/api/analytics/points-trend/:userId?', authenticateToken, (req, res) => {
  const userId = req.params.userId || req.user.id;
  const { period = 'month' } = req.query; // week, month, year

  let dateFilter = '';
  let groupBy = '';
  let dateFormat = '';

  switch (period) {
    case 'week':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-7 days')";
      groupBy = "DATE(ci.completed_at)";
      dateFormat = '%Y-%m-%d';
      break;
    case 'month':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-30 days')";
      groupBy = "DATE(ci.completed_at)";
      dateFormat = '%Y-%m-%d';
      break;
    case 'year':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-365 days')";
      groupBy = "strftime('%Y-%m', ci.completed_at)";
      dateFormat = '%Y-%m';
      break;
  }

  db.all(
    `SELECT 
       strftime('${dateFormat}', ci.completed_at) as date,
       SUM(ci.points_awarded) as points,
       COUNT(*) as completed_count
     FROM chore_instances ci
     WHERE ci.assigned_to = ? AND ci.status = 'completed' ${dateFilter}
     GROUP BY ${groupBy}
     ORDER BY date ASC`,
    [userId],
    (err, data) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(data);
    }
  );
});

// Get category distribution
app.get('/api/analytics/category-distribution/:userId?', authenticateToken, (req, res) => {
  const userId = req.params.userId || req.user.id;
  const { period = 'month' } = req.query;

  let dateFilter = '';
  switch (period) {
    case 'week':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-7 days')";
      break;
    case 'month':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-30 days')";
      break;
    case 'year':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-365 days')";
      break;
  }

  db.all(
    `SELECT 
       ct.category,
       COUNT(*) as completed_count,
       SUM(ci.points_awarded) as total_points,
       AVG(ci.points_awarded) as avg_points
     FROM chore_instances ci
     JOIN chore_templates ct ON ci.template_id = ct.id
     WHERE ci.assigned_to = ? AND ci.status = 'completed' ${dateFilter}
     GROUP BY ct.category
     ORDER BY completed_count DESC`,
    [userId],
    (err, data) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(data);
    }
  );
});

// Get weekly productivity pattern
app.get('/api/analytics/weekly-productivity/:userId?', authenticateToken, (req, res) => {
  const userId = req.params.userId || req.user.id;
  const { period = 'month' } = req.query;

  let dateFilter = '';
  switch (period) {
    case 'week':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-7 days')";
      break;
    case 'month':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-30 days')";
      break;
    case 'year':
      dateFilter = "AND DATE(ci.completed_at) >= DATE('now', '-365 days')";
      break;
  }

  db.all(
    `SELECT 
       CASE cast(strftime('%w', ci.completed_at) as integer)
         WHEN 0 THEN 'Nedelja'
         WHEN 1 THEN 'Ponedeljek'
         WHEN 2 THEN 'Torek'
         WHEN 3 THEN 'Sreda'
         WHEN 4 THEN 'Četrtek'
         WHEN 5 THEN 'Petek'
         WHEN 6 THEN 'Sobota'
       END as day_name,
       cast(strftime('%w', ci.completed_at) as integer) as day_number,
       COUNT(*) as completed_count,
       SUM(ci.points_awarded) as total_points,
       AVG(ci.points_awarded) as avg_points
     FROM chore_instances ci
     WHERE ci.assigned_to = ? AND ci.status = 'completed' ${dateFilter}
     GROUP BY day_number
     ORDER BY day_number`,
    [userId],
    (err, data) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(data);
    }
  );
});

// Get activity heatmap data (last 90 days)
app.get('/api/analytics/activity-heatmap/:userId?', authenticateToken, (req, res) => {
  const userId = req.params.userId || req.user.id;

  db.all(
    `SELECT 
       DATE(ci.completed_at) as date,
       COUNT(*) as activity_count,
       SUM(ci.points_awarded) as points
     FROM chore_instances ci
     WHERE ci.assigned_to = ? 
     AND ci.status = 'completed'
     AND DATE(ci.completed_at) >= DATE('now', '-90 days')
     GROUP BY DATE(ci.completed_at)
     ORDER BY date ASC`,
    [userId],
    (err, data) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(data);
    }
  );
});

// Get performance metrics
app.get('/api/analytics/performance/:userId?', authenticateToken, (req, res) => {
  const userId = req.params.userId || req.user.id;
  const { period = 'month' } = req.query;

  let dateFilter = '';
  switch (period) {
    case 'week':
      dateFilter = "AND DATE(ci.created_at) >= DATE('now', '-7 days')";
      break;
    case 'month':
      dateFilter = "AND DATE(ci.created_at) >= DATE('now', '-30 days')";
      break;
    case 'year':
      dateFilter = "AND DATE(ci.created_at) >= DATE('now', '-365 days')";
      break;
  }

  // Get user performance metrics
  db.get(
    `SELECT 
       COUNT(CASE WHEN ci.status = 'completed' THEN 1 END) as completed,
       COUNT(CASE WHEN ci.status = 'pending' THEN 1 END) as pending,
       COUNT(CASE WHEN ci.status = 'overdue' THEN 1 END) as overdue,
       COUNT(*) as total,
       SUM(CASE WHEN ci.status = 'completed' THEN ci.points_awarded ELSE 0 END) as total_points,
       AVG(CASE WHEN ci.status = 'completed' THEN ci.points_awarded END) as avg_points_per_task,
       MAX(streak.current_streak) as longest_streak
     FROM chore_instances ci
     LEFT JOIN (
       SELECT 
         assigned_to,
         MAX(consecutive_days) as current_streak
       FROM (
         SELECT 
           assigned_to,
           ROW_NUMBER() OVER (PARTITION BY assigned_to ORDER BY date) - 
           ROW_NUMBER() OVER (PARTITION BY assigned_to, grp ORDER BY date) as consecutive_days
         FROM (
           SELECT 
             assigned_to,
             DATE(completed_at) as date,
             RANK() OVER (PARTITION BY assigned_to ORDER BY DATE(completed_at)) as grp
           FROM chore_instances 
           WHERE status = 'completed'
         )
       )
       GROUP BY assigned_to
     ) streak ON ci.assigned_to = streak.assigned_to
     WHERE ci.assigned_to = ? ${dateFilter}`,
    [userId],
    (err, userMetrics) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }

      // Get average metrics for comparison
      db.get(
        `SELECT 
           AVG(CASE WHEN ci.status = 'completed' THEN 1.0 ELSE 0.0 END) as avg_completion_rate,
           AVG(CASE WHEN ci.status = 'completed' THEN ci.points_awarded END) as avg_points_per_task
         FROM chore_instances ci
         WHERE ci.assigned_to != ? ${dateFilter}`,
        [userId],
        (err, avgMetrics) => {
          if (err) {
            return res.status(500).json({ error: 'Napaka strežnika.' });
          }

          const completionRate = userMetrics.total > 0 ? 
            (userMetrics.completed / userMetrics.total) * 100 : 0;
          
          const avgCompletionRate = (avgMetrics.avg_completion_rate || 0) * 100;

          res.json({
            user: {
              completion_rate: completionRate,
              avg_points_per_task: userMetrics.avg_points_per_task || 0,
              longest_streak: userMetrics.longest_streak || 0,
              total_completed: userMetrics.completed || 0,
              total_pending: userMetrics.pending || 0,
              total_overdue: userMetrics.overdue || 0
            },
            average: {
              completion_rate: avgCompletionRate,
              avg_points_per_task: avgMetrics.avg_points_per_task || 0
            }
          });
        }
      );
    }
  );
});

// Chore template routes
app.post('/api/chore-templates', authenticateToken, requireRole(['admin']), (req, res) => {
  const { name, description, points, negative_points, category, frequency, time_limit_days } = req.body;

  if (!name || !points || !category || !frequency) {
    return res.status(400).json({ error: 'Vsa obvezna polja morajo biti izpolnjena.' });
  }

  db.run(
    `INSERT INTO chore_templates 
     (name, description, points, negative_points, category, frequency, time_limit_days, created_by) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, description, points, negative_points || 0, category, frequency, time_limit_days || 1, req.user.id],
    function(err) {
      if (err) {
        console.error('Napaka pri ustvarjanju predloge:', err);
        return res.status(500).json({ error: 'Napaka pri ustvarjanju predloge opravila.' });
      }

      res.status(201).json({
        message: 'Predloga opravila uspešno ustvarjena',
        templateId: this.lastID
      });
    }
  );
});

// Get chore templates
app.get('/api/chore-templates', authenticateToken, requireRole(['admin', 'superuser']), (req, res) => {
  db.all(
    `SELECT ct.*, u.full_name as created_by_name 
     FROM chore_templates ct 
     LEFT JOIN users u ON ct.created_by = u.id 
     ORDER BY ct.created_at DESC`,
    (err, templates) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(templates);
    }
  );
});

// Update chore template
app.put('/api/chore-templates/:id', authenticateToken, requireRole(['admin']), (req, res) => {
  const { name, description, points, negative_points, category, frequency, time_limit_days } = req.body;
  const templateId = req.params.id;

  if (!name || !points || !category || !frequency) {
    return res.status(400).json({ error: 'Vsa obvezna polja morajo biti izpolnjena.' });
  }

  db.run(
    `UPDATE chore_templates 
     SET name = ?, description = ?, points = ?, negative_points = ?, category = ?, frequency = ?, time_limit_days = ?
     WHERE id = ?`,
    [name, description, points, negative_points || 0, category, frequency, time_limit_days || 1, templateId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Napaka pri posodabljanju predloge.' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Predloga ni najdena.' });
      }
      res.json({ message: 'Predloga opravila uspešno posodobljena' });
    }
  );
});

// Delete chore template
app.delete('/api/chore-templates/:id', authenticateToken, requireRole(['admin']), (req, res) => {
  const templateId = req.params.id;

  db.run('DELETE FROM chore_templates WHERE id = ?', [templateId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Napaka pri brisanju predloge.' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Predloga ni najdena.' });
    }
    res.json({ message: 'Predloga opravila uspešno obrisana' });
  });
});

// Update user (Admin only)
app.put('/api/users/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  const { username, full_name, email, role, points } = req.body;
  const userId = req.params.id;

  if (!username || !full_name || !role) {
    return res.status(400).json({ error: 'Vsa obvezna polja morajo biti izpolnjena.' });
  }

  if (!['admin', 'superuser', 'normaluser'].includes(role)) {
    return res.status(400).json({ error: 'Neveljavna vloga uporabnika.' });
  }

  db.run(
    "UPDATE users SET username = ?, full_name = ?, email = ?, role = ?, points = ? WHERE id = ?",
    [username, full_name, email, role, points || 0, userId],
    function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(400).json({ error: 'Uporabniško ime ali email že obstaja.' });
        }
        return res.status(500).json({ error: 'Napaka pri posodabljanju uporabnika.' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Uporabnik ni najden.' });
      }

      res.json({ message: 'Uporabnik uspešno posodobljen' });
    }
  );
});

// Delete user (Admin only)
app.delete('/api/users/:id', authenticateToken, requireRole(['admin']), (req, res) => {
  const userId = req.params.id;

  if (userId == req.user.id) {
    return res.status(400).json({ error: 'Ne morete obrisati sebe.' });
  }

  db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Napaka pri brisanju uporabnika.' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Uporabnik ni najden.' });
    }
    res.json({ message: 'Uporabnik uspešno obrisan' });
  });
});

// Reward management routes (Admin only)
app.post('/api/rewards', authenticateToken, requireRole(['admin']), (req, res) => {
  const { name, description, cost, icon, category } = req.body;

  if (!name || !cost) {
    return res.status(400).json({ error: 'Ime in cena sta obvezna.' });
  }

  db.run(
    "INSERT INTO rewards (name, description, cost, icon, category, created_by) VALUES (?, ?, ?, ?, ?, ?)",
    [name, description, cost, icon || '🎁', category || 'splošno', req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Napaka pri ustvarjanju nagrade.' });
      }

      res.status(201).json({
        message: 'Nagrada uspešno ustvarjena',
        rewardId: this.lastID
      });
    }
  );
});

// Get rewards
app.get('/api/rewards', authenticateToken, (req, res) => {
  db.all(
    "SELECT * FROM rewards WHERE active = 1 ORDER BY cost ASC",
    (err, rewards) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka strežnika.' });
      }
      res.json(rewards);
    }
  );
});

// Update reward (Admin only)
app.put('/api/rewards/:id', authenticateToken, requireRole(['admin']), (req, res) => {
  const { name, description, cost, icon, category, active } = req.body;
  const rewardId = req.params.id;

  if (!name || !cost) {
    return res.status(400).json({ error: 'Ime in cena sta obvezna.' });
  }

  db.run(
    "UPDATE rewards SET name = ?, description = ?, cost = ?, icon = ?, category = ?, active = ? WHERE id = ?",
    [name, description, cost, icon || '🎁', category || 'splošno', active !== false ? 1 : 0, rewardId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Napaka pri posodabljanju nagrade.' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Nagrada ni najdena.' });
      }
      res.json({ message: 'Nagrada uspešno posodobljena' });
    }
  );
});

// Delete reward (Admin only)
app.delete('/api/rewards/:id', authenticateToken, requireRole(['admin']), (req, res) => {
  const rewardId = req.params.id;

  db.run('DELETE FROM rewards WHERE id = ?', [rewardId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Napaka pri brisanju nagrade.' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Nagrada ni najdena.' });
    }
    res.json({ message: 'Nagrada uspešno obrisana' });
  });
});

// Assign chore to user
app.post('/api/assign-chore', authenticateToken, requireRole(['admin', 'superuser']), (req, res) => {
  const { template_id, assigned_to, due_date } = req.body;

  if (!template_id || !assigned_to) {
    return res.status(400).json({ error: 'Predloga opravila in uporabnik sta obvezna.' });
  }

  // Get template details
  db.get(
    "SELECT * FROM chore_templates WHERE id = ?",
    [template_id],
    (err, template) => {
      if (err || !template) {
        return res.status(404).json({ error: 'Predloga opravila ni najdena.' });
      }

      // Calculate due date if not provided
      let calculatedDueDate = due_date;
      if (!calculatedDueDate) {
        const now = new Date();
        now.setDate(now.getDate() + template.time_limit_days);
        calculatedDueDate = now.toISOString().split('T')[0];
      }

      // Create chore instance
      db.run(
        `INSERT INTO chore_instances 
         (template_id, assigned_to, assigned_by, due_date, status) 
         VALUES (?, ?, ?, ?, 'pending')`,
        [template_id, assigned_to, req.user.id, calculatedDueDate],
        function(err) {
          if (err) {
            console.error('Napaka pri dodeljevanju opravila:', err);
            return res.status(500).json({ error: 'Napaka pri dodeljevanju opravila.' });
          }

          res.status(201).json({
            message: 'Opravilo uspešno dodeljeno',
            choreInstanceId: this.lastID
          });
        }
      );
    }
  );
});

// Get assignment data (templates and users)
app.get('/api/assignment-data', authenticateToken, requireRole(['admin', 'superuser']), (req, res) => {
  // Get both templates and users
  db.all(
    "SELECT * FROM chore_templates ORDER BY name",
    (err, templates) => {
      if (err) {
        return res.status(500).json({ error: 'Napaka pri nalaganju predlog.' });
      }

      db.all(
        "SELECT id, username, full_name, role FROM users WHERE role IN ('normaluser', 'superuser') ORDER BY full_name",
        (err, users) => {
          if (err) {
            return res.status(500).json({ error: 'Napaka pri nalaganju uporabnikov.' });
          }

          res.json({ templates, users });
        }
      );
    }
  );
});

// Redeem reward
app.post('/api/redeem-reward/:id', authenticateToken, (req, res) => {
  const rewardId = req.params.id;

  db.get(
    "SELECT * FROM rewards WHERE id = ? AND active = 1",
    [rewardId],
    (err, reward) => {
      if (err || !reward) {
        return res.status(404).json({ error: 'Nagrada ni najdena.' });
      }

      // Check if user has enough points
      db.get(
        "SELECT points FROM users WHERE id = ?",
        [req.user.id],
        (err, user) => {
          if (err) {
            return res.status(500).json({ error: 'Napaka strežnika.' });
          }

          if (user.points < reward.cost) {
            return res.status(400).json({ 
              error: 'Nimate dovolj točk.',
              needed: reward.cost - user.points
            });
          }

          // Deduct points and record redemption
          db.run(
            "UPDATE users SET points = points - ? WHERE id = ?",
            [reward.cost, req.user.id],
            (err) => {
              if (err) {
                return res.status(500).json({ error: 'Napaka pri odkupu nagrade.' });
              }

              db.run(
                "INSERT INTO reward_redemptions (user_id, reward_id, points_spent) VALUES (?, ?, ?)",
                [req.user.id, reward.id, reward.cost],
                (err) => {
                  if (err) {
                    console.error('Napaka pri beleženju odkupa:', err);
                  }

                  res.json({
                    message: 'Nagrada uspešno odkupljena',
                    reward: reward,
                    pointsSpent: reward.cost
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

// Cron job to automatically create recurring chores and mark overdue ones
cron.schedule('0 0 * * *', () => {
  console.log('Izvajam dnevno preverjanje opravil...');
  
  // Mark overdue chores
  const today = new Date().toISOString().split('T')[0];
  db.run(
    "UPDATE chore_instances SET status = 'overdue' WHERE due_date < ? AND status = 'pending'",
    [today],
    function(err) {
      if (err) {
        console.error('Napaka pri označevanju zamujenih opravil:', err);
      } else if (this.changes > 0) {
        console.log(`Označenih ${this.changes} zamujenih opravil`);
      }
    }
  );

  // Create recurring chores based on automatic assignments
  db.all(
    `SELECT aa.*, ct.name, ct.frequency, ct.points, ct.negative_points
     FROM automatic_assignments aa
     JOIN chore_templates ct ON aa.template_id = ct.id`,
    [],
    (err, assignments) => {
      if (err) {
        console.error('Napaka pri pridobivanju avtomatskih dodelitev:', err);
        return;
      }

      assignments.forEach(assignment => {
        // Check if there's already a pending or recent instance
        const checkQuery = `
          SELECT ci.*, ct.frequency
          FROM chore_instances ci
          JOIN chore_templates ct ON ci.template_id = ct.id
          WHERE ci.template_id = ? AND ci.assigned_to = ?
          AND (ci.status = 'pending' OR 
               (ci.status = 'completed' AND 
                DATE(ci.completed_at) >= DATE('now', CASE 
                  WHEN ct.frequency = 'daily' THEN '-1 days'
                  WHEN ct.frequency = 'weekly' THEN '-7 days'
                  WHEN ct.frequency = 'monthly' THEN '-30 days'
                  ELSE '-1 days'
                END)))
          ORDER BY ci.created_at DESC
          LIMIT 1
        `;

        db.get(checkQuery, [assignment.template_id, assignment.assigned_to], (err, existingInstance) => {
          if (err) {
            console.error('Napaka pri preverjanju obstoječih opravil:', err);
            return;
          }

          let shouldCreate = false;
          let dueDate = new Date();

          if (!existingInstance) {
            // No instance exists, create one
            shouldCreate = true;
          } else if (existingInstance.status === 'completed') {
            // Check if enough time has passed since completion
            const completedDate = new Date(existingInstance.completed_at);
            const daysSinceCompletion = Math.floor((Date.now() - completedDate.getTime()) / (1000 * 60 * 60 * 24));

            switch (assignment.frequency) {
              case 'daily':
                shouldCreate = daysSinceCompletion >= 1;
                dueDate.setDate(dueDate.getDate() + 1);
                break;
              case 'weekly':
                shouldCreate = daysSinceCompletion >= 7;
                dueDate.setDate(dueDate.getDate() + 7);
                break;
              case 'monthly':
                shouldCreate = daysSinceCompletion >= 30;
                dueDate.setDate(dueDate.getDate() + 30);
                break;
            }
          }

          if (shouldCreate) {
            const dueDateString = dueDate.toISOString();

            db.run(
              `INSERT INTO chore_instances 
               (template_id, assigned_to, assigned_by, due_date, status, created_at)
               VALUES (?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)`,
              [assignment.template_id, assignment.assigned_to, assignment.assigned_by, dueDateString],
              function(err) {
                if (err) {
                  console.error('Napaka pri ustvarjanju ponavljajočega opravila:', err);
                } else {
                  console.log(`Ustvarjeno novo ${assignment.frequency} opravilo: ${assignment.name} za uporabnika ${assignment.assigned_to}`);
                }
              }
            );
          }
        });
      });
    }
  );
});

// Serve the main application
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Strežnik teče na portu ${PORT}`);
  console.log(`Obiščite: http://localhost:${PORT}`);
  
  if (HASSIO) {
    console.log('Aplikacija deluje v Home Assistant OS');
    console.log(`Baza podatkov: ${DATABASE_PATH}`);
    console.log('Ingress support omogočen');
  } else {
    console.log('Aplikacija deluje v samostojnem načinu');
  }
}); 