const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Primero, crear la aplicación Express
const app = express();

// Configuración de CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['http://localhost:3000'];

app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Middleware para logging de requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  console.log('Headers:', req.headers);
  next();
});

// Configuración corregida del pool MySQL
const pool = mysql.createPool({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
  port: process.env.DATABASE_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 30000,
  connectTimeout: 20000,
  multipleStatements: true,
  dateStrings: true
});

// Promisificar el pool
const promisePool = pool.promise();

// Middleware de verificación de conexión
const checkDatabaseConnection = async (req, res, next) => {
  try {
    const connection = await promisePool.getConnection();
    connection.release();
    next();
  } catch (err) {
    console.error('Error de conexión en middleware:', err);
    res.status(503).json({ 
      error: 'Servicio temporalmente no disponible',
      message: 'Por favor, intente nuevamente en unos momentos'
    });
  }
};

// Aplicar middleware después de crear la aplicación
app.use('/api', checkDatabaseConnection);

// Configuración de almacenamiento de imágenes con Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(process.cwd(), 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // Límite de 5MB
  },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Solo se permiten archivos de imagen'));
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token no proporcionado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token no válido' });

    if (user.role !== 'admin' && user.role !== 'user') {
      return res.status(403).json({ message: 'No tienes permiso para acceder a este recurso' });
    }

    req.user = user;
    next();
  });
};

// ===================== Funcionalidad de Atletas ===================== //

// Obtener atletas
app.get('/api/athletes', (req, res) => {
  promisePool.query('SELECT * FROM athletes ORDER BY id DESC')
    .then(([results]) => {
      res.json(results);
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al obtener atletas');
    });
});

// Agregar nuevo atleta
app.post('/api/athletes', upload.single('image'), (req, res) => {
  const { first_name, last_name, document_type, document_number, age, height, weight } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

  promisePool.query(
    'INSERT INTO athletes (first_name, last_name, document_type, document_number, age, height, weight, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [first_name, last_name, document_type, document_number, age, height, weight, imageUrl]
  )
    .then(([result]) => {
      res.status(201).send('Atleta agregado');
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al agregar atleta');
    });
});

// Editar atleta existente
app.put('/api/athletes/:id', upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { first_name, last_name, document_type, document_number, age, height, weight } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.image_url;

  promisePool.query(
    'UPDATE athletes SET first_name = ?, last_name = ?, document_type = ?, document_number = ?, age = ?, height = ?, weight = ?, image_url = ? WHERE id = ?',
    [first_name, last_name, document_type, document_number, age, height, weight, imageUrl, id]
  )
    .then(([result]) => {
      res.status(200).send('Atleta actualizado');
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al actualizar atleta');
    });
});

// Eliminar atleta (y su imagen)
app.delete('/api/athletes/:id', (req, res) => {
  const { id } = req.params;
  promisePool.query('SELECT image_url FROM athletes WHERE id = ?', [id])
    .then(([results]) => {
      if (results.length > 0) {
        const imageUrl = results[0].image_url;
        const imagePath = path.join(__dirname, imageUrl);
        fs.unlink(imagePath, (err) => {
          if (err) {
            console.error('Error al eliminar la imagen:', err);
          }
        });
        promisePool.query('DELETE FROM athletes WHERE id = ?', [id])
          .then(([result]) => {
            res.status(200).send('Atleta eliminado');
          })
          .catch((err) => {
            console.error(err);
            return res.status(500).send('Error al eliminar atleta');
          });
      } else {
        res.status(404).send('Atleta no encontrado');
      }
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al eliminar atleta');
    });
});

// ===================== Funcionalidad de Entrenadores ===================== //

// Obtener entrenadores
app.get('/api/trainers', (req, res) => {
  promisePool.query('SELECT * FROM trainers ORDER BY id DESC')
    .then(([results]) => {
      res.json(results);
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al obtener entrenadores');
    });
});

// Agregar nuevo entrenador
app.post('/api/trainers', upload.single('image'), (req, res) => {
  const { first_name, last_name, document_type, document_number, age, height, weight } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

  promisePool.query(
    'INSERT INTO trainers (first_name, last_name, document_type, document_number, age, height, weight, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [first_name, last_name, document_type, document_number, age, height, weight, imageUrl]
  )
    .then(([result]) => {
      res.status(201).send('Entrenador agregado');
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al agregar entrenador');
    });
});

// Editar entrenador existente
app.put('/api/trainers/:id', upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { first_name, last_name, document_type, document_number, age, height, weight } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.image_url;

  promisePool.query(
    'UPDATE trainers SET first_name = ?, last_name = ?, document_type = ?, document_number = ?, age = ?, height = ?, weight = ?, image_url = ? WHERE id = ?',
    [first_name, last_name, document_type, document_number, age, height, weight, imageUrl, id]
  )
    .then(([result]) => {
      res.status(200).send('Entrenador actualizado');
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al actualizar entrenador');
    });
});

app.delete('/api/trainers/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  promisePool.query('DELETE FROM attendance WHERE trainer_id = ?', [id])
    .then(([result]) => {
      if (result.affectedRows > 0) {
        promisePool.query('SELECT image_url FROM trainers WHERE id = ?', [id])
          .then(([results]) => {
            if (results.length > 0) {
              const imageUrl = results[0].image_url;
              if (imageUrl) {
                const imagePath = path.join(__dirname, imageUrl);
                fs.unlink(imagePath, (err) => {
                  if (err) {
                    console.error('Error al eliminar la imagen:', err);
                    return res.status(500).json({ message: 'Error al eliminar la imagen' });
                  }
                });
              }
              promisePool.query('DELETE FROM trainers WHERE id = ?', [id])
                .then(([result]) => {
                  res.status(200).send('Entrenador eliminado');
                })
                .catch((err) => {
                  console.error(err);
                  return res.status(500).send('Error al eliminar entrenador');
                });
            } else {
              res.status(404).send('Entrenador no encontrado');
            }
          })
          .catch((err) => {
            console.error(err);
            return res.status(500).send('Error al eliminar entrenador');
          });
      } else {
        res.status(404).send('Entrenador no encontrado');
      }
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al eliminar entrenador');
    });
});

// ===================== Funcionalidad de Pagos ===================== //

// Obtener pagos
app.get('/api/payments', (req, res) => {
  const { athlete_id } = req.query;

  let query = `
    SELECT payments.id, 
    CONCAT(athletes.first_name, ' ', athletes.last_name) AS athlete, 
    payments.amount, 
    payments.payment_method, 
    payments.payment_date
    FROM payments
    JOIN athletes ON payments.athlete_id = athletes.id
  `;

  if (athlete_id) {
    query += ` WHERE athletes.id = ? ORDER BY payments.payment_date DESC`;
    promisePool.query(query, [athlete_id])
      .then(([results]) => {
        res.json(results);
      })
      .catch((err) => {
        console.error(err);
        return res.status(500).send('Error al obtener pagos');
      });
  } else {
    query += ` ORDER BY payments.payment_date DESC`;
    promisePool.query(query)
      .then(([results]) => {
        res.json(results);
      })
      .catch((err) => {
        console.error(err);
        return res.status(500).send('Error al obtener pagos');
      });
  }
});

// Registrar un pago
app.post('/api/payments', (req, res) => {
  const { athlete_id, amount, payment_method, payment_date } = req.body;

  promisePool.query(
    'INSERT INTO payments (athlete_id, amount, payment_method, payment_date) VALUES (?, ?, ?, ?)',
    [athlete_id, amount, payment_method, payment_date]
  )
    .then(([result]) => {
      promisePool.query('UPDATE athletes SET amount_due = amount_due - ? WHERE id = ?', [amount, athlete_id])
        .then(([result]) => {
          const message = `Se ha registrado un pago de $${amount} el ${payment_date}.`;
          promisePool.query('INSERT INTO notifications (message) VALUES (?)', [message])
            .then(([result]) => {
              res.status(201).send('Pago registrado con éxito');
            })
            .catch((err) => {
              console.error(err);
              return res.status(500).send('Error al crear la notificación');
            });
        })
        .catch((err) => {
          console.error(err);
          return res.status(500).send('Error al actualizar el monto adeudado');
        });
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al registrar el pago');
    });
});

// ===================== Funcionalidad de Inventario ===================== //

// Obtener inventario
app.get('/api/inventory', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'No tienes permiso para acceder al inventario' });
  }
  promisePool.query('SELECT * FROM inventory ORDER BY created_at DESC')
    .then(([results]) => {
      res.json(results);
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al obtener el inventario');
    });
});

// Agregar un nuevo implemento (con imagen)
app.post('/api/inventory', upload.single('image'), (req, res) => {
  const { name, quantity, description } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

  promisePool.query(
    'INSERT INTO inventory (name, quantity, description, image_url) VALUES (?, ?, ?, ?)',
    [name, quantity, description, imageUrl]
  )
    .then(([result]) => {
      res.status(201).send('Implemento agregado al inventario');
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al agregar implemento');
    });
});

// Editar un implemento del inventario (con imagen opcional)
app.put('/api/inventory/:id', upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { name, quantity, description } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.image_url;

  promisePool.query(
    'UPDATE inventory SET name = ?, quantity = ?, description = ?, image_url = ? WHERE id = ?',
    [name, quantity, description, imageUrl, id]
  )
    .then(([result]) => {
      res.status(200).send('Implemento actualizado');
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al actualizar implemento');
    });
});

// Eliminar un implemento (con eliminación de imagen)
app.delete('/api/inventory/:id', (req, res) => {
  const { id } = req.params;
  promisePool.query('SELECT image_url FROM inventory WHERE id = ?', [id])
    .then(([results]) => {
      if (results.length > 0) {
        const imageUrl = results[0].image_url;
        const imagePath = path.join(__dirname, imageUrl);
        fs.unlink(imagePath, (err) => {
          if (err) {
            console.error('Error al eliminar la imagen:', err);
          } else {
            console.log('Imagen eliminada correctamente');
          }
        });
        promisePool.query('DELETE FROM inventory WHERE id = ?', [id])
          .then(([result]) => {
            res.status(200).send('Implemento e imagen eliminados');
          })
          .catch((err) => {
            console.error(err);
            return res.status(500).send('Error al eliminar implemento');
          });
      } else {
        res.status(404).send('Implemento no encontrado');
      }
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al eliminar implemento');
    });
});

// ===================== Funcionalidad de Notificaciones ===================== //

// Obtener todas las notificaciones
app.get('/api/notifications', (req, res) => {
  promisePool.query('SELECT * FROM notifications ORDER BY created_at DESC')
    .then(([results]) => {
      res.json(results);
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al obtener notificaciones');
    });
});

// Crear una nueva notificación
app.post('/api/notifications', (req, res) => {
  const { message } = req.body;
  if (!message) {
    return res.status(400).send('El mensaje de la notificación es requerido');
  }

  promisePool.query('INSERT INTO notifications (message) VALUES (?)', [message])
    .then(([result]) => {
      res.status(201).send('Notificación creada con éxito');
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al crear la notificación');
    });
});

// ===================== Funcionalidad de Asistencia ===================== //

// Obtener asistencia por clase (GET)
app.get('/api/attendance', (req, res) => {
  const { class_id } = req.query;
  
  if (!class_id) {
    return res.status(400).send('class_id es requerido');
  }

  promisePool.query('SELECT * FROM attendance WHERE class_id = ?', [class_id])
    .then(([results]) => {
      res.json(results);
    })
    .catch((err) => {
      console.error('Error al obtener la lista de asistencia:', err);
      return res.status(500).send('Error al obtener la lista de asistencia');
    });
});

// Registrar asistencia de atletas (POST)
app.post('/api/attendance/athletes', (req, res) => {
  const { class_id, athlete_id, status } = req.body;

  if (!class_id || !athlete_id || !status) {
    return res.status(400).send('Todos los campos son obligatorios');
  }

  promisePool.query(
    'INSERT INTO attendance (class_id, athlete_id, status) VALUES (?, ?, ?)',
    [class_id, athlete_id, status]
  )
    .then(([result]) => {
      res.status(201).send('Asistencia registrada exitosamente');
    })
    .catch((err) => {
      console.error('Error al registrar la asistencia:', err);
      return res.status(500).send('Error al registrar la asistencia');
    });
});

// Registrar asistencia (entrenadores y admins) (POST)
app.post('/api/attendance', authenticateToken, (req, res) => {
  const { athletes, trainer_id, class_id, date, time, notes } = req.body;

  if (!athletes || !trainer_id || !class_id) {
    return res.status(400).send('Los campos athletes, trainer_id y class_id son requeridos.');
  }

  promisePool.query(
    'INSERT INTO attendance (trainer_id, class_id, date, time, notes) VALUES (?, ?, ?, ?, ?)',
    [trainer_id, class_id, date, time, notes]
  )
    .then(([result]) => {
      const attendanceId = result.insertId;

      athletes.forEach((athleteId) => {
        promisePool.query(
          'INSERT INTO attendance_athletes (attendance_id, athlete_id) VALUES (?, ?)',
          [attendanceId, athleteId]
        )
          .catch((err) => {
            console.error('Error al guardar la asistencia de atletas:', err);
          });
      });

      const message = `Se ha pasado lista para la clase del ${date} a las ${time}.`;
      promisePool.query('INSERT INTO notifications (message) VALUES (?)', [message])
        .catch((err) => {
          console.error('Error al crear la notificación:', err);
        });

      res.status(201).send('Registro de asistencia guardado exitosamente');
    })
    .catch((err) => {
      console.error('Error al guardar la asistencia:', err);
      return res.status(500).send('Error al guardar la asistencia');
    });
});

app.get('/api/attendance/detailed', (req, res) => {
  const { class_id } = req.query;

  if (!class_id) {
    return res.status(400).send('class_id es requerido');
  }

  const query = `
    SELECT 
      a.id,
      a.date,
      a.time,
      a.notes,
      t.first_name AS trainer_first_name,
      t.last_name AS trainer_last_name,
      ct.name AS class_name,
      GROUP_CONCAT(
        JSON_OBJECT(
          'first_name', ath.first_name,
          'last_name', ath.last_name
        )
      ) AS athletes
    FROM attendance a
    LEFT JOIN trainers t ON a.trainer_id = t.id
    LEFT JOIN class_type ct ON a.class_id = ct.id
    LEFT JOIN attendance_athletes aa ON aa.attendance_id = a.id
    LEFT JOIN athletes ath ON aa.athlete_id = ath.id
    WHERE a.class_id = ?
    GROUP BY a.id, t.first_name, t.last_name, ct.name
  `;

  promisePool.query(query, [class_id])
    .then(([results]) => {
      // Parsear el resultado de GROUP_CONCAT
      results = results.map(row => ({
        ...row,
        athletes: row.athletes ? JSON.parse(`[${row.athletes}]`) : []
      }));

      res.json(results);
    })
    .catch((err) => {
      console.error('Error al obtener la lista de asistencia detallada:', err);
      return res.status(500).send('Error al obtener la lista de asistencia');
    });
});

app.post('/api/register', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Faltan campos' });
  }

  const username = email.split('@')[0]; // Usar parte del correo como nombre de usuario predeterminado
  promisePool.query(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
    [username, email, password]
  )
    .then(([result]) => {
      res.status(201).json({ id: result.insertId, email });
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).json({ message: 'Error al registrar usuario' });
    });
});

// Inicio de sesión
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log('Intento de login:', { email });

    const [users] = await promisePool.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    const user = users[0];
    if (password !== user.password) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role }, 
      process.env.JWT_SECRET || 'tu_secreto_jwt', 
      { expiresIn: '24h' }
    );

    console.log('Login exitoso para:', email);
    res.json({ token, role: user.role });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// ===================== Funcionalidad de Clases ===================== //

app.get('/api/classes', (req, res) => {
  promisePool.query(`
    SELECT 
      classes.*, 
      trainers.first_name AS trainer_first_name, 
      trainers.last_name AS trainer_last_name, 
      class_type.name AS class_type_name
    FROM classes
    JOIN trainers ON classes.trainer_id = trainers.id
    JOIN class_type ON classes.class_type = class_type.id
  `)
    .then(([results]) => {
      res.json(results);
    })
    .catch((err) => {
      console.error('Error al obtener clases:', err);
      return res.status(500).send('Error al obtener clases');
    });
});

app.get('/api/class_type', (req, res) => {
  promisePool.query('SELECT * FROM class_type ORDER BY id ASC')
    .then(([results]) => {
      res.json(results);
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al obtener los tipos de clases');
    });
});

// Registrar una nueva clase
app.post('/api/classes', (req, res) => {
  const { trainer_id, class_type, date, time, duration } = req.body;

  if (!class_type) {
    return res.status(400).send('class_type es requerido');
  }

  promisePool.query(
    'INSERT INTO classes (trainer_id, class_type, date, time, duration) VALUES (?, ?, ?, ?, ?)',
    [trainer_id, class_type, date, time, duration]
  )
    .then(([result]) => {
      res.status(201).json({ id: result.insertId });
    })
    .catch((err) => {
      console.error('Error al registrar la clase:', err);
      return res.status(500).send('Error al registrar la clase');
    });
});

app.put('/api/classes/:id', (req, res) => {
  const { id } = req.params;
  const { trainer_id, class_type, date, time, duration } = req.body;

  promisePool.query(
    'UPDATE classes SET trainer_id = ?, class_type = ?, date = ?, time = ?, duration = ? WHERE id = ?',
    [trainer_id, class_type, date, time, duration, id]
  )
    .then(([result]) => {
      if (result.affectedRows === 0) {
        return res.status(404).send('Clase no encontrada');
      }
      res.status(200).json({ id });
    })
    .catch((err) => {
      console.error('Error al actualizar la clase:', err);
      return res.status(500).send('Error al actualizar la clase');
    });
});

app.delete('/api/classes/:id', (req, res) => {
  const { id } = req.params;
  promisePool.query('DELETE FROM classes WHERE id = ?', [id])
    .then(([result]) => {
      res.status(200).send(`Clase con id ${id} eliminada`);
    })
    .catch((err) => {
      console.error(err);
      return res.status(500).send('Error al eliminar la clase');
    });
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    message: err.message || 'Error interno del servidor',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// Manejo de rutas no encontradas
app.use((req, res) => {
  res.status(404).json({ message: 'Ruta no encontrada' });
});

// Iniciar el servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en http://0.0.0.0:${PORT}`);
  console.log('Presiona CTRL + C para detener el servidor');
});