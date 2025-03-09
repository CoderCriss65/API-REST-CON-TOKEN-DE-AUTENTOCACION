const express = require('express');
const mysql = require('mysql2');
const jwt = require('jwt-simple');
const bcrypt = require('bcryptjs');
const cors = require('cors');

// Definir la clave secreta del JWT
const JWT_SECRET = '123';

// Crear la aplicación Express
const app = express();
const PORT = 3000;

// Middleware para permitir JSON y CORS
app.use(express.json());
app.use(cors());

// Configuración de la conexión a MySQL con los valores en crudo
const db = mysql.createConnection({
  host: 'localhost', // DB_HOST
  user: 'root', // DB_USER
  password: '123', // DB_PASSWORD
  database: 'empresa', // DB_NAME
  port: 3306, // Puerto por defecto
});

// Verificar la conexión
db.connect((err) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
    process.exit(1); // Detener la aplicación si no se puede conectar a la base de datos
  } else {
    console.log('Conectado a la base de datos MySQL');
  }
});

// Función de manejo de errores
const handleDbError = (error, res) => {
  console.error(error);
  return res.status(500).json({ message: 'Error en la base de datos.', error: error.message });
};

// Ruta para registrar un nuevo usuario
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'El nombre de usuario y la contraseña son requeridos.' });
  }

  try {
    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Guardar el usuario en la base de datos
    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(query, [username, hashedPassword], (error, result) => {
      if (error) {
        return handleDbError(error, res);
      }
      res.status(201).json({ message: 'Usuario registrado correctamente.' });
    });
  } catch (err) {
    return res.status(500).json({ message: 'Error al encriptar la contraseña.' });
  }
});

// Ruta para login de usuario (obtener el JWT)
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'El nombre de usuario y la contraseña son requeridos.' });
  }

  // Buscar el usuario en la base de datos
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (error, results) => {
    if (error) {
      return handleDbError(error, res);
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    // Comparar la contraseña con la encriptada
    bcrypt.compare(password, results[0].password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ message: 'Contraseña incorrecta.' });
      }

      // Crear el token JWT
      const payload = { id: results[0].id, username: results[0].username };
      const token = jwt.encode(payload, JWT_SECRET); // Usar la constante JWT_SECRET

      res.json({ token });
    });
  });
});

// Middleware para proteger las rutas con autenticación
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ message: 'Token requerido.' });
  }

  try {
    const decoded = jwt.decode(token, JWT_SECRET); // Usar la constante JWT_SECRET
    req.user = decoded; // Añadir al objeto `req` el usuario decodificado
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido.' });
  }
};

// Rutas CRUD protegidas con JWT

// Obtener todos los empleados
app.get('/empleados', verifyToken, (req, res) => {
  db.query('SELECT * FROM empleados', (error, results) => {
    if (error) {
      return handleDbError(error, res);
    }
    res.json(results);
  });
});

// Obtener un empleado por su ID
app.get('/empleados/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM empleados WHERE id = ?', [id], (error, results) => {
    if (error) {
      return handleDbError(error, res);
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Empleado no encontrado.' });
    }
    res.json(results[0]);
  });
});

// Agregar un nuevo empleado
app.post('/empleados', verifyToken, (req, res) => {
  const { nombre, puesto, salario } = req.body;
  if (!nombre || !puesto || !salario) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
  }

  db.query(
    'INSERT INTO empleados (nombre, puesto, salario) VALUES (?, ?, ?)',
    [nombre, puesto, salario],
    (error, result) => {
      if (error) {
        return handleDbError(error, res);
      }
      res.status(201).json({ message: 'Empleado agregado correctamente.', id: result.insertId });
    }
  );
});

// Ruta para inserción masiva de empleados
app.post("/empleados/masivo", verifyToken, (request, response) => {
  const empleados = request.body;

  // Validar que el array no esté vacío
  if (!Array.isArray(empleados) || empleados.length === 0) {
    return response.status(400).json({ mensaje: "Debe enviar un array de empleados válido." });
  }

  // Construir los valores para la consulta SQL
  const valores = empleados.map(({ nombre, puesto, salario }) => [nombre, puesto, salario]);

  // Query de inserción masiva
  const sql = "INSERT INTO empleados (nombre, puesto, salario) VALUES ?";

  db.query(sql, [valores], (error, result) => {
    if (error) {
      response.status(500).json({ error: error.message });
    } else {
      response.status(201).json({ mensaje: "Empleados agregados correctamente", filasInsertadas: result.affectedRows });
    }
  });
});

// Actualizar un empleado
app.put('/empleados/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { nombre, puesto, salario } = req.body;

  if (!nombre || !puesto || !salario) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
  }

  db.query(
    'UPDATE empleados SET nombre = ?, puesto = ?, salario = ? WHERE id = ?',
    [nombre, puesto, salario, id],
    (error, result) => {
      if (error) {
        return handleDbError(error, res);
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Empleado no encontrado.' });
      }
      res.json({ message: 'Empleado actualizado correctamente.' });
    }
  );
});

// Eliminar un empleado
app.delete('/empleados/:id', verifyToken, (req, res) => {
  const { id } = req.params;

  db.query('DELETE FROM empleados WHERE id = ?', [id], (error, result) => {
    if (error) {
      return handleDbError(error, res);
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Empleado no encontrado.' });
    }
    res.json({ message: 'Empleado eliminado correctamente.' });
  });
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
