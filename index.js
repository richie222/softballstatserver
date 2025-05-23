require('dotenv').config(); // Load environment variables

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000; // Use port from environment or default to 3000

// Database connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Middleware to parse JSON request bodies
app.use(express.json());

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Get token from "Bearer TOKEN"

    if (token == null) {
        return res.sendStatus(401); // If no token, unauthorized
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // If token is invalid, forbidden
        }
        req.user = user; // Attach user information to the request
        next(); // Proceed to the next middleware or route handler
    });
};


// --- API Routes ---

// Registration Route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Basic validation
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Usuario, correo y conraseña son datos requeridos para el registro' });
    }

    if (password.length < 8) {
        return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres' });
    }

    try {
        // Check if email already exists
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ message: 'Email ya se encuentra registrado' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        // Insert the new user into the database
        const newUser = await pool.query(
            'INSERT INTO users (username, email, password, id_team) VALUES ($1, $2, $3, 1) RETURNING id, username, email',
            [username, email, hashedPassword]
        );

        res.status(201).json({ message: 'Usuario registrado exitosamente', user: newUser.rows[0] });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Ha ocurrido un error el registro' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña son datos obligatorios' });
    }

    try {
        // Find the user by username
        const userResult = await pool.query('SELECT Id, UserName, password, Email, Rol, SuperUser FROM users WHERE username = $1', [username]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: 'Usuario no se encuentra registrado.' });
        }

        const user = userResult.rows[0];

        // Compare the provided password with the stored hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Contraseña incorecta.' });
        }

        // Generate a JWT for session management
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.status(200).json({ message: 'Sessión iniciada exitosamente.',
                                token,
                             user: {
                                id: user.id,
                                username: user.username,
                                email: user.email,
                                rol: user.rol,
                                superuser: user.superuser}});

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Ha ocurrido un error al iniciar sesión' });
    }
});

// Logout Route (Protected)
app.post('/logout', authenticateToken, (req, res) => {
    // For JWTs, server-side logout is often just a confirmation.
    // The client is responsible for discarding the token.
    res.status(200).json({ message: 'Sessión cerrada exitosamente.' });
});

// Crear una nueva season
app.post('/seasons', authenticateToken, async (req, res) => {
    const { name, date_ini } = req.body;

    // Validación básica
    if (!name || !date_ini) {
        return res.status(400).json({ message: 'Name and date_ini are required.' });
    }

    try {
        // Insertar la nueva season en la base de datos
        const result = await pool.query(
            'INSERT INTO seasons (name, date_ini) VALUES ($1, $2) RETURNING name, date_ini',
            [name, date_ini]
        );

        res.status(201).json({ message: 'Season created successfully.', season: result.rows[0] });
    } catch (error) {
        console.error('Error creating season:', error);
        res.status(500).json({ message: 'An error occurred while creating the season.' });
    }
});

// Listar todas las seasons
app.get('/seasons', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, date_ini FROM seasons ORDER BY date_ini DESC');
        
        res.status(200).json({
            message: 'Seasons retrieved successfully.',
            count: result.rows.length,
            seasons: result.rows
        });
    } catch (error) {
        console.error('Error retrieving seasons:', error);
        res.status(500).json({ message: 'An error occurred while retrieving seasons.' });
    }
});

// Editar una season por id
app.put('/seasons/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, date_ini } = req.body;

    // Validación básica
    if (!name || !date_ini) {
        return res.status(400).json({ message: 'Nombre y Fecha son requeridos.' });
    }

    try {
        // Actualizar la season en la base de datos
        const result = await pool.query(
            'UPDATE seasons SET name = $1, date_ini = $2 WHERE id = $3 RETURNING id, name, date_ini',
            [name, date_ini, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Temporada no encontrada.' });
        }

        res.status(200).json({
            message: 'Temporada actualizada exitosamente.',
            season: result.rows[0]
        });
    } catch (error) {
        console.error('Error actualizando temporada:', error);
        res.status(500).json({ message: 'Ha ocurrido un error mientras se actualizaba la temporada.' });
    }
});

// Listar juegos con filtro opcional por id_season
app.get('/games', async (req, res) => {
    try {
        let query = `
            SELECT 
                g.id, 
                g.id_season, 
                g.win, 
                g.team_score, 
                g.opposing_team_name, 
                g.opposing_team_score
            FROM games g
        `;
        
        const params = [];
        
        // Filtrar por id_season si se proporciona
        if (req.query.id_season) {
            params.push(req.query.id_season);
            query += ` WHERE g.id_season = $1`;
        }
        
        // Ordenar por id (más recientes primero)
        query += ` ORDER BY g.id DESC`;
        
        const result = await pool.query(query, params);
        
        // Opcional: Obtener información de la temporada si se filtró por id_season
        let seasonInfo = null;
        if (req.query.id_season && result.rows.length > 0) {
            const seasonResult = await pool.query(
                'SELECT name, date_ini FROM seasons WHERE id = $1',
                [req.query.id_season]
            );
            
            if (seasonResult.rows.length > 0) {
                seasonInfo = seasonResult.rows[0];
            }
        }
        
        res.status(200).json({
            message: 'Games retrieved successfully.',
            count: result.rows.length,
            season: seasonInfo,
            games: result.rows
        });
    } catch (error) {
        console.error('Error retrieving games:', error);
        res.status(500).json({ message: 'An error occurred while retrieving games.' });
    }
});

// Crear un nuevo juego
app.post('/games', authenticateToken, async (req, res) => {
    const { id_season, team_score, opposing_team_name, opposing_team_score } = req.body;

    // Validación básica
    if (!id_season || team_score === undefined || !opposing_team_name || opposing_team_score === undefined) {
        return res.status(400).json({ 
            message: 'Los campos son requeridos: Id Torneo, Carreras Toros, Nombre Equipo Rival, Carreras Equipo Rival' 
        });
    }

    // Validar que los puntajes sean números enteros positivos
    if (!Number.isInteger(team_score) || team_score < 0 || 
        !Number.isInteger(opposing_team_score) || opposing_team_score < 0) {
        return res.status(400).json({ message: 'Las carreras deben ser números enteros.' });
    }

    try {
        // Verificar que la temporada existe
        const seasonCheck = await pool.query('SELECT id FROM seasons WHERE id = $1', [id_season]);
        if (seasonCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Torneo no encontrado.' });
        }

        // Determinar si el equipo ganó
        const win = team_score > opposing_team_score;

        // Insertar el nuevo juego en la base de datos
        const result = await pool.query(
            `INSERT INTO games 
            (id_season, win, team_score, opposing_team_name, opposing_team_score) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id, id_season, win, team_score, opposing_team_name, opposing_team_score`,
            [id_season, win, team_score, opposing_team_name, opposing_team_score]
        );

        res.status(201).json({
            message: 'Juego creado exitosamente.',
            game: result.rows[0]
        });
    } catch (error) {
        console.error('Error creando el juego:', error);
        res.status(500).json({ message: 'Ha ocurrido un error al crear el juego.' });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
