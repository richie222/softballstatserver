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
        const result = await pool.query('SELECT id, name, date_ini FROM seasons ORDER BY date_ini ASC');
        
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
        query += ` ORDER BY g.id ASC`;
        
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

// Crear un nuevo registro de datos ofensivos de jugador en un juego
app.post('/offensive-player-data', authenticateToken, async (req, res) => {
    const { 
        id_season, 
        id_game, 
        id_player, 
        vb, 
        hit, 
        "2b": doubles, 
        "3b": triples, 
        hr, 
        bb, 
        kk 
    } = req.body;

    // Validación básica de campos requeridos
    const requiredFields = ['id_season', 'id_game', 'id_player', 'vb', 'hit', '2b', '3b', 'hr', 'bb', 'kk'];
    const missingFields = requiredFields.filter(field => {
        // Manejo especial para campos con nombres que son palabras reservadas
        if (field === '2b') return doubles === undefined;
        if (field === '3b') return triples === undefined;
        return req.body[field] === undefined;
    });

    if (missingFields.length > 0) {
        return res.status(400).json({ 
            message: `Missing required fields: ${missingFields.join(', ')}` 
        });
    }

    // Validar que todos los campos numéricos sean enteros no negativos
    const numericFields = ['vb', 'hit', '2b', '3b', 'hr', 'bb', 'kk'];
    const invalidFields = numericFields.filter(field => {
        let value;
        if (field === '2b') value = doubles;
        else if (field === '3b') value = triples;
        else value = req.body[field];
        
        return !Number.isInteger(value) || value < 0;
    });

    if (invalidFields.length > 0) {
        return res.status(400).json({ 
            message: `Invalid values for fields: ${invalidFields.join(', ')}. Must be non-negative integers.` 
        });
    }

    try {
        // Verificar que la temporada existe
        const seasonCheck = await pool.query('SELECT id FROM seasons WHERE id = $1', [id_season]);
        if (seasonCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Season not found.' });
        }

        // Verificar que el juego existe
        const gameCheck = await pool.query('SELECT id FROM games WHERE id = $1', [id_game]);
        if (gameCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Game not found.' });
        }

        // Verificar que el jugador existe
        const playerCheck = await pool.query('SELECT id FROM users WHERE id = $1', [id_player]);
        if (playerCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Player not found.' });
        }

        // Verificar si ya existe un registro para este jugador en este juego
        const existingCheck = await pool.query(
            'SELECT id FROM offensive_player_data_games WHERE id_game = $1 AND id_player = $2',
            [id_game, id_player]
        );

        if (existingCheck.rows.length > 0) {
            return res.status(409).json({ 
                message: 'A record for this player in this game already exists. Use PUT to update it.',
                record_id: existingCheck.rows[0].id
            });
        }

        // Insertar el nuevo registro
        const result = await pool.query(
            `INSERT INTO offensive_player_data_games 
            (id_season, id_game, id_player, vb, hit, "2b", "3b", hr, bb, kk) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
            RETURNING id, id_season, id_game, id_player, vb, hit, "2b" as "doubles", "3b" as "triples", hr, bb, kk, created_at, updated_at`,
            [id_season, id_game, id_player, vb, hit, doubles, triples, hr, bb, kk]
        );

        res.status(201).json({
            message: 'Offensive player data created successfully.',
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error creating offensive player data:', error);
        res.status(500).json({ message: 'An error occurred while creating offensive player data.' });
    }
});

// Listar datos ofensivos de jugadores con filtros opcionales
app.get('/offensive-player-data', async (req, res) => {
    try {
        // Construir la consulta base
        let query = `
            SELECT 
                t1.id, 
                t1.id_season, 
                t1.id_game, 
                t1.vb, 
                t1.hit, 
                t1."2b", 
                t1."3b", 
                t1.hr, 
                t1.bb, 
                t1.kk,
                t2.username as player_name
            FROM offensive_player_data_games t1, users t2
            WHERE t1.id_player = t2.id
        `;
        
        const params = [];
        let paramIndex = 1;
        
        // Filtrar por id_season si se proporciona
        if (req.query.id_season) {
            query += ` AND t1.id_season = $${paramIndex}`;
            params.push(req.query.id_season);
            paramIndex++;
        }
        
        // Filtrar por id_game si se proporciona
        if (req.query.id_game) {
            query += ` AND t1.id_game = $${paramIndex}`;
            params.push(req.query.id_game);
            paramIndex++;
        }
        
        // Filtrar por id_player si se proporciona
        if (req.query.id_player) {
            query += ` AND t1.id_player = $${paramIndex}`;
            params.push(req.query.id_player);
            paramIndex++;
        }
        
        // Ordenar por fecha de actualización (más recientes primero)
        query += ` ORDER BY t1.updated_at DESC`;
        
        // Ejecutar la consulta
        const result = await pool.query(query, params);
        
        res.status(200).json({
            message: 'Offensive player data retrieved successfully.',
            count: result.rows.length,
            data: result.rows
        });
    } catch (error) {
        console.error('Error retrieving offensive player data:', error);
        res.status(500).json({ message: 'An error occurred while retrieving offensive player data.' });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
