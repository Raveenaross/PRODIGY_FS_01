const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const session = require('express-session');
const app = express();
const port = 3000;

// MySQL connection pool
const pool = mysql.createPool({
    connectionLimit: 10,
    host: 'localhost',
    user: 'root',
    password: 'Macro25**',
    database: 'secure_auth'
});

// Middleware to parse URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: false }));

// Session middleware setup
app.use(session({
    secret: 'No Secrets', // Change this to a secure secret
    resave: false,
    saveUninitialized: true
}));

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.loggedIn) {
        return next();
    } else {
        res.redirect('/login.html');
    }
}

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Serve signup.html at the root URL
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/signup.html');
});

// Handle registration form submission
app.post('/signup', (req, res) => {
    const { nm, addr, psw } = req.body;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error connecting to database: ', err);
            return res.status(500).send('Internal Server Error');
        }

        const checkUserSql = 'SELECT * FROM users WHERE email = ?';
        connection.query(checkUserSql, [addr], (error, results) => {
            if (error) {
                connection.release();
                console.error('Error querying database: ', error);
                return res.status(500).send('Internal Server Error');
            }

            if (results.length > 0) {
                connection.release();
                return res.redirect('/login.html');
            } else {
                const insertSql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
                connection.query(insertSql, [nm, addr, psw], (insertError, insertResults) => {
                    connection.release();

                    if (insertError) {
                        console.error('Error inserting user: ', insertError);
                        return res.status(500).send('Internal Server Error');
                    }

                    res.redirect('/login.html');
                });
            }
        });
    });
});

// Serve home.html at /home, protected route
app.get('/home', requireAuth, (req, res) => {
    console.log('Session user:', req.session.user);
    res.sendFile(__dirname + '/public/home.html');
});

// Serve login.html at /login
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
});

// Handle login form submission
app.post('/login', (req, res) => {
    const { addr, psw } = req.body;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error connecting to database: ', err);
            return res.status(500).send('Internal Server Error');
        }

        const sql = 'SELECT * FROM users WHERE email = ? AND password = ?';
        connection.query(sql, [addr, psw], (error, results) => {
            connection.release();

            if (error) {
                console.error('Error querying database: ', error);
                return res.status(500).send('Internal Server Error');
            }

            if (results.length > 0) {
                req.session.loggedIn = true;
                req.session.user = { email: addr }; // Store user information in session if needed
                console.log('Session variables after login:', req.session);
                res.redirect('/home');
            } else {
                res.status(400).send('Login failed. Incorrect email or password.');
            }
        });
    });
});

// Logout endpoint
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session: ', err);
            return res.status(500).send('Internal Server Error');
        }
        console.log('Session destroyed.');
        res.redirect('/login.html');
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
