import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import cors from "cors";
import session from "express-session";

const app = express();
const port = 3000;
const saltRounds = 10;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(session({
  secret: 'pavanmalige',
  resave: false,
  saveUninitialized: true,
}));

// Database connection
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "skill",
  password: "Pavan@13",
  port: 5432,
});
db.connect();

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/jobs", async (req, res) => {
  const result = await db.query('SELECT * FROM jobs ORDER BY posted_date DESC');
  res.render('jobs.ejs', { jobs: result.rows });
});

app.get("/profile", async (req, res) => {
  const username = req.session.username;

  if (!username) {
    return res.redirect("/login");
  }

  res.render("secrets.ejs", { username });
});

app.post("/register", async (req, res) => {
  const user = req.body.user;
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    const userCheck = await db.query("SELECT * FROM users WHERE username = $1", [user]);

    if (userCheck.rows.length > 0) {
      res.send("Username already taken");
    } else if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.send("Server error");
        } else {
          await db.query(
            "INSERT INTO users (email, password, username) VALUES ($1, $2, $3)",
            [email, hash, user]
          );

          req.session.username = user; // ✅ Save username in session
          res.redirect("/profile");
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.send("Server error");
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;

      bcrypt.compare(loginPassword, storedHashedPassword, (err, isMatch) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          res.send("Server error");
        } else {
          if (isMatch) {
            req.session.username = user.username; // ✅ Save username from DB
            res.redirect("/profile");
          } else {
            res.send("Incorrect Password");
          }
        }
      });
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
    res.send("Server error");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
