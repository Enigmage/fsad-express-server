import express, { Request, Response } from "express";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;
const secretKey = process.env.SECRET || "2023sl93054";

const users = [
  { id: 1, username: "user1", password: "password1", role: "user" },
  { id: 2, username: "user2", password: "password2", role: "user" },
];

async function createPasswordHash(password: string) {
  const saltRounds = 10;
  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (err) {
    console.error(err);
  }
}

async function compareHashPassword(
  password: string,
  hashPassword: string,
): Promise<Boolean> {
  const isMatch = await bcrypt.compare(password, hashPassword);
  return isMatch;
}

app.post("/register", async (req: Request, res: Response) => {
  const { username, password, role } = req.body;
  const user = users.find(u => u.username == username);
  if (user) {
    return res.status(400).json({ message: "Username already exists" });
  }
  const passwordHash = (await createPasswordHash(password)) || "";
  if (users.length > 0) {
    const newId = users[users.length - 1].id + 1;
    users.push({
      id: newId,
      username: username,
      password: passwordHash,
      role: role,
    });
    return res.status(200).json(users);
  }
});

// Login route
app.post("/login", async (req: Request, res: Response) => {
  // Mocked authentication logic
  const { username, password } = req.body;
  let user;
  if (username === "user1" || username === "user2") {
    user = users.find(u => u.username === username && u.password === password);
  } else {
    for (let i = 0; i < users.length; i++) {
      const isMatch = await compareHashPassword(password, users[i].password);
      if (username === users[i].username && isMatch) {
        user = users[i];
        break;
      }
    }
  }

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate JWT token
  const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: "1h" });

  res.json({ token });
});

// Dummy protected route
app.get("/protected", authenticateToken, (_req, res) => {
  res.json({ message: "Protected route accessed successfully" });
});

app.get("/admin", authenticateToken, authenticateAdmin, (_req, res) => {
  res.json({ message: "Admin route accessed successfully" });
});

app.get("/user", authenticateToken, (_req, res) => {
  res.json({ message: "User route accessed successfully" });
});

// Middleware to authenticate JWT token
function authenticateToken(req: any, res: any, next: any) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, secretKey, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

// Middleware to authenticate role
function authenticateAdmin(req: any, res: any, next: any) {
  const user = users.find(u => u.id === req.user.userId);
  if (user && `${user.role}` === "admin") {
    next();
  } else {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
