const express = require("express");
const http = require("http");
const { default: mongoose } = require("mongoose");
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const server = http.createServer(app);
const io = new Server(server);

// MongoDB bağlantısı
mongoose
  .connect("mongodb://localhost:27017/chatdb", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("MongoDB connection successful");
  })
  .catch((err) => console.error("MongoDB connection error:", err));

// Şema tanımlamaları
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  content: String,
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "user"], default: "user" },
  token: { type: String },
  lastSeen: { type: Date },
  online: { type: Boolean, default: false },
});

const Message = mongoose.model("Message", messageSchema);
const User = mongoose.model("User", userSchema);

// JWT token doğrulama middleware
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Token not provided" });
    }

    const decoded = jwt.verify(token, "your-secret-key");
    const user = await User.findOne({ _id: decoded.userId });

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Socket.IO bağlantı yönetimi
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentication token required"));
    }

    const decoded = jwt.verify(token, "your-secret-key");
    const user = await User.findOne({ _id: decoded.userId });

    if (!user) {
      return next(new Error("User not found"));
    }

    socket.user = user;
    next();
  } catch (error) {
    next(new Error("Invalid token"));
  }
});

// Socket bağlantı yönetimi
io.on("connection", async (socket) => {
  const user = socket.user;

  // Kullanıcıyı online yap
  await User.findByIdAndUpdate(user._id, {
    online: true,
    lastSeen: new Date(),
  });

  // Kullanıcıya özel oda oluştur
  socket.join(user._id.toString());

  // Tüm kullanıcılara online durumu bildir
  io.emit("user status", { userId: user._id, online: true });

  socket.on("chat message", async (data) => {
    try {
      const message = new Message({
        sender: user._id,
        receiver: data.receiverId,
        content: data.message,
      });

      await message.save();

      // Mesajı hem gönderen hem alıcıya ilet
      io.to(data.receiverId).to(user._id.toString()).emit("chat message", {
        messageId: message._id,
        sender: user._id,
        receiver: data.receiverId,
        content: data.message,
        timestamp: message.timestamp,
      });
    } catch (error) {
      console.error("Message sending error:", error);
    }
  });

  socket.on("disconnect", async () => {
    // Kullanıcıyı offline yap
    await User.findByIdAndUpdate(user._id, {
      online: false,
      lastSeen: new Date(),
    });

    // Tüm kullanıcılara offline durumu bildir
    io.emit("user status", { userId: user._id, online: false });
  });
});

// API Endpoints

// Kullanıcı listesi endpoint'i
app.get("/users", verifyToken, async (req, res) => {
  try {
    const users = await User.find(
      { _id: { $ne: req.user._id } }, // Kendisi hariç tüm kullanıcılar
      { password: 0, token: 0 } // Hassas bilgileri çıkar
    );
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Error fetching users" });
  }
});

// Mesaj geçmişi endpoint'i
app.get("/messages", verifyToken, async (req, res) => {
  try {
    // Assuming `verifyToken` adds `userId` to `req.user`

    const userId = req.user._id; // Extract user ID from token payload
    console.log(userId);

    // Find messages where the authenticated user is either the sender or receiver
    const messages = await Message.find({
      $or: [
        { sender: req.user._id, receiver: userId },
        { sender: userId, receiver: req.user._id },
      ],
    })
      .sort({ timestamp: 1 }) // Sort messages by timestamp in ascending order
      .populate("sender", "username") // Populate only the username field for sender
      .populate("receiver", "username"); // Populate only the username field for receiver

    res.json(messages); // Return the messages as JSON
  } catch (error) {
    res.status(500).json({ error: "Error fetching messages" });
  }
});

// Kullanıcı kaydı endpoint'i
app.post("/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;

    if (await User.findOne({ username })) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
      role,
    });

    await user.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ error: "Registration error" });
  }
});

// Giriş endpoint'i
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      "your-secret-key",
      { expiresIn: "24h" }
    );

    user.token = token;
    await user.save();

    res.json({
      token,
      user: {
        _id: user._id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Login error" });
  }
});

// Mesajları okundu olarak işaretle
app.post("/messages/read", verifyToken, async (req, res) => {
  try {
    const { senderId } = req.body;

    await Message.updateMany(
      {
        sender: senderId,
        receiver: req.user._id,
        read: false,
      },
      { read: true }
    );

    res.json({ message: "Messages marked as read" });
  } catch (error) {
    res.status(500).json({ error: "Error marking messages as read" });
  }
});

// HTML dosyasını serve et
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// Server'ı başlat
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
