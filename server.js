// server.js - Đã nâng cấp bảo mật JWT & Dotenv
require('dotenv').config(); // Load bảo mật từ file .env
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const mqtt = require('mqtt');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken'); // Thư viện mới

// --- CẤU HÌNH ---
const SUPER_ADMIN = "Mikeyiy"; 
const JWT_SECRET = process.env.JWT_SECRET; // Lấy từ .env

// --- GỬI EMAIL ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// --- KẾT NỐI MONGODB ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB OK!"))
    .catch(err => console.log("❌ Lỗi DB:", err));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true },
    role: { type: String, default: 'viewer' },
    resetToken: String, resetTokenExpiration: Date
});
const User = mongoose.model('User', UserSchema);

app.use(express.static('public'));
app.use(bodyParser.json());

// --- MQTT ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_ROOT = 'demo_iot_vn_2025'; 
const TOPIC_CMD = 'shadowfox/commands';
mqttClient.on('connect', () => { mqttClient.subscribe(`${TOPIC_ROOT}/+/+`); });
mqttClient.on('message', (topic, message) => io.emit('sensor_data', { topic, value: message.toString() }));

// --- MIDDLEWARE BẢO MẬT (QUAN TRỌNG NHẤT) ---
// Hàm này chặn mọi request không có Token hợp lệ
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Lấy token từ header "Bearer <token>"

    if (!token) return res.status(401).json({ success: false, message: "Thiếu Token đăng nhập!" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Token không hợp lệ hoặc hết hạn!" });
        req.user = user; // Lưu thông tin người dùng đã giải mã vào biến req.user
        next(); // Cho phép đi tiếp
    });
}

// --- API AUTH ---
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (await User.findOne({ username })) return res.json({ success: false, message: "Tên đã tồn tại!" });

    const role = (username === SUPER_ADMIN) ? 'admin' : 'viewer';
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, email, role });
    await newUser.save();
    res.json({ success: true, message: "Đăng ký thành công!" });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) 
        return res.json({ success: false, message: "Sai tài khoản/mật khẩu!" });

    const finalRole = (username === SUPER_ADMIN) ? 'admin' : user.role;

    // TẠO TOKEN: Gói tên và quyền vào trong Token
    const token = jwt.sign({ username: user.username, role: finalRole }, JWT_SECRET, { expiresIn: '24h' });
    
    // Trả về Token cho Client
    res.json({ success: true, username: user.username, role: finalRole, token: token });
});

// --- CÁC API CẦN BẢO MẬT (Dùng middleware authenticateToken) ---

// 1. Lấy danh sách user
app.post('/api/list-users', authenticateToken, async (req, res) => {
    // Bây giờ ta kiểm tra quyền từ Token (req.user), KHÔNG tin body nữa
    if (req.user.role !== 'admin' && req.user.username !== SUPER_ADMIN) 
        return res.json({ success: false, message: "Không có quyền!" });

    const users = await User.find({}, 'username email role');
    res.json({ success: true, users });
});

// 2. Đổi quyền
app.post('/api/set-user-role', authenticateToken, async (req, res) => {
    const { targetUser, newRole } = req.body;
    const requestBy = req.user.username; // Lấy tên người yêu cầu từ Token an toàn

    if (req.user.role !== 'admin' && requestBy !== SUPER_ADMIN) 
        return res.json({ success: false, message: "Không có quyền!" });

    if (targetUser === SUPER_ADMIN) 
        return res.json({ success: false, message: "Không thể hạ bệ VUA!" });

    await User.updateOne({ username: targetUser }, { role: newRole });
    console.log(`👑 ${requestBy} đã đổi quyền của ${targetUser} thành ${newRole}`);
    res.json({ success: true, message: "Cập nhật thành công!" });
});

// 3. API Bơm
app.post('/api/control-pump', authenticateToken, async (req, res) => {
    const { action } = req.body;
    // Kiểm tra quyền từ Token
    if (req.user.role === 'admin' || req.user.username === SUPER_ADMIN) {
        mqttClient.publish(TOPIC_CMD, JSON.stringify({ device: 'pump', state: action === 'ON' }));
        res.json({ success: true, message: "Thành công" });
    } else {
        res.status(403).json({ success: false, message: "Không có quyền!" });
    }
});

// 4. Xóa User
app.post('/api/delete-user', authenticateToken, async (req, res) => {
    const { targetUser } = req.body;
    const requestBy = req.user.username; // Lấy từ Token

    if (requestBy !== SUPER_ADMIN) {
        return res.json({ success: false, message: "Chỉ Super Admin mới được xóa!" });
    }
    if (targetUser === SUPER_ADMIN) {
        return res.json({ success: false, message: "Không thể xóa chính mình!" });
    }

    try {
        await User.deleteOne({ username: targetUser });
        console.log(`❌ ${requestBy} đã xóa user: ${targetUser}`);
        res.json({ success: true, message: `Đã xóa tài khoản ${targetUser}!` });
    } catch (e) {
        res.json({ success: false, message: "Lỗi Database" });
    }
});

// 5. Đổi mật khẩu
app.post('/api/change-password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const username = req.user.username; // Chỉ đổi được cho chính mình (từ Token)

    const user = await User.findOne({ username });
    if (!user) return res.json({ success: false, message: "Lỗi user" });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.json({ success: false, message: "Mật khẩu cũ sai!" });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ success: true, message: "Đổi mật khẩu thành công!" });
});

// API Quên mật khẩu giữ nguyên (hoặc nâng cấp sau)
app.post('/forgot-password', async (req, res) => { /* Code cũ... */ });

http.listen(3000, () => console.log('🚀 Server running with JWT Security...'));