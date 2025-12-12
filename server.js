// server.js - Đã nâng cấp: Lưu lịch sử & Xuất Excel
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
const jwt = require('jsonwebtoken');

// --- CẤU HÌNH ---
const SUPER_ADMIN = "Mikeyiy"; 
const JWT_SECRET = process.env.JWT_SECRET; 

// --- GỬI EMAIL ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// --- KẾT NỐI MONGODB ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB OK!"))
    .catch(err => console.log("❌ Lỗi DB:", err));

// 1. Schema User (Tài khoản)
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true },
    role: { type: String, default: 'viewer' },
    resetToken: String, resetTokenExpiration: Date
});
const User = mongoose.model('User', UserSchema);

// 2. Schema SensorData (Lưu lịch sử cảm biến - MỚI)
const SensorSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now }, // Thời gian ghi
    waterLevel: Number,                           // Mực nước (%)
    isPumpOn: Boolean,                            // Bơm bật hay tắt
    isSirenOn: Boolean                            // Còi bật hay tắt
});
const SensorData = mongoose.model('SensorData', SensorSchema);

app.use(express.static('public'));
app.use(bodyParser.json());

// --- MQTT ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_DATA = 'shadowfox/system_data'; // Topic dữ liệu cảm biến
const TOPIC_CMD = 'shadowfox/commands';     // Topic điều khiển

mqttClient.on('connect', () => { 
    // Đăng ký nhận tin từ cả topic dữ liệu và các topic khác nếu cần
    mqttClient.subscribe(TOPIC_DATA); 
    console.log("✅ Đã kết nối MQTT và lắng nghe:", TOPIC_DATA);
});

// XỬ LÝ KHI NHẬN TIN NHẮN MQTT
mqttClient.on('message', async (topic, message) => {
    const msgString = message.toString();
    
    // 1. Gửi ngay cho Frontend qua Socket (để vẽ biểu đồ realtime)
    io.emit('sensor_data', { topic, value: msgString });

    // 2. LƯU VÀO DATABASE (Phần mới thêm)
    if (topic === TOPIC_DATA) {
        try {
            const data = JSON.parse(msgString);
            
            // Tạo bản ghi mới
            const newRecord = new SensorData({
                waterLevel: data.waterLevel,
                isPumpOn: data.isPumpOn,
                isSirenOn: data.isSirenOn
            });

            // Lưu vào MongoDB
            await newRecord.save();
            // console.log(`💾 Đã lưu: Nước ${data.waterLevel}%`); 
        } catch (e) {
            console.error("❌ Lỗi lưu dữ liệu cảm biến:", e.message);
        }
    }
});

// --- MIDDLEWARE BẢO MẬT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ success: false, message: "Thiếu Token đăng nhập!" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Token không hợp lệ!" });
        req.user = user;
        next();
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
    const token = jwt.sign({ username: user.username, role: finalRole }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({ success: true, username: user.username, role: finalRole, token: token });
});

// --- CÁC API BẢO MẬT ---

// 1. Lấy danh sách user
app.post('/api/list-users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.username !== SUPER_ADMIN) 
        return res.json({ success: false, message: "Không có quyền!" });

    const users = await User.find({}, 'username email role');
    res.json({ success: true, users });
});

// 2. Đổi quyền
app.post('/api/set-user-role', authenticateToken, async (req, res) => {
    const { targetUser, newRole } = req.body;
    const requestBy = req.user.username;

    if (req.user.role !== 'admin' && requestBy !== SUPER_ADMIN) 
        return res.json({ success: false, message: "Không có quyền!" });
    if (targetUser === SUPER_ADMIN) 
        return res.json({ success: false, message: "Không thể hạ bệ VUA!" });

    await User.updateOne({ username: targetUser }, { role: newRole });
    res.json({ success: true, message: "Cập nhật thành công!" });
});

// 3. API Bơm
app.post('/api/control-pump', authenticateToken, async (req, res) => {
    const { action } = req.body;
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
    const requestBy = req.user.username;

    if (requestBy !== SUPER_ADMIN) return res.json({ success: false, message: "Chỉ Super Admin mới được xóa!" });
    if (targetUser === SUPER_ADMIN) return res.json({ success: false, message: "Không thể xóa chính mình!" });

    try {
        await User.deleteOne({ username: targetUser });
        res.json({ success: true, message: `Đã xóa tài khoản ${targetUser}!` });
    } catch (e) {
        res.json({ success: false, message: "Lỗi Database" });
    }
});

// 5. Đổi mật khẩu
app.post('/api/change-password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const username = req.user.username;

    const user = await User.findOne({ username });
    if (!user) return res.json({ success: false, message: "Lỗi user" });
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.json({ success: false, message: "Mật khẩu cũ sai!" });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ success: true, message: "Đổi mật khẩu thành công!" });
});

// 6. API Lấy lịch sử dữ liệu (MỚI - Cho chức năng Export)
app.post('/api/sensor-history', authenticateToken, async (req, res) => {
    try {
        // Lấy 500 dòng dữ liệu mới nhất, sắp xếp từ mới đến cũ
        const history = await SensorData.find().sort({ timestamp: -1 }).limit(500);
        res.json({ success: true, data: history });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Lỗi lấy dữ liệu Server" });
    }
});

// API Quên mật khẩu (Giữ nguyên logic cũ nếu có)
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    // Logic gửi email reset pass ở đây (nếu bạn có code cũ thì paste lại vào đây)
    res.json({ success: false, message: "Tính năng đang bảo trì" }); 
});

http.listen(3000, () => console.log('🚀 Server running with Sensor History...'));