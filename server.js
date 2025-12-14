// server.js - Phiên bản Ultimate: Full tính năng + HTTP Polling cho Camera
require('dotenv').config();
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
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// --- CẤU HÌNH ---
const SUPER_ADMIN = "Mikeyiy"; 
const JWT_SECRET = process.env.JWT_SECRET; 

// --- [MỚI] BIẾN CỜ LỆNH CHỤP ẢNH (HỘP THƯ) ---
// Biến này sẽ nhớ xem có ai đang đòi chụp ảnh không
let shouldTakePhoto = false; 

// --- GỬI EMAIL ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// --- KẾT NỐI MONGODB ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB OK!"))
    .catch(err => console.log("❌ Lỗi DB:", err));

// 1. Schema User
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true },
    role: { type: String, default: 'viewer' },
    resetToken: String, resetTokenExpiration: Date
});
const User = mongoose.model('User', UserSchema);

// 2. Schema SensorData
const SensorSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now }, 
    waterLevel: Number,                           
    isPumpOn: Boolean,                            
    isSirenOn: Boolean                            
});
const SensorData = mongoose.model('SensorData', SensorSchema);

app.use(express.static('public'));
app.use(bodyParser.json());

// --- CẤU HÌNH LƯU TRỮ ẢNH ---
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, 'event_' + Date.now() + '.jpg')
});
const upload = multer({ storage: storage });

// --- MQTT ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_DATA = 'shadowfox/system_data'; 
const TOPIC_CMD = 'shadowfox/commands';     
const TOPIC_TRIGGER = 'shadowfox/camera_trigger'; // Topic lệnh chụp ảnh

mqttClient.on('connect', () => { 
    // [CẬP NHẬT] Đăng ký nghe thêm topic Trigger để biết khi nào nước ngập
    mqttClient.subscribe([TOPIC_DATA, TOPIC_TRIGGER]); 
    console.log("✅ Đã kết nối MQTT (Data & Trigger)");
});

mqttClient.on('message', async (topic, message) => {
    const msgString = message.toString();
    
    // 1. Xử lý dữ liệu cảm biến
    if (topic === TOPIC_DATA) {
        io.emit('sensor_data', { topic, value: msgString });
        try {
            const data = JSON.parse(msgString);
            const newRecord = new SensorData({
                waterLevel: data.waterLevel,
                isPumpOn: data.isPumpOn,
                isSirenOn: data.isSirenOn
            });
            await newRecord.save();
        } catch (e) { console.error("❌ Lỗi lưu DB:", e.message); }
    }

    // 2. [MỚI] Xử lý lệnh chụp từ Gateway (Khi nước ngập)
    if (topic === TOPIC_TRIGGER && msgString === "SNAP") {
        console.log("🌊 LŨ VỀ: Gateway yêu cầu chụp ảnh!");
        shouldTakePhoto = true; // Bật cờ lên để Camera biết
    }
});

// --- [MỚI] CÁC API PHỤC VỤ CAMERA (HTTP) ---

// 1. Camera hỏi: "Có việc gì không?"
app.get('/api/check-command', (req, res) => {
    // Trả lời: true (chụp đi) hoặc false (ngủ tiếp)
    res.json({ snap: shouldTakePhoto });
    
    // Nếu đã giao việc xong thì reset cờ
    if (shouldTakePhoto) {
        console.log("✅ Đã chuyển lệnh chụp cho Camera");
        shouldTakePhoto = false; 
    }
});

// 2. Web bấm nút "Chụp Ngay" (Manual Snap)
// Không cần auth quá chặt ở đây để demo cho dễ, hoặc thêm authenticateToken nếu muốn
app.post('/api/manual-snap', (req, res) => {
    console.log("🖱️ WEB: Người dùng bấm nút chụp");
    shouldTakePhoto = true; // Bật cờ lên
    res.json({ success: true });
});

// 3. Nhận ảnh từ Camera gửi lên
app.post('/api/upload-snapshot', upload.single('imageFile'), (req, res) => {
    if (!req.file) return res.status(400).send("Lỗi: Không có ảnh");
    
    console.log("📸 CAMERA: Đã nhận ảnh mới ->", req.file.filename);
    
    // Báo cho Web hiện ảnh lên
    io.emit('new_snapshot', { 
        url: '/uploads/' + req.file.filename, 
        time: new Date().toLocaleTimeString('vi-VN') 
    });

    res.status(200).send("Upload OK");
});

// --- MIDDLEWARE BẢO MẬT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: "Thiếu Token!" });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Token lỗi!" });
        req.user = user; next();
    });
}

// --- CÁC API AUTH & ĐIỀU KHIỂN ---
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (await User.findOne({ username })) return res.json({ success: false, message: "Tên tồn tại" });
    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ username, password: hashedPassword, email, role: username===SUPER_ADMIN?'admin':'viewer' }).save();
    res.json({ success: true });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.json({ success: false, message: "Sai TK/MK" });
    const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, username: user.username, role: user.role, token });
});

app.post('/api/list-users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.username !== SUPER_ADMIN) return res.json({ success: false });
    const users = await User.find({}, 'username email role');
    res.json({ success: true, users });
});

app.post('/api/set-user-role', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.json({ success: false });
    await User.updateOne({ username: req.body.targetUser }, { role: req.body.newRole });
    res.json({ success: true });
});

app.post('/api/control-pump', authenticateToken, async (req, res) => {
    if (req.user.role === 'admin' || req.user.username === SUPER_ADMIN) {
        mqttClient.publish(TOPIC_CMD, JSON.stringify({ device: 'pump', state: req.body.action === 'ON' }));
        res.json({ success: true });
    } else res.status(403).json({ success: false });
});

// API Còi (Siren)
app.post('/api/control-siren', authenticateToken, async (req, res) => {
    if (req.user.role === 'admin' || req.user.username === SUPER_ADMIN) {
        mqttClient.publish(TOPIC_CMD, JSON.stringify({ device: 'siren', state: req.body.action === 'ON' }));
        res.json({ success: true });
    } else res.status(403).json({ success: false });
});

app.post('/api/delete-user', authenticateToken, async (req, res) => {
    if (req.user.username !== SUPER_ADMIN) return res.json({ success: false });
    await User.deleteOne({ username: req.body.targetUser });
    res.json({ success: true });
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
    const user = await User.findOne({ username: req.user.username });
    if (!await bcrypt.compare(req.body.oldPassword, user.password)) return res.json({ success: false });
    user.password = await bcrypt.hash(req.body.newPassword, 10);
    await user.save();
    res.json({ success: true });
});

app.post('/api/sensor-history', authenticateToken, async (req, res) => {
    const history = await SensorData.find().sort({ timestamp: -1 }).limit(500);
    res.json({ success: true, data: history });
});

app.post('/forgot-password', async (req, res) => {
    res.json({ success: false, message: "Tính năng đang bảo trì" }); 
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}...`));