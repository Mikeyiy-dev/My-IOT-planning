// server.js
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const mqtt = require('mqtt');
const bodyParser = require('body-parser');

// Cấu hình
app.use(express.static('public')); // Cho phép truy cập thư mục public
app.use(bodyParser.json());

// --- DATABASE TRÊN RAM (Mất khi tắt server) ---
const USERS = [
    { username: "admin", password: "123" } // Tài khoản mặc định
];

// --- KẾT NỐI MQTT ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_ROOT = 'demo_iot_vn_2025'; 

mqttClient.on('connect', () => {
    console.log("✅ Server đã kết nối MQTT Broker");
    mqttClient.subscribe(`${TOPIC_ROOT}/+/+`); // Lắng nghe tất cả user
});

mqttClient.on('message', (topic, message) => {
    const value = message.toString();
    // Gửi dữ liệu xuống Dashboard qua Socket
    io.emit('sensor_data', { topic: topic, value: value });
});

// --- API ĐĂNG NHẬP ---
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);
    if (user) {
        res.json({ success: true });
    } else {
        res.json({ success: false, message: "Sai tài khoản hoặc mật khẩu!" });
    }
});

// --- API ĐĂNG KÝ (MỚI) ---
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    // Kiểm tra trùng tên
    const exists = USERS.find(u => u.username === username);
    if (exists) return res.json({ success: false, message: "Tên này đã có người dùng!" });

    // Thêm user mới
    USERS.push({ username, password });
    console.log("🎉 User mới đăng ký:", username);
    res.json({ success: true, message: "Đăng ký thành công!" });
});

// Chạy server
http.listen(3000, () => {
    console.log('🚀 Server chạy tại: http://localhost:3000');
});