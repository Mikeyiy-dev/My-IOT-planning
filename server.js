// server.js
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const mqtt = require('mqtt');
const bodyParser = require('body-parser');
const mongoose = require('mongoose'); // Thư viện để nói chuyện với MongoDB

// --- 1. KẾT NỐI MONGODB (Thay thế phần RAM cũ) ---
const CONNECTION_STRING = 'mongodb+srv://Mikeyiy:Dangkhoa23042004@cluster0.x3tldft.mongodb.net/MyIoT?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(CONNECTION_STRING)
    .then(() => console.log("✅ Đã kết nối thành công tới MongoDB Cloud!"))
    .catch((err) => console.log("❌ Lỗi kết nối MongoDB:", err));

// Định nghĩa khuôn mẫu cho User (Schema)
const UserSchema = new mongoose.Schema({
    username: String,
    password: String
});
const User = mongoose.model('User', UserSchema);

// --- CẤU HÌNH SERVER ---
app.use(express.static('public'));
app.use(bodyParser.json());

// --- KẾT NỐI MQTT ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_ROOT = 'demo_iot_vn_2025'; 

mqttClient.on('connect', () => {
    console.log("✅ Server đã kết nối MQTT Broker");
    mqttClient.subscribe(`${TOPIC_ROOT}/+/+`);
});

mqttClient.on('message', (topic, message) => {
    const value = message.toString();
    io.emit('sensor_data', { topic: topic, value: value });
});

// --- API ĐĂNG NHẬP (SỬA LẠI ĐỂ DÙNG MONGODB) ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // Tìm trong Database xem có ai tên đó, pass đó không
    const user = await User.findOne({ username: username, password: password });
    
    if (user) {
        res.json({ success: true });
    } else {
        res.json({ success: false, message: "Sai tài khoản hoặc mật khẩu!" });
    }
});

// --- API ĐĂNG KÝ (SỬA LẠI ĐỂ DÙNG MONGODB) ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    // 1. Kiểm tra xem tên đã tồn tại trong DB chưa
    const existingUser = await User.findOne({ username: username });
    if (existingUser) {
        return res.json({ success: false, message: "Tên này đã có người dùng!" });
    }

    // 2. Nếu chưa có, tạo user mới và lưu vào DB
    const newUser = new User({ username: username, password: password });
    await newUser.save(); // Lệnh này giúp lưu vĩnh viễn lên Cloud
    
    console.log("🎉 User mới đăng ký và đã lưu vào DB:", username);
    res.json({ success: true, message: "Đăng ký thành công!" });
});

// Chạy server
http.listen(3000, () => {
    console.log('🚀 Server chạy tại: http://localhost:3000');
});