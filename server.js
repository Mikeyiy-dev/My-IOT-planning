// server.js
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const mqtt = require('mqtt');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Thư viện mã hóa
const nodemailer = require('nodemailer'); // Thư viện gửi mail

// --- CẤU HÌNH GỬI EMAIL (GMAIL) ---
// Bạn phải bật "Mật khẩu ứng dụng" trong cài đặt Google thì mới gửi được
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'mikeyiy2304@gmail.com', // 
        pass: 'xyxu spui lgku prvu' // DỤNG VÀO ĐÂY (Không phải mật khẩu đăng nhập nhé)
    }
});

// --- KẾT NỐI MONGODB ---
const CONNECTION_STRING = 'mongodb+srv://Mikeyiy:Dangkhoa23042004@cluster0.x3tldft.mongodb.net/MyIoT?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(CONNECTION_STRING)
    .then(() => console.log("✅ Đã kết nối MongoDB Cloud!"))
    .catch((err) => console.log("❌ Lỗi MongoDB:", err));

// Cập nhật Schema: Thêm Email và Token reset
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true }, // Bắt buộc phải có email để khôi phục
    resetToken: String,
    resetTokenExpiration: Date
});
const User = mongoose.model('User', UserSchema);

app.use(express.static('public'));
app.use(bodyParser.json());

// --- KẾT NỐI MQTT (Giữ nguyên) ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_ROOT = 'demo_iot_vn_2025'; 
mqttClient.on('connect', () => {
    console.log("✅ MQTT Connected");
    mqttClient.subscribe(`${TOPIC_ROOT}/+/+`);
});
mqttClient.on('message', (topic, message) => io.emit('sensor_data', { topic, value: message.toString() }));

// --- API ĐĂNG KÝ (CÓ MÃ HÓA) ---
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    
    // Kiểm tra trùng tên
    const exists = await User.findOne({ username });
    if (exists) return res.json({ success: false, message: "Tên đăng nhập đã tồn tại!" });

    // MÃ HÓA MẬT KHẨU TRƯỚC KHI LƯU
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, password: hashedPassword, email });
    await newUser.save();
    
    console.log("🎉 User mới:", username);
    res.json({ success: true, message: "Đăng ký thành công!" });
});

// --- API ĐĂNG NHẬP (CÓ SO SÁNH MÃ HÓA) ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) return res.json({ success: false, message: "Sai tài khoản!" });

    // So sánh mật khẩu nhập vào với mật khẩu đã mã hóa trong DB
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (isMatch) {
        res.json({ success: true });
    } else {
        res.json({ success: false, message: "Sai mật khẩu!" });
    }
});

// --- API QUÊN MẬT KHẨU (GỬI EMAIL) ---
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.json({ success: false, message: "Email này chưa đăng ký tài khoản nào!" });

    // Tạo mật khẩu mới ngẫu nhiên (Ví dụ: 6 số)
    const newTempPassword = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Mã hóa mật khẩu mới này và lưu vào DB
    const hashedPassword = await bcrypt.hash(newTempPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Gửi Email
    const mailOptions = {
        from: 'ShadowFox IoT System',
        to: email,
        subject: 'Cấp lại mật khẩu mới',
        text: `Chào ${user.username},\n\nMật khẩu mới của bạn là: ${newTempPassword}\n\nVui lòng đăng nhập và đổi lại mật khẩu ngay.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            return res.json({ success: false, message: "Lỗi gửi mail!" });
        } else {
            return res.json({ success: true, message: "Đã gửi mật khẩu mới vào Email của bạn!" });
        }
    });
});

http.listen(3000, () => console.log('🚀 Server running at http://localhost:3000'));