// server.js (Phiên bản SUPER ADMIN + OTP Reset)
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const mqtt = require('mqtt');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // Thêm thư viện crypto để tạo OTP

// --- CẤU HÌNH SUPER ADMIN ---
const SUPER_ADMIN = "Mikeyiy"; 

// --- CẤU HÌNH GỬI EMAIL ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: 'mikeyiy2304@gmail.com', pass: 'xyxu spui lgku prvu' }
});

// --- KẾT NỐI MONGODB ---
const CONNECTION_STRING = 'mongodb+srv://Mikeyiy:Dangkhoa23042004@cluster0.x3tldft.mongodb.net/MyIoT?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(CONNECTION_STRING).then(() => console.log("✅ MongoDB OK!"));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true },
    role: { type: String, default: 'viewer' },
    resetToken: String, 
    resetTokenExpiration: Date
});
const User = mongoose.model('User', UserSchema);

app.use(express.static('public')); // Đảm bảo thư mục chứa html là 'public' hoặc cùng cấp
app.use(bodyParser.json());

// --- MQTT (Giữ nguyên) ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_ROOT = 'demo_iot_vn_2025'; 
const TOPIC_CMD = 'shadowfox/commands';
mqttClient.on('connect', () => { mqttClient.subscribe(`${TOPIC_ROOT}/+/+`); });
mqttClient.on('message', (topic, message) => io.emit('sensor_data', { topic, value: message.toString() }));

// --- API AUTH (Đăng ký/Đăng nhập - Giữ nguyên) ---
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
    res.json({ success: true, username: user.username, role: finalRole });
});

// ============================================================
// --- QUY TRÌNH QUÊN MẬT KHẨU BẰNG OTP (MỚI) ---
// ============================================================

// Bước 1: Gửi yêu cầu + Tạo OTP
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "Email không tồn tại trong hệ thống!" });

    // Tạo OTP 6 số ngẫu nhiên
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Lưu OTP vào DB (Hết hạn sau 5 phút)
    user.resetToken = otp;
    user.resetTokenExpiration = Date.now() + 300000; // 5 phút
    await user.save();

    // Gửi Email
    const mailOptions = {
        from: 'ShadowFox IoT <no-reply@shadowfox.com>',
        to: email,
        subject: 'MÃ XÁC THỰC KHÔI PHỤC MẬT KHẨU',
        text: `Chào ${user.username},\n\nMã xác thực (OTP) của bạn là: ${otp}\n\nMã này sẽ hết hạn sau 5 phút. Không chia sẻ mã này cho ai.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            return res.json({ success: false, message: "Lỗi gửi mail! Vui lòng thử lại." });
        }
        res.json({ success: true, message: "Đã gửi mã OTP qua Email!" });
    });
});

// Bước 2: Xác thực OTP và Đổi mật khẩu mới
app.post('/reset-password-otp', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    
    const user = await User.findOne({ 
        email: email,
        resetToken: otp,
        resetTokenExpiration: { $gt: Date.now() } // Kiểm tra còn hạn không
    });

    if (!user) return res.json({ success: false, message: "Mã OTP không đúng hoặc đã hết hạn!" });

    // Mã hóa mật khẩu mới
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Cập nhật User và xóa OTP
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();

    res.json({ success: true, message: "Đổi mật khẩu thành công! Hãy đăng nhập lại." });
});

// --- CÁC API KHÁC (Giữ nguyên) ---
// ... (Giữ nguyên các API /api/list-users, /api/set-user-role, /api/control-pump, /api/delete-user từ file cũ của bạn)

// Lưu ý: Đảm bảo copy phần API cũ vào đây nếu bạn muốn giữ tính năng quản lý user

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}...`));