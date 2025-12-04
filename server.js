// server.js (Phiên bản SUPER ADMIN)
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const mqtt = require('mqtt');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

// --- CẤU HÌNH SUPER ADMIN (BẠN CHỈNH TÊN BẠN MUỐN VÀO ĐÂY) ---
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
    resetToken: String, resetTokenExpiration: Date
});
const User = mongoose.model('User', UserSchema);

app.use(express.static('public'));
app.use(bodyParser.json());

// --- MQTT (Giữ nguyên) ---
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');
const TOPIC_ROOT = 'demo_iot_vn_2025'; 
const TOPIC_CMD = 'shadowfox/commands';
mqttClient.on('connect', () => { mqttClient.subscribe(`${TOPIC_ROOT}/+/+`); });
mqttClient.on('message', (topic, message) => io.emit('sensor_data', { topic, value: message.toString() }));

// --- API AUTH ---
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (await User.findOne({ username })) return res.json({ success: false, message: "Tên đã tồn tại!" });

    // Nếu tên đăng ký trùng với SUPER_ADMIN -> Tự động cấp quyền Admin luôn
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

    // BẢO VỆ TUYỆT ĐỐI: Nếu là Mikeyiy, luôn trả về role admin bất chấp database
    const finalRole = (username === SUPER_ADMIN) ? 'admin' : user.role;
    
    res.json({ success: true, username: user.username, role: finalRole });
});

// --- API QUẢN LÝ USER (MỚI) ---

// 1. Lấy danh sách tất cả user (Chỉ Admin mới xem được)
app.post('/api/list-users', async (req, res) => {
    const { requestBy } = req.body; 
    const admin = await User.findOne({ username: requestBy });

    // Kiểm tra quyền: Phải là Admin hoặc Super Admin
    if (!admin || (admin.role !== 'admin' && requestBy !== SUPER_ADMIN)) 
        return res.json({ success: false, message: "Không có quyền!" });

    // Trả về danh sách (ẩn mật khẩu)
    const users = await User.find({}, 'username email role');
    res.json({ success: true, users });
});

// 2. Thay đổi quyền (Chỉ Admin mới làm được)
app.post('/api/set-user-role', async (req, res) => {
    const { requestBy, targetUser, newRole } = req.body;

    // Check quyền người yêu cầu
    const admin = await User.findOne({ username: requestBy });
    if (!admin || (admin.role !== 'admin' && requestBy !== SUPER_ADMIN)) 
        return res.json({ success: false, message: "Không có quyền!" });

    // KHÔNG CHO PHÉP hạ quyền của Super Admin
    if (targetUser === SUPER_ADMIN) 
        return res.json({ success: false, message: "Không thể hạ bệ VUA!" });

    await User.updateOne({ username: targetUser }, { role: newRole });
    console.log(`👑 ${requestBy} đã đổi quyền của ${targetUser} thành ${newRole}`);
    res.json({ success: true, message: "Cập nhật thành công!" });
});

// --- API BƠM (Giữ nguyên logic cũ) ---
app.post('/api/control-pump', async (req, res) => {
    const { username, action } = req.body;
    const user = await User.findOne({ username });
    
    if (!user) return res.json({ success: false, message: "Lỗi user" });

    // Admin hoặc Super Admin đều được bơm
    if (user.role === 'admin' || username === SUPER_ADMIN) {
        mqttClient.publish(TOPIC_CMD, JSON.stringify({ device: 'pump', state: action === 'ON' }));
        res.json({ success: true, message: "Thành công" });
    } else {
        res.status(403).json({ success: false, message: "Không có quyền!" });
    }
});

// Forgot Password (Giữ nguyên...)
app.post('/forgot-password', async (req, res) => {/*Code cũ của bạn*/});
// --- API ĐỔI MẬT KHẨU (MỚI THÊM) ---
app.post('/api/change-password', async (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
    
    // 1. Tìm user
    const user = await User.findOne({ username });
    if (!user) return res.json({ success: false, message: "User không tồn tại!" });

    // 2. Kiểm tra mật khẩu cũ có đúng không
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.json({ success: false, message: "Mật khẩu cũ không đúng!" });

    // 3. Mã hóa mật khẩu mới và lưu lại
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    console.log(`🔐 User ${username} vừa đổi mật khẩu.`);
    res.json({ success: true, message: "Đổi mật khẩu thành công!" });
});
// --- API XÓA USER (CHỈ SUPER ADMIN) ---
app.post('/api/delete-user', async (req, res) => {
    const { requestBy, targetUser } = req.body;

    // 1. Chỉ cho phép Mikeyiy thực hiện
    if (requestBy !== SUPER_ADMIN) {
        return res.json({ success: false, message: "Bạn không đủ quyền hạn để xóa người khác!" });
    }

    // 2. Không cho phép tự xóa chính mình
    if (targetUser === SUPER_ADMIN) {
        return res.json({ success: false, message: "Không thể xóa tài khoản Super Admin!" });
    }

    // 3. Thực hiện xóa
    try {
        await User.deleteOne({ username: targetUser });
        console.log(`❌ SUPER ADMIN đã xóa user: ${targetUser}`);
        res.json({ success: true, message: `Đã xóa bay màu tài khoản ${targetUser}!` });
    } catch (e) {
        res.json({ success: false, message: "Lỗi Database: " + e.message });
    }
});
http.listen(3000, () => console.log('🚀 Server running...'));