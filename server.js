const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = 3000;
app.use(express.json());
const users = []; 
const SECRET_KEY = "rahasia_negara";

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        const isExist = users.find(u => u.username === username);
        if (isExist) return res.status(400).json({ pesan: "Username sudah terdaftar! akang/teteh" });

        
        const hashedPassword = await bcrypt.hash(password, 5);

        
        const newUser = { id: users.length + 1, username: username, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ pesan: "Registrasi berhasil akang/teteh!" });
    } catch (error) {
        res.status(500).json({ pesan: "Terjadi kesalahan saat registrasi, silahkan coba lagi." });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        
        const user = users.find(u => u.username === username);
        if (!user) return res.status(404).json({ pesan: "Pengguna tidak ditemukan, silahkan masukan data yang benar!" });

        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ pesan: "Password salah!" });

        
        const token = jwt.sign(
            { id: user.id, username: user.username }, 
            SECRET_KEY, 
            { expiresIn: '1h' }
        );

        res.json({ pesan: "Login sukses!", token: token });
    } catch (error) {
        res.status(500).json({ pesan: "Terjadi kesalahan saat login." });
    }
});

app.get('/profil', (req, res) => {
    try {
        
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) return res.status(401).json({ pesan: "Akses ditolak! Anda belum login." });

        
        const decoded = jwt.verify(token, SECRET_KEY);
        
        res.json({ pesan: "Selamat datang di gudang data!", data: decoded });
    } catch (error) {
        res.status(403).json({ pesan: "Token tidak valid atau sudah kadaluarsa!" });
    }
});

app.listen(PORT, () => {
    console.log(`Server Keamanan berjalan di http://localhost:${PORT}`);
});