const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'maktab_maxfiy_kalit_2026';

// Turso ma'lumotlar bazasi ulanishi
const TURSO_URL = process.env.TURSO_DATABASE_URL || 'libsql://maktab-dbb-javokh14.aws-ap-northeast-1.turso.io';
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3OTI5OTY2NDUsImlkIjoiMDFhMTc2ZTUtM2YwMS03MjE1LWI4NDMtMDE3ZmQ2ZWU1ZjkwIiwia2lkIjoiZElaN0NzZExlZXZIZkJwU29vWW9nVGNrd3NMczRXSG1LT0x0aTMzT0tPayIsInJpZCI6ImE4YWIyMGRjLTc0ZDgtNDhiOS1hMGRmLTUyM2YzMzJkYTcyNiJ9.r52YShbLwjZDVhyf_Uvjb9tOGh-cGrJuOaI1_aMtkezmJLpwnACOkY6mZM5q6ivcnQQff6HlZ5f1D83xQYKSBA';

const turso = createClient({
    url: TURSO_URL,
    authToken: TURSO_TOKEN
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Tokenni tekshirish uchun middleware
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Avtorizatsiyadan o'tilmagan: Token yo'q" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Yaroqsiz token" });
        req.user = user;
        next();
    });
}

// 1. Tizimga kirish (Admin yoki Mas'ul)
app.post('/api/login', async (req, res) => {
    try {
        const { login, password } = req.body;
        if (!login || !password) return res.status(400).json({ error: "Login va parolni kiriting" });

        const rs = await turso.execute({
            sql: "SELECT * FROM users WHERE login = ?",
            args: [login]
        });

        if (rs.rows.length === 0) {
            return res.status(400).json({ error: "Login yoki parol noto'g'ri" });
        }

        const user = rs.rows[0];
        const isMatch = await bcrypt.compare(password, String(user.password));
        if (!isMatch) {
            return res.status(400).json({ error: "Login yoki parol noto'g'ri" });
        }

        const token = jwt.sign(
            { id: user.id, fullname: user.fullname, role: user.role, assigned_class: user.assigned_class },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                fullname: user.fullname,
                role: user.role,
                assigned_class: user.assigned_class
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Mas'ul xodimlarni olish (Faqat Admin)
app.get('/api/teachers', authMiddleware, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Faqat admin uchun" });
    try {
        const rs = await turso.execute("SELECT id, fullname, login, assigned_class, role FROM users WHERE role = 'teacher'");
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Yangi mas'ul xodim qo'shish (Faqat Admin)
app.post('/api/teachers', authMiddleware, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Faqat admin uchun" });
    try {
        const { fullname, login, password, assigned_class } = req.body;
        if (!fullname || !login || !password || !assigned_class) {
            return res.status(400).json({ error: "Barcha maydonlarni to'ldiring" });
        }

        const hash = await bcrypt.hash(password, 10);
        const rs = await turso.execute({
            sql: "INSERT INTO users (fullname, login, password, role, assigned_class) VALUES (?, ?, ?, 'teacher', ?)",
            args: [fullname, login, hash, assigned_class]
        });

        res.json({ id: Number(rs.lastInsertRowid), fullname, login, assigned_class });
    } catch (err) {
        res.status(400).json({ error: "Bu login band yoki xatolik yuz berdi" });
    }
});

// 4. Mas'ul xodimni o'chirish (Faqat Admin)
app.delete('/api/teachers/:id', authMiddleware, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Faqat admin uchun" });
    try {
        await turso.execute({
            sql: "DELETE FROM users WHERE id = ? AND role = 'teacher'",
            args: [req.params.id]
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. O'quvchilar ro'yxatini olish (Admin hammasini, Mas'ul faqat o'z sinfini)
app.get('/api/students', authMiddleware, async (req, res) => {
    try {
        if (req.user.role === 'admin') {
            const rs = await turso.execute("SELECT * FROM students ORDER BY grade_number ASC, grade_letter ASC");
            res.json(rs.rows);
        } else {
            const [num, letter] = req.user.assigned_class.split('-');
            const rs = await turso.execute({
                sql: "SELECT * FROM students WHERE grade_number = ? AND grade_letter = ? ORDER BY fullname ASC",
                args: [parseInt(num), letter]
            });
            res.json(rs.rows);
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. O'quvchi qo'shish
app.post('/api/students', authMiddleware, async (req, res) => {
    try {
        const { fullname, grade_number, grade_letter, login, password } = req.body;
        const num = parseInt(grade_number);

        if (req.user.role === 'teacher') {
            const expectedClass = `${num}-${grade_letter}`;
            if (req.user.assigned_class !== expectedClass) {
                return res.status(403).json({ error: `Siz faqat ${req.user.assigned_class} sinfiga o'quvchi qo'sha olasiz!` });
            }
        }

        const rs = await turso.execute({
            sql: "INSERT INTO students (fullname, grade_number, grade_letter, login, password) VALUES (?, ?, ?, ?, ?)",
            args: [fullname, num, grade_letter, login, password]
        });

        res.json({ id: Number(rs.lastInsertRowid), fullname, grade_number: num, grade_letter, login, password });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 7. O'quvchini o'chirish
app.delete('/api/students/:id', authMiddleware, async (req, res) => {
    try {
        const studentId = req.params.id;

        const check = await turso.execute({
            sql: "SELECT * FROM students WHERE id = ?",
            args: [studentId]
        });

        if (check.rows.length === 0) return res.status(404).json({ error: "O'quvchi topilmadi" });
        const student = check.rows[0];

        if (req.user.role === 'teacher') {
            const currentClass = `${student.grade_number}-${student.grade_letter}`;
            if (req.user.assigned_class !== currentClass) {
                return res.status(403).json({ error: "Siz faqat o'z sinfingiz o'quvchisini o'chira olasiz!" });
            }
        }

        await turso.execute({
            sql: "DELETE FROM students WHERE id = ?",
            args: [studentId]
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// SPA routing fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server ishga tushdi: Port ${PORT}`);
});
