require('dotenv').config();
const jwt = require('jsonwebtoken');
const db = require('../models/mysql/index');

// Tạo JWT token
const createJWT = (payload) => {
    let token = null;
    try {
        token = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN, // Thời gian hết hạn của token
        });

        return token;
    } catch (error) {
        console.log(error);
        return null;
    }
};

// Xác minh JWT token
const verifyToken = (token) => {
    let decoded = null;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        decoded = 'TokenExpiredError';
        console.log('TokenExpiredError');
    }
    return decoded;
};

// Lưu refresh token vào DB
const insertTokenToDB = async (email, token, typeAccount) => {
    try {
        const rows = await db.Users.update(
            { refresh_token: token },
            { where: { email: email, type_account: typeAccount } }
        );

        if (rows[0] === 0) {
            return {
                EC: -1,
                EM: 'Thêm token thất bại!',
            };
        }

        return { EC: 0, EM: 'Token đã được thêm vào DB thành công!' };
    } catch (error) {
        console.log(error);
        return {
            EC: -1,
            EM: 'Lỗi không xác định!',
        };
    }
};

// Tìm người dùng qua email
const findUserByEmail = async (email) => {
    try {
        const user = await db.Users.findOne({
            where: { email },
            raw: true,
        });

        if (!user) {
            return {
                EC: -1,
                EM: 'Không tìm thấy người dùng!',
                DT: '',
            };
        }

        return {
            EC: 0,
            EM: 'Tìm thấy người dùng!',
            DT: user,
        };
    } catch (error) {
        console.log(error);
        return {
            EC: -1,
            EM: 'Lỗi không xác định!',
        };
    }
};

// Đăng nhập người dùng
const login = async (req, res) => {
    const { email, password } = req.body;

    // Kiểm tra người dùng với email
    const { EC, EM, DT: user } = await findUserByEmail(email);

    if (EC === -1) {
        return res.status(400).json({ EC, EM });
    }

    // So sánh mật khẩu (so sánh mật khẩu thuần túy, không mã hóa)
    if (user.password !== password) {
        return res.status(400).json({ EC: -1, EM: 'Mật khẩu không đúng!' });
    }

    // Tạo JWT token cho người dùng
    const payload = { email: user.email, userId: user.id };
    const accessToken = createJWT(payload);

    // Tạo refresh token và lưu vào DB nếu cần
    const refreshToken = createJWT(payload);
    await insertTokenToDB(user.email, refreshToken, user.type_account);

    // Thêm token vào cookies
    insertTokenToCookies(res, accessToken, refreshToken);

    return res.status(200).json({ EC: 0, EM: 'Đăng nhập thành công!' });
};

// Đăng xuất người dùng
const logout = (req, res) => {
    try {
        res.clearCookie('access_token');
        res.clearCookie('refresh_token');
        return res.status(200).json({ EC: 0, EM: 'Đăng xuất thành công!' });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ EC: -1, EM: 'Lỗi khi đăng xuất!' });
    }
};

// Kiểm tra token
const checkToken = (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) {
        return res.status(403).json({ EC: -1, EM: 'Không có token!' });
    }

    const decoded = verifyToken(token);
    if (decoded === 'TokenExpiredError') {
        return res.status(401).json({ EC: -1, EM: 'Token hết hạn!' });
    }

    req.user = decoded; // Đặt thông tin người dùng vào req để sử dụng sau
    next();
};

// Thêm token vào cookies
const insertTokenToCookies = (res, accessToken, refreshToken) => {
    try {
        res.cookie('refresh_token', refreshToken, {
            maxAge: +process.env.MAX_AGE_REFRESH_TOKEN,
            httpOnly: true,
            secure: true,
            sameSite: 'none',
        });

        res.cookie('access_token', accessToken, {
            maxAge: +process.env.MAX_AGE_ACCESS_TOKEN,
            httpOnly: true,
            secure: true,
            sameSite: 'none',
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!',
        });
    }
};

module.exports = {
    login,
    logout,
    checkToken,
    insertTokenToDB,
    insertTokenToCookies,
};
