require("dotenv").config();

const configCors = (app) => {
    app.use(function (req, res, next) {
        res.setHeader('Access-Control-Allow-Origin', 'https://thanhdatflix.vercel.app'); // Thay trực tiếp URL frontend
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
        res.setHeader('Access-Control-Allow-Credentials', 'true'); // Phải đặt giá trị kiểu string

        if (req.method === 'OPTIONS') {
            return res.sendStatus(200);
        }
        next();
    });
}

module.exports = configCors;
