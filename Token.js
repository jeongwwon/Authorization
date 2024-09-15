const ACCESS_TOKEN_SECRET = "9e8821c8ef4ab43ba09310af54e98caedc13e314efdea720bf513b9b3675faf4";
const REFRESH_TOKEN_SECRET = "9e8821c8ef4ab43ba09310af54e98caedc13e314efdea720bf513b9b3675faf4";
const PORT = 12010;

const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// DB에 있는 유저 정보를 흉내내는 객체
const userInfo = {
    username: 'kundol',
    password: '1234',
    email: 'kundol@gmail.com'
};

// 토큰을 만들 때 사용하는 유저 객체
const user = {
    username: userInfo.username,
    email: userInfo.email
};

// 두개의 토큰에 대한 만료기한 옵션: access 토큰은 짧게, refresh 토큰은 길게
const accessOpt = {
    expiresIn: '10m'
};

const refreshOpt = {
    expiresIn: '1d'
};

// 쿠키 옵션
const cookieOpt = {
    httpOnly: true,
    sameSite: 'Strict',
    secure: true,
    maxAge: 24 * 60 * 60 * 1000 // 1 day
};

// 인증 미들웨어
const isAuthenticated = (req, res, next) => {
    if (!req.headers.authorization) {
        return next('route');
    }

    let auth = req.headers.authorization;

    if (auth.startsWith("Bearer ")) {
        auth = auth.substring(7, auth.length);
    }

    try {
        const user = jwt.verify(auth, ACCESS_TOKEN_SECRET);
        if (user) return next();
    } catch (err) {
        return next('route');
    }
};

// 허용된 요청
app.get('/', isAuthenticated, (req, res) => {
    return res.status(200).send("허용된 요청입니다.");
});

// 허용되지 않은 요청
app.get('/', (req, res) => {
    return res.status(401).send("허용되지 않은 요청입니다.");
});

// 로그인 요청 처리
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === userInfo.username && password === userInfo.password) {
        const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, accessOpt);
        const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET, refreshOpt);

        // cookie에는 refresh 토큰을 담습니다.
        res.cookie('jwt', refreshToken, cookieOpt);
        return res.json({ accessToken, refreshToken });
    } else {
        return res.status(401).json({ message: "인증되지 않은 요청입니다." });
    }
});

// Access 토큰 갱신을 위한 refresh 토큰 요청 처리
app.post('/refresh', (req, res) => {
    if (req.cookies.jwt) {
        const refreshToken = req.cookies.jwt;

        jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: '인증되지 않은 요청입니다.' });
            } else {
                const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, accessOpt);
                return res.json({ accessToken });
            }
        });
    } else {
        return res.status(401).json({ message: "인증되지 않은 요청입니다." });
    }
});

app.listen(PORT, () => {
    console.log(`서버 시작: http://localhost:${PORT}`);
    console.log(`로그인 요청: http://localhost:${PORT}/login`);
    console.log(`Refresh 요청: http://localhost:${PORT}/refresh`);
});
