const escapeHtml = require('escape-html');
const express = require('express');
const session = require('express-session');
const app = express();

// 세션 설정
app.use(session({
    name: 'session-id',
    secret: '9e8821c8ef4ab43ba09310af54e98caedc13e314efdea720bf513b9b3675faf4',
    resave: false,
    saveUninitialized: false
}));

// 인증 미들웨어
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next(); // 세션이 있으면 다음 미들웨어로
    } else {
        next('route'); // 없으면 다음 라우트로
    }
};

// 로그인된 사용자에게 환영 메시지
app.get('/', isAuthenticated, (req, res) => {
    res.send(`${escapeHtml(req.session.user)}님 환영합니다!`);
});

// 로그인 페이지 표시
app.get('/', (req, res) => {
    res.send(`
        <p>로그인</p>
        <form action="/login" method="post">
            Username: <input name="user"><br>
            Password: <input name="pass" type="password"><br>
            <input type="submit" value="Login">
        </form>
    `);
});

// 로그인 요청 처리
app.post('/login', express.urlencoded({ extended: false }), (req, res, next) => {
    if (req.body.user === 'jeongwon' && req.body.pass === '1234') {
        req.session.regenerate((err) => {
            if (err) return next(err);

            // 세션에 사용자 정보 저장
            req.session.user = req.body.user;

            // 세션 저장 후 리다이렉트
            req.session.save((err) => {
                if (err) return next(err);
                res.redirect('/');
            });
        });
    } else {
        res.redirect('/');
    }
});

app.listen(3000, () => console.log('서버가 시작되었습니다: http://localhost:3000'));
