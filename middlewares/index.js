const jwt = require("jsonwebtoken"); // JWT(JSON Wep Token) 라이브러리 불러오기

// 사용자가 로그인한 상태인지 확인하는 미들웨어
exports.isLoggedIn = (req, res, next) => {
    if (req.isAuthenticated()) { // 사용자가 인증된 상태인지 확인
        // Passport -> res객체에 isAuthenticated 메서드 추가
        // 로그인 중이면 req.isAuthenicated()가 True, 그렇지 않으면 False
        next(); // 인증된 상태이면 다름 미들웨어로 이동
    } else {
        res.status(403).send('로그인 필요');
        // 인증되지 않은 상태이면 403 상태 코드와 함께 '로그인 필요' 메시지 전송
    }
};

// 사용자가 로그인하지 않은 상태인지 확인하는 미들웨어
exports.isNotLoggedIn = (req, res, next) => {
    if (!req.isAuthenticated()) { // 사용자가 인증되지 않은 상태인지 확인
        next(); // 인증되지 않은 상태이면 다음 미들웨어로 이동
    } else {
        const message = encodeURIComponent('로그인한 상태입니다.'); // 인증된 상태이면 메시지 인코딩
        res.redirect(`/?error=${message}`); // 메시지를 포함하여 리다이렉트
    }
};

// JWT 토컨을 검증하는 미들웨어
exports.verifyToken = (req, res, next) => {
    try {
        // Authorization 헤더의 토큰을 검증하여 decoded 객테를 생성하고 이를 res.locals에 정장
        // 요청 헤더에 저장된 토큰(req.headers.authorization) 사용 -> 사용자가 쿠키처럼 헤더에 토근을 넣어 전송
        // jwt.verify 메서드 -> 토큰 검증, 첫번째 인수(토큰), 두번째 인수(토큰의 비밀 키)
        res.locals.decoded = jwt.verify(req.headers.quthorization, process.env.JWT_SECRET);
        // 인증에 성공한 경우 토큰의 내용(사용자 아이디, 닉네임, 발급자, 유효기간 등)이
        // 반환되어 res.locals.decoded에 저장됨
        return next(); // 토큰이 유효하다면 다음 미들웨어로 이동
    } catch (error) {
        // 에러가 발생했을 경우
        if (error.name === 'TokenExpiredError') {
            // 에러의 이름이 'TokenExpiredError'이면 -> 올바른 토큰이지만, 유효기간 만료
            return res.status(419).json({
                code: 419, // 상태 코드는 419 (토큰 만료)
                message: '토큰이 만료되었습니다.', // 에러 메시지
            });
        }
        return res.status(401).json({
            code: 401, // 상태 코드는 401 (유효하지 않은 토큰) -> 토큰의 비밀키가 일치하지 않은 경우
            message: '유효하지 않은 토큰입니다.', // 에러 메시지
        });
    }
};