## endPoint

requestMapping("/api/v1/auth") 처리함

### 회원가입

Post /register

ex) http://localhost:8081/register

### 회원 인증

Post /authenticate

ex) http://localhost:8081/authenticate

### 회원 인증되서 token 유효성 체크
header에 회원 인증후에 나오는 token을 넣어주기

Get /api/v1/demo-controller

ex) http://localhost:8081/api/v1/demo-controller