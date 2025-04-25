PROJECT3: Mini Cloud Storage System for Students

# basic funtion
- login register
- list file in folder and view file
- upload file
- share file as link
- download file

## authentication

## Authentication

## Mã hóa khi truyền tải (Encryption in Transit)
Kết hợp HTTPS và E2EE
HTTPS Bảo vệ dữ liệu khi truyền đến server
E2EE Bảo vệ dữ liệu khỏi chính server
Cơ chế:
1. Client:
 Sử dụng WebCrypto API để sinh khóa và mã hóa dữ liệu
 Sau đó gửi ciphertext lên server qua HTTPS 
3. Server:
  Nhận dữ liệu đã mã hóa, không bao giòe giải mã, chỉ lưu ciphertext + metadata cần thiết
4. Other Client:
 Lấy ciphertext và dùng khóa riêng để giải mã 
