PROJECT3: Mini Cloud Storage System for Students
# implementation
- express app 
- web interface

## function
- login register
- list file in folder and view file
- upload file
- share file as link
- download file

### upload file
Client Side
1. user choose a file to upload
2. client application will generate random AES key for encrypt file
3. client application will encrypt file content (AES-GCM) and file  (AES-GCM) with that AES key
4. AES key will be encypted by user public key (RSA)  (only user have privatekey can decypt aes key to decrypt file to get plaintext)
5. upload encrypted file to server including encrypted file content and metadata (file will be stored in server and metadata will be store in database)

Server side
1. receive payload
2. save blob enc_file to object storage (file system)
3. save IV value and metadata to database 
4. create file id (UUID) as path and as key for mapping file with metadata in database

### download file

nguoc lai voi qua trinh upload file


### authentication and authorization
1. authentication
   - username/password or oauthentication 
   - session voi jwt
   - middleware cho viec xac thuc voi jwt token

2. authorization
   - owner_id in metadata for authorization
### share file (temporary link)
- can xac thuc truoc
- khi nguoi dung muon sharefile, gui request den server, server tao token su dung cho viec truy cap vao file chia se
- co the download file chia se 
- request can qua middle ware de xac thuc va kiem tra quyen truy cap