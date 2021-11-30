# ElGamal
ElGamal Cryptosystem

## Môi trường chạy
Python

## Thư viện cần thiết
Crypto

--> pip install pycrypto

## Chạy

## Dùng hệ mật ElGamal để mã hóa bản tin
--> Chạy file EncodeUI.py
Giao diện hiện ra như sau

![image](https://user-images.githubusercontent.com/71261304/144073872-d3b63b69-cf10-4ff2-9fa7-4627e3501e21.png)

Phía bên trái giao diện là hiển thị khóa, phía bên phải giao diện là hiển thị bản tin, bản mã hóa, bản giải mã

### Tạo khóa
Chọn số bit của p

![image](https://user-images.githubusercontent.com/71261304/144074211-dfdc7d10-a072-4bd6-b009-fce059067e5c.png)

Bấm vào button 'Tạo khóa' để hệ thống tự động tạo cho bạn một khóa với p có số bit như đã chọn ở mục số bit của p

![image](https://user-images.githubusercontent.com/71261304/144074908-c24b6334-f2fd-43db-a2ad-323c82e41aaa.png)

### Kiểm tra khóa
Bấm vào button 'Kiểm tra khóa' --> Phần mềm sẽ lấy dữ liệu từ các trường mà người dùng nhập để kiểm tra khóa

Phần mềm sẽ kiểm tra các điều kiện sau: p có phải số nguyên tố hay không, alpha có phải là thành phần nguyên thủy của p hay không, a có nằm trong đoạn từ 1 đến p-2 hay không
Ngoài ra, nếu trường beta đã được nhập, phần mềm sẽ kiểm tra beta có bằng alpha^a mod p hay không; trong trường hợp beta chưa được nhập, và các giá trị p, alpha, a đều hợp lệ thì phần mềm sẽ tự động sinh giá trị beta và hiển thị trường beta.

### Mã hóa bản tin
Nhập bản tin bạn muốn mã hóa vào trường tin nhắn gốc, sau đó bấm vào button mã hóa --> phần mềm sẽ lấy bản tin, khóa --> mã hóa bản tin --> tin nhắn sau khi được mã hóa sẽ hiển thị ở trường tin nhắn mã hóa

![image](https://user-images.githubusercontent.com/71261304/144076977-592aedc4-33c0-41c0-8ea8-0c1a54db2b18.png)

### Giải mã bản tin
Nhập bản tin bạn muốn giải mã vào trường bản tin mã hóa, sau đó bấm vào button giải mã --> phần mềm sẽ lấy bản tin mã hóa, khóa --> giải mã bản tin --> tin nhắn sau khi được mã hóa sẽ hiển thị ở trường bản giải mã

![image](https://user-images.githubusercontent.com/71261304/144077468-6ed5cf45-aafb-48a5-a414-8b0e23eb9452.png)

## Dùng hệ mật ElGamal để ký văn bản
--> Chạy file SignatureUI.py
Giao diện hiện ra như sau

![image](https://user-images.githubusercontent.com/71261304/144077852-fbc8ba9c-8da7-4ce0-bd2e-9d6f0cc8d44d.png)

### Tạo khóa và Kiểm tra khóa
--> Như với giao diện Dùng hệ mật ElGamal để mã hóa bản tin

### Ký văn bản
Nhập vào văn bản muốn ký --> bấm button 'Ký văn bản'
Phần mềm sẽ lấy văn bản, khóa --> tạo chữ ký --> hiển thị ở mục chữ ký

![image](https://user-images.githubusercontent.com/71261304/144078250-fd7642ca-946a-4fed-95d7-ec70791e0141.png)

### Kiểm tra văn bản được ký
Nhập vào chữ ký và bấm button 'Kiểm tra chữ ký'
Phần mềm sẽ lấy chữ ký, văn bản, khóa công khai --> xác thực chữ ký và thông báo ra kết quá

nếu chữ ký được xác thực

![image](https://user-images.githubusercontent.com/71261304/144078625-9a6f08fc-4cc1-4261-ba13-0e47316ab77e.png)

nếu chữ ký không được xác thực

![image](https://user-images.githubusercontent.com/71261304/144078673-7f43653d-8fd3-4a04-8ec8-a45897bf834f.png)







