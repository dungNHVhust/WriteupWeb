from flask import Flask, jsonify, request, make_response, redirect, render_template_string, render_template
from database import *
import jwt
import os
import ujson

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(32)

database_file = "database.db"
connection = connect_to_db(database_file)


@app.route('/login', methods=['GET'])
def login_page():

    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = login_db(connection, username, password)

    if user:
        token = jwt.encode({
            'username': user[0],
            'role': user[1]
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify(message=token)
    else:
        return jsonify(message="Login failed! Invalid username or password."), 401

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    json_data = request.data
    if "admin" in json_data:
        return jsonify(message="Blocked!")
    data = ujson.loads(json_data)
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    if role !="admin" and role != "user":
        return jsonify(message="Never heard about that role!")
    
    if username == "" or password == "" or role == "":
        return jsonify(messaage="Lack of input")
    
    if register_db(connection, username, password, role):
        return jsonify(message="User registered successfully."), 201
    else:
        return jsonify(message="Registration failed!"), 400

@app.route('/')
def index():
    token = request.cookies.get('jwt_token')
    username = None
    if token:
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            username = decoded.get('username')
        except:
            return jsonify(message="Bad JWT")
    else:
        return jsonify(message="Where is your token?")
    return render_template('index.html', username=username)

@app.route('/render', methods=['POST'])
def dynamic_template():
    token = request.cookies.get('jwt_token')
    if token:
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            role = decoded.get('role')

            if role != "admin":
                return jsonify(message="Admin only"), 403

            data = request.get_json()
            template = data.get("template")
            rendered_template = render_template_string(template)
            
            return jsonify(message="Done")

        except jwt.ExpiredSignatureError:
            return jsonify(message="Token has expired."), 401
        except jwt.InvalidTokenError:
            return jsonify(message="Invalid JWT."), 401
        except Exception as e:
            return jsonify(message=str(e)), 500
    else:
        return jsonify(message="Where is your token?"), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082)
