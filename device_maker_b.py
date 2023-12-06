from flask import Flask, request, render_template_string

app = Flask(__name__)


LOGIN_FORM = """
<html>
    <body>
        <form action="" method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == "lrk" and password == "lrk14":
            return "Logged in successfully!"
        else:
            return "Login Failed!"
    return render_template_string(LOGIN_FORM)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
