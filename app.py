import os, sqlite3
from functools import wraps
from flask import Flask, request, Response, g, render_template_string

DATABASE = 'test.db'
app = Flask(__name__)

def check_auth(user, pw):
    return user == os.environ.get('LAB_USER') and pw == os.environ.get('LAB_PASS')

def authenticate():
    return Response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Lab"'})

def requires_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*a, **kw)
    return wrapper

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);")
        conn.execute("INSERT INTO users (username,password) VALUES ('alice','alicepass');")
        conn.commit()
        conn.close()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

@app.route('/')
@requires_auth
def index():
    return "<h1>Vuln Lab</h1><a href='/login'>Login</a> | <a href='/users'>Users</a>"

@app.route('/login', methods=['GET','POST'])
@requires_auth
def login():
    if request.method=='POST':
        u = request.form.get('username','')
        p = request.form.get('password','')
        db = get_db()
        row = db.execute(f"SELECT * FROM users WHERE username='{u}' AND password='{p}'").fetchone()
        return f"<p>{'Welcome '+u if row else 'Bad creds'}</p><a href='/'>Home</a>"
    return "<form method='post'>User:<input name='username'><br>Pass:<input name='password'><br><button>Login</button></form>"

@app.route('/users')
@requires_auth
def users():
    rows = get_db().execute("SELECT id,username FROM users").fetchall()
    return "<br>".join([f'{r['id']}: {r['username']}' for r in rows]) + "<p><a href='/'>Home</a></p>"

if __name__=='__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)))
