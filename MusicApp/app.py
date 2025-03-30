from flask import Flask, render_template, request, redirect,jsonify, session, url_for
from flask_sqlalchemy import SQLAlchemy
#from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import requests

app = Flask(__name__, template_folder= 'templates', static_folder='static', static_url_path='/')
CORS(app)
app.secret_key = "Secret_Key_123"

# Configure Database
#app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:password@localhost:5432/music_db"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///music.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "JesusIsL0rd"

db = SQLAlchemy(app)
#jwt = JWTManager(app)
#db.init_app(app)
migrate = Migrate(app, db)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)



class FavSong(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    song_id = db.Column(db.String(100), nullable=False)
    song_name = db.Column(db.String(200), nullable=False)



#Routes
@app.route("/")
def index():
    return render_template("index.html")


#Login
@app.route("/login", methods= ['POST'])
def login():
    username = request.form["username"]
    password = request.form["password"]

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        session ['username'] = username
        return redirect(url_for(dashboard))
    else:
        return render_template("signup.html", error= "Invalid user. Please sign up.")
    



#Register
@app.route("/signup", methods= ["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    #email = request.form["email"]

    user = User.query.filter_by(username=username).first()

    if user:
        return render_template("login.html", error= "User already exists.")
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session ['username'] = username
        return redirect(url_for(dashboard), message= "Registeration was successful")
    


#signup
@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/dashboard")
def dashboard():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template("signup.html")



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)