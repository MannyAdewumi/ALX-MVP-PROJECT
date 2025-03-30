from flask import Flask, render_template, request, redirect,jsonify, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_migrate import Migrate
import requests

app = Flask(__name__, template_folder= 'templates', static_folder='static', static_url_path='/')

# Configure Database
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:password@localhost:5432/music_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "JesusIsL0rd"

db = SQLAlchemy(app)
jwt = JWTManager(app)
#db.init_app(app)
migrate = Migrate(app, db)





@app.route("/")
def index():
    return render_template("index.html")


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