from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()
# db.session.delete(User.query.get(4))
# db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods = ["POST", "GET"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:    
        hashed_password = generate_password_hash(request.form.get("password"),method='pbkdf2:sha256', salt_length=8)
        try:
            new_user = User(
                email = request.form.get("email"),
                password = hashed_password,
                name = request.form.get("name")
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(user=new_user)
            return redirect(url_for('secrets'))
        except:
            flash("You have already signed up with that email. Login instead!")
            return redirect(url_for('register'))



@app.route('/login',methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email = email).first()
        if not user:
            flash("This email does not exist, please try again!")
        elif not check_password_hash(pwhash=user.password, password=password):
            flash("Password incorrect, please try again!")
        elif(check_password_hash(pwhash=user.password, password=password)):
            login_user(user=user)
            return redirect(url_for('secrets'))
        
        return redirect(url_for('login'))


@app.route('/secrets')
@login_required
def secrets():
    # print(name)
    return render_template("secrets.html",name = current_user.name)
    


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/<path:filename>')
def download(filename):
        return send_from_directory('static/files',filename)


if __name__ == "__main__":
    app.run(debug=True)
