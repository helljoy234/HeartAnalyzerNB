from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pickle
import numpy as np


model = pickle.load(open('heart.pkl', 'rb'))
app = Flask(__name__)
app.config['SECRET_KEY'] = '?\x1bK`V\xa55\xdeJ\xf1\n\xa9[\x8etf\xca\xfd\x08\xa5\xdd@`\x80'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        #return '<h1>New user has been created!</h1>'
        flash(f'Your account has been created! You are now able to Log in', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route('/predict',methods=["POST"])
@login_required
def predict():
    data1 = request.form["Age"]
    data2 = request.form['Mygender']
    data3 = request.form['Chestpain']
    data4 = request.form['bloodpressure']
    data5 = request.form['cholestrol']
    data6 = request.form['fbloodsugar']
    data7 = request.form['RestingECG']
    data8 = request.form['Heartrate']
    data9 = request.form['ExerciseAngina']
    data10 = request.form['Stdepression']
    data11 = request.form['Slope']
    data12 = request.form['Caa']
    data13 = request.form['thal']
    arr = np.array([[data1, data2, data3, data4,data5,data6,data7,data8,data9,data10,data11,data12,data13]])
    pred = model.predict(arr)
    return render_template('prediction.html', data=pred)


@app.route('/update',methods=['POST','GET'])
@login_required
def update():
    form = RegisterForm()
    id = current_user.id
    name_to_update = User.query.get_or_404(id)
	
    name_to_update.username = request.form['username']
    name_to_update.email = request.form['email']
    name_to_update.password = request.form['password']
    db.session.commit()
    flash("User Updated Successfully!")
    return render_template("update.html", form=form, name_to_update = name_to_update)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
    


























if __name__ == '__main__':
    app.run(debug=True)