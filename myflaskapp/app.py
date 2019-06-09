from waitress import serve
from flask import request
from flask import Flask,render_template,flash,redirect,url_for,session,logging
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL


app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)
app.debug=True


@app.route('/')
def index():
	return render_template('home.html')

@app.route('/Link')
def Link():
	return render_template('Link.html')

class RegisterForm(Form):
	name=StringField('Name',[validators.Length(min=1,max=50)])
	username=StringField('Username',[validators.Length(min=4,max=50)])
	email=StringField('Email',[validators.Length(min=4,max=50)])    
	password=PasswordField('Password',[validators.DataRequired(),validators.EqualTo('confirm',message='password do not match')])
	confirm=PasswordField('Confirm Password')

@app.route('/register',methods=['GET','POST'])
def register():
	 form = RegisterForm(request.form)
	 if request.method == 'POST' and form.validate():
	 	name = form.name.data
	 	email=form.email.data
	 	username = form.username.data
	 	password = sha256_crypt.encrypt(str(form.password.data))
	 	cur = mysql.connection.cursor()
	 	cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
	 	mysql.connection.commit()
	 	cur.close()
	 	flash('You are now registered and can log in', 'success')
	 	return redirect(url_for('login'))
	 return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_candidate, password):
            	session['logged_in'] = True
            	session['username'] = username
            	flash('You are now logged in', 'success')
            	return redirect(url_for('dashboard'))
            else:
            	error='Invalid login'
            
            	return render_template('login.html',error=error)
            cur.close()
        else:
        	error='Username not found'
        	return render_template('login.html',error=error)
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
	return render_template('dashboard.html')

if __name__ == '__main__':
	app.secret_key='secret123'
	app.run()

#serve(app, host='0.0.0.0', port=8080)






 
