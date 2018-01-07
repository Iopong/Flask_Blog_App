from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

'''
INSTANCE OF FLASK
'''
#Create instance of flask app
app = Flask(__name__)

#config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'firstapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#initialize MySQL
mysql = MySQL(app)

#Articles = Articles()

'''
VIEW FUNCTIONS
'''

#index page
@app.route('/')
def index():
	#Root element
	#Return value is called a response --> What the client receives.
	#Could also return '<h1>Hello World!</h1>'
	return render_template('home.html')

#About page
@app.route('/about')
def about():
	return render_template('about.html')

#Article page
@app.route('/articles')
def articles():
	#create DictCursor
	cur = mysql.connection.cursor()


	#Get Articles
	result = cur.execute("SELECT * FROM articles")

	#Returns article in dict format
	articles = cur.fetchall()

	if result > 0:
		return render_template('articles.html', articles=articles)
	else:
		msg = 'No Articles Found'
		return render_template('articles.html', msg=msg)

	#close connection
	cur.close()

	return render_template('articles.html')

#Single article
@app.route('/article/<string:id>/')
def article(id):
	#create DictCursor
	cur = mysql.connection.cursor()

	#Get Articles
	result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

	#Returns article in dict format
	article = cur.fetchone()

	return render_template('article.html', article=article)

"""
REGISTER FORM
"""
#A form requires you to have a class for the register form.
#WTF forms by default protects all forms from
#Cross-Site Request Forgery (CSRF) attacks. 
#A CSRF attack occurs when a malicious website sends requests to a different
#website on which the victim is logged in.
class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username = StringField('Username', [validators.Length(min=4, max=25)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	password = PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message="Password do not match")
	])

	confirm = PasswordField('Confirm Password')

#User register
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data)) #must encrpyt before submission

		#create DictCursor
		#Execute query
		cur = mysql.connection.cursor()
		cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

		#commit to DB
		mysql.connection.commit()

		#close connection
		cur.close()

		flash('You are now registered and can log in', 'success')

		return redirect(url_for('login'))
	return render_template('register.html', form=form)

#user login
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		#Get form username and Password
		#We are not using the WTF form. This is how you'd usually
		#Get form information.
		username = request.form['username']
		password_candidate = request.form['password']

		#create DictCursor
		cur = mysql.connection.cursor()

		#get user by Username
		result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

		if result > 0:
			#Get the stored password or hash
			#It will only fetch the first occurence of that username.
			data = cur.fetchone()
			password = data['password']

			#now compare the password
			if sha256_crypt.verify(password_candidate, password):
				#Passed
				session['logged_in'] = True
				session['username'] = username

				#flash a message
				flash('You are now logged in', 'success')
				return redirect(url_for('dashboard'))
			else:
				app.logger.info('PASSWORD NOT MATCHED')
				error = 'Invalid Login'
				return render_template('login.html', error=error)
		else:
			app.logger.info('NO USER')
			error = 'Username not found'
			return render_template('login.html', error=error)
		#close connection
		cur.close()

	return render_template('login.html')

#use decorators to enable or disable certain functionalities
#In this instance we do not want the user to able to access Dashboard if they
#Arent logged in.
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorized, Please Login', 'danger')
			return redirect(url_for('login'))
	return wrap


#logout
@app.route('/logout')
@is_logged_in
def logout():
	session.clear()
	flash('You are now logged out', 'success')
	return redirect(url_for('login'))

#Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
	#create DictCursor
	cur = mysql.connection.cursor()


	#Get Articles
	result = cur.execute("SELECT * FROM articles")

	#Returns article in dict format
	articles = cur.fetchall()

	if result > 0:
		return render_template('dashboard.html', articles=articles)
	else:
		msg = 'No Articles Found'
		return render_template('dashboard.html', msg=msg)

	#close connection
	cur.close()

	return render_template('dashboard.html')

#Article form class
#WTF forms
class ArticleForm(Form):
	title = StringField('Title', [validators.Length(min=1, max=100)])
	body = TextAreaField('Body', [validators.Length(min=30)])

#Add Article route
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
	form = ArticleForm(request.form)
	if request.method == 'POST' and form.validate():
		title = form.title.data
		body = form.body.data

		#create cursor
		cur = mysql.connection.cursor()

		#Execute
		cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)", (title, body, session['username']))

		#commit to DB
		mysql.connection.commit()

		#Close connection
		cur.close()

		flash('Article Created', 'success')

		return redirect(url_for('dashboard'))

	return render_template('add_article.html', form=form)

#Edit Article route
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
	#Create cursor
	cur = mysql.connection.cursor()

	#Get Article from DB
	result = cur.execute("SELECT * FROM articles WHERE id=%s", [id])

	#Fetch only one
	article = cur.fetchone()

	#Get our form and auto populate
	form = ArticleForm(request.form)

	#Populate article form fields
	form.title.data = article['title']
	form.body.data = article['body']

	if request.method == 'POST' and form.validate():
		title = request.form['title']
		body = request.form['body']

		#create cursor
		cur = mysql.connection.cursor()

		#Execute
		cur.execute("UPDATE articles SET title=%s, body=%s WHERE id=%s", (title, body, id))

		#commit to DB
		mysql.connection.commit()

		#Close connection
		cur.close()

		flash('Article Updated', 'success')

		return redirect(url_for('dashboard'))

	return render_template('edit_article.html', form=form)

#Delete articles
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
	#create cursor
	cur = mysql.connection.cursor()

	#execute
	cur.execute("DELETE FROM articles WHERE id=%s", [id])

	#commit changes to DB
	mysql.connection.commit()

	#close connection
	cur.close()

	#flash message
	flash('Article Deleted', 'success')

	return redirect(url_for('dashboard'))

#Name finds the main and runs the main app
#We set app debug = True so we do not have to keep reloading
if __name__ == '__main__':
	app.secret_key='secret123'
	app.run(debug=True)
