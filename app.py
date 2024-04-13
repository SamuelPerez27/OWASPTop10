from flask import Flask, request, redirect, render_template, session
import pymysql.cursors
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import bcrypt

# ... rest of your code



app = Flask(__name__)


#Conexion a la base de datos
MYSQL_HOST="localhost"
MYSQL_PORT=5306
MYSQL_USER="root"
MYSQL_PASSWORD="password"
MYSQL_DATABASE="medioambiente"
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}'

database = SQLAlchemy(app)

secret_key = "ab23fa4dac99f035b1e707409f4149331c08d72fc9b886744aa01e93bc43010a"
app.config['SECRET_KEY'] = secret_key

# Configura la conexión a MySQL
###
##
class User(database.Model):
    __tablename__ = 'users'
    id = database.Column(database.Integer, primary_key=True)
    username = database.Column(database.String(80), unique=True, nullable=False)
    password = database.Column(database.String(256), nullable=False)
    login_attempts = database.Column(database.Integer, default=0, nullable=False)
    is_blocked = database.Column(database.Boolean, nullable=False, default=False)
    last_login = database.Column(database.DateTime, nullable=True)

    def encriptar_password(self, password):
        #generar sal
        salt = bcrypt.gensalt()
        # Codificar contraseña
        encoded_password = password.encode('utf-8')
        # Generar hash
        hash = bcrypt.hashpw(encoded_password, salt)
        self.password = hash

    def check_password(self, password):
        encoded_password = password.encode('utf-8')

        # bcrypt.checkpw(encoded_password, sam)
        # print(self.password)
        return bcrypt.checkpw(encoded_password, self.password)

### Routers 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Encode password

        try:
    
            user = User.query.filter_by(username=username).first()
            if user is not None:
                #encoded_token = jwt.encode(payload, password, algorithm="HS256")
               # payload = jwt.decode(encoded_token, password, algorithms=["HS256"])



              
                # current_time = datetime.datetime.utcnow()
                # if current_time > exp:
                #     print("Token expired:", exp)


                if user.is_blocked:
                    warning = "Tu cuenta está bloqueada. Contacta al administrador para más detalles."
                    return render_template('login.html', warning=warning)
                
                if user.login_attempts >= 3:
                    user.is_blocked = True
                    database.session.commit()
                    error = 'La cuenta está bloqueada temporalmente debido a demasiados intentos fallidos.'
                    return render_template('login.html', error=error)
                    
                if user.check_password(password):
                    print("Login successful")
                    user.login_attempts = 0
                    user.last_login = datetime.datetime.now()
                    database.session.commit()

                    # Create JWT token
                    payload = {
                        "username": username,
                        "iat": datetime.datetime.utcnow(),  # Momento de emisión
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1),  # Tiempo de expiración
                    }
                    #Método de encriptación
                    encoded_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")               
                    session['auth_jwt'] = encoded_token

                    return render_template('index.html')
                
                else:
                    user.login_attempts += 1
                    database.session.commit()
                    error = "Usuario y/o incorrecta."
                    return render_template('login.html', error=error)
                    
        
            else:
              error = "Usuario no encontrado."
              return render_template('login.html', error=error)
          

        except Exception as e:
            # Handle any errors during database operations
            print(f"Error during login: {e}")
          #  return render_template('login.html', error="An error occurred. Please try again.")
  
    return render_template('login.html')

##
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user is not None:
            return render_template('register.html', error="El Usuario ya existe, intente con otro nombre.")

        # Create new user
        new_user = User(username=username)
        new_user.encriptar_password(password)
        database.session.add(new_user)
        database.session.commit()

        return redirect('/login')

    return render_template('register.html')

@app.route('/')
def home():
    try:
        if 'auth_jwt' in session:
            decoded_token = jwt.decode(session['auth_jwt'], app.config['SECRET_KEY'], algorithms=["HS256"])
            current_time = datetime.datetime.now()
            expiration_time = datetime.datetime.fromtimestamp(decoded_token["exp"])
            
        
            if current_time > expiration_time:
                return redirect('/login')
            return render_template('index.html')
    except jwt.exceptions.ExpiredSignatureError:
        session.pop('auth_jwt', None)
        return redirect('/login')
    session.pop('auth_jwt', None)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('auth_jwt', None)
    return redirect('/login')


@app.errorhandler(404)  # Handle 404 errors
def invalid_route(error):
    # Render the 404 error page
    return render_template('404.html')

if __name__ == '__main__':
    with app.app_context():
        database.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
