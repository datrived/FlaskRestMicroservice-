import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from sqlalchemy_utils import database_exists, create_database, drop_database
from sqlalchemy import create_engine
import psycopg2
import base64






# can set explicitly with environment

'''
def get_env_variable(name):
    try:
        return os.environ[name]
    except KeyError:
        message = "Expected environment variable '{}' not set.".format(name)
        raise Exception(message)

# the values of those depend on your setup
POSTGRES_URL = get_env_variable("POSTGRES_URL")
POSTGRES_USER = get_env_variable("POSTGRES_USER")
POSTGRES_PW = get_env_variable("POSTGRES_PW")
POSTGRES_DB = get_env_variable("POSTGRES_DB")
'''

# Hard Coded

POSTGRES_URL="127.0.0.1:5432"
POSTGRES_USER="postgres"
POSTGRES_PW="pgdbpass"
POSTGRES_DB="restCert"

#APP Configure

DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Hello Rest world. Welcome to my API.'
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL  
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True # To ensure persistence 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True  # TO Ease development and testing


### DATABASE and AUTHENTICATION Initialization

db = SQLAlchemy(app)
db_conn = create_engine(DB_URL)
auth = HTTPBasicAuth()
db.init_app(app)

class Customer(db.Model):
	__tablename__ = 'Customer'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(200))
	email = db.Column(db.String(200), unique=True)
	password_hash = db.Column(db.String(200)) #Secure Password storing
	
		
	def __init__(self,name, email, password):
		self.name = name.title()
		self.email = email.title()
		self.hash_password(password)
	
	#To Store password Hash Instead of password directly, Good Practice for security purpose	
	def hash_password(self, password):
		self.password_hash = pwd_context.encrypt(password)
	
	def verify_password(self, password):
		return pwd_context.verify(password, self.password_hash)
	
	def generate_auth_token(self, expiration=600):
		s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
		return s.dumps({'id': self.id})

    #Static for each customer, so customer can generate multiple tokens
	#all token will verify against the given credencials
	@staticmethod
	def verify_auth_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except SignatureExpired:
			return None    # Valid but Expired Token
		except BadSignature:
			return None    # Invalid Token
		customer = Customer.query.get(data['id'])
		return customer
	


	

class Certificate(db.Model):
	__tablename__ = 'Certificate'
	id = db.Column(db.Integer, primary_key=True)
	owner = db.Column(db.Integer, db.ForeignKey('Customer.id', ondelete='cascade'), nullable=False)
	activeFlag = db.Column(db.Boolean)
	certificateKey = db.Column(db.Text, unique=True)
	certificateBody = db.Column(db.Text, unique=True)
	customer = db.relationship('Customer')
	
	
	def __init__(self,owner, activeFlag, certificateKey, certificateBody):
		self.owner = owner
		self.activeFlag = activeFlag
		self.certificateKey = certificateKey
		self.certificateBody = certificateBody


#Create the customer and check if the customer already exist.
#If customer forgot their token then generate and send the token again if customer wants token based authentication
# Require unique email address from customer
#--- CURL --Test
#curl -i -X POST -H "Content-Type: application/json" -d '{"name": "kev", "password":"kev", "email":"kev@123.com"}' http://localhost:5000/api/customer
@app.route('/api/customer', methods=['POST'])
def create_customer():
    name = request.json.get('name')
    password = request.json.get('password')
    email = request.json.get('email')
    if name is None or password is None or email is None:
        abort(400)    # All fields are mandatory. Abort the request. 
    if Customer!= None and Customer.query.filter_by(name=name.title(), email=email.title()).first() is not None:
        customer = Customer.query.filter_by(name=name.title(), email=email.title()).first()
        print str(customer.verify_password(password))
        if customer.verify_password(password) == False:
			return jsonify({'status': 'Incorrect login credencials. Please try again!' }) 
        token = customer.generate_auth_token(600)
        return jsonify({'status': 'Customer Already exist!','token':token })  # existing user
    customer = Customer.query.filter_by(email=email.title()).first()
    if customer:
		return jsonify({'status': 'Email address already used!' }) 
    customer = Customer(name=name, email=email, password=password)

    db.session.add(customer)
    db.session.commit()
    token = customer.generate_auth_token(600)
    return jsonify({'status': 'Customer creted Successfully!','warning':'Please note it and use to access other services or submit this request again to get token.', 'token':token })

#deletes the customer
#Accepts token or 'name:password' field for Authentication with curl
#--- CURL -- with user name/password
# curl -u 'name:password' -i -X DELETE http://localhost:5000/api/deleteme
#--- CURL -- with Token
#  curl -u token:unused -i -X DELETE http://localhost:5000/api/deleteme
@app.route('/api/deleteme', methods=['DELETE'])
@auth.login_required
def delete_customer():
	customer =  g.customer
	if not customer:
		return jsonify({'status': ('No Customer. Please check the id or name.').decode('ascii')})
	name = customer.name
	db.session.delete(customer) #Commit to database
	db.session.commit()
	return jsonify({'status': ('Customer '+name +' deleted Successfully!').decode('ascii')})


#Cretes RSA Certificate key, body and stores in the database, reuire 'activeFlag=True/False' with curl
#Accepts token or 'name:password' field for Authentication with curl
#--- CURL -- with user name/password
# curl -u 'name:password' -i -X POST -H "Content-Type: application/json" -d '{"active":"True"}' http://localhost:5000/api/cert
#--- CURL -- with Token
# curl -u token:unused -i -X POST -H "Content-Type: application/json" -d '{"active":"True"}' http://localhost:5000/api/cert
@app.route('/api/cert', methods=['POST'])
@auth.login_required
def create_certificate():
	activeFlag = request.json.get('active')
	customer = g.customer
	if not customer:
		return jsonify({'status': ('No Customer. Please check the id or name.').decode('ascii')})
	owner = customer.id
	
	if activeFlag.title() == "True":
		activeFlag = True
	else:
		activeFlag = False
	#RSA Certificate Key cert generation
	key = RSA.generate(2048) 
	pemKey= key.exportKey('PEM')
	
	pubkey = RSA.importKey(pemKey)
	cipher = PKCS1_v1_5.new(pubkey)
	cipher_text = cipher.encrypt(customer.name.encode('utf-8'))
	cipher_text = base64.b64encode(cipher_text)
	certificate = Certificate(owner=owner, activeFlag=activeFlag, certificateKey=pemKey.encode('utf-8'), certificateBody =cipher_text.encode('utf-8') )
	db.session.add(certificate)
	db.session.commit()
	return jsonify({'status': 'Certificate created SUCCESSFULY...!' })

#Get all the active certificate (ONLY ACTIVE)
#Accepts token or 'name:password' field for Authentication with curl
#--- CURL -- with user name/password
# curl -u 'name:password' -i -X GET http://localhost:5000/api/getcert
#--- CURL -- with Token
# curl -u token:unused -i -X GET http://localhost:5000/api/getcert
@app.route('/api/getcert', methods=['GET'])
@auth.login_required
def get_active_certificates():
	customer = g.customer
	if not customer:
		return jsonify({'status': ('No Customer. Please check the id or name.').decode('ascii')})
	owner = customer.id
	
	certificates = Certificate.query.filter_by(owner = customer.id).all()
	strCert = {}
	i=0
	for cert in certificates:
		if cert.activeFlag == True:
			temp = {"id": cert.id, "owner": owner, "activeFlag": cert.activeFlag, "body":cert.certificateBody, "key": cert.certificateBody}
			strCert[i] = temp
			i = i+1
			
	return jsonify(strCert)


#Get all the certificate -- Helper API to determine list of certificates without detail
#Accepts token or 'name:password' field for Authentication with curl
#--- CURL -- with user name/password
# curl -u 'name:password' -i -X GET http://localhost:5000/api/getall
#--- CURL -- with Token
# curl -u token:unused -i -X GET http://localhost:5000/api/getall
@app.route('/api/getall', methods=['GET'])
@auth.login_required
def get_all_certificates():
	customer = g.customer
	if not customer:
		return jsonify({'status': ('No Customer. Please check the id or name.').decode('ascii')})
	owner = customer.id
	
	certificates = Certificate.query.filter_by(owner = customer.id).all()
	strCert = {}
	i=0
	for cert in certificates:
		temp = {"id": cert.id, "owner": owner, "activeFlag": cert.activeFlag}
		strCert[i] = temp
		i = i+1
			
	return jsonify(strCert)





#Change Certificate ActiveFlag (True/False)
#Accepts token or 'name:password' field for Authentication with curl
#--- CURL -- with user name/password
# curl -u 'name:password' -i -X POST -H "Content-Type: application/json" -d '{"active":"False","certID":"1"}' http://localhost:5000/api/changeCert
#--- CURL -- with Token
#curl -u token:unused  -i -X POST -H "Content-Type: application/json" -d '{"active":"False","certID":"1"}' http://localhost:5000/api/changeCert
@app.route('/api/changeCert', methods=['POST'])
@auth.login_required
def change_activeFlag():
    activeFlag = request.json.get('active')
    certID = request.json.get('certID')
    customer = g.customer
    if not customer:
        return jsonify({'status': ('No Customer. Please check the id or name.').decode('ascii')})
    owner = customer.id
	
    if activeFlag.title() == "True":
        activeStat = "Active"
        activeFlag = True
    else:
        activeStat = "Inactive"
        activeFlag = False
	
    certificate =Certificate.query.get(int(certID))
    if not certificate:
		return jsonify({'status': ('Certificate doen not Exist.').decode('ascii')})
    if certificate.activeFlag == activeFlag:
		return jsonify({'status': ('Certificate is already ' + activeStat ).decode('ascii')})
    certificate.activeFlag = activeFlag
    return jsonify({'status': ('Certificate Updated Successfully! Now your certificate is '+ activeStat).decode('ascii')})

# verify the password or Token internally for all the request
@auth.verify_password
def verify_password(name_or_token, password):
    # first try to authenticate by token
    customer = Customer.verify_auth_token(name_or_token)
    if not customer:
        # try to authenticate with username/password
        customer = Customer.query.filter_by(name=name_or_token.title()).first()
        if not customer or not customer.verify_password(password):
            return False
        if not customer:
            return False

    g.customer = customer
    return True


#####For testing only
### CURL TESTING
# curl  -i -X GET http://localhost:5000/api/getusers
@app.route('/api/getusers', methods=['GET'])
def get_all_customers():
	customer = Customer.query.all()
	str = {}
	i=0
	for c in customer:
		temp = {"id": c.id, "name":c.name, "email": c.email}
		str[i]=temp
		i = i+1
	return jsonify(str)



#####For testing only
### CURL TESTING
# curl  -i -X GET http://localhost:5000/api/getusers
@app.route('/api/getalluserscert', methods=['GET'])
def get_all_user_cert():
	certificates = Certificate.query.all()
	str = {}
	i=0
	for c in certificates:
		temp = {"id": c.id, "owner":c.owner, "activeFlag": c.activeFlag}
		str[i]=temp
		i = i+1
	return jsonify(str)

if __name__ == '__main__':
	port = int(os.environ.get('PORT', 5000))
	if not database_exists(DB_URL):
		print('Creating database.')
		create_database(DB_URL)
		db.create_all()
		db.session.commit()
		
	
	
	app.run(debug=True, port = port)