import hashlib
import json
from time import time
from uuid import uuid4
import os
from textwrap import dedent
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import requests
import datetime

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blockchain_docs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    user_type = db.Column(db.String(20), default='user')  # 'user' or 'issuer'
    organization = db.Column(db.String(120), nullable=True)  # For issuers

    def __repr__(self):
        return f'<User {self.username}>'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    file_hash = db.Column(db.String(256), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.Float, default=time)
    block_index = db.Column(db.Integer, nullable=True)
    transaction_index = db.Column(db.Integer, nullable=True)
    
    def __repr__(self):
        return f'<Document {self.filename}>'

# Blockchain Class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        
        # Create a genesis block
        self.new_block(previous_hash=1, proof=100)
        
    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :return: <dict> New Block
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        
        # Reset the current list of transactions
        self.current_transactions = []
        
        self.chain.append(block)
        return block
    
    def new_transaction(self, sender, recipient, document_hash, document_id):
        """
        Creates a new transaction for document verification
        :param sender: <str> Issuer ID
        :param recipient: <str> User ID
        :param document_hash: <str> SHA-256 hash of the document
        :param document_id: <int> Database ID of the document
        :return: <int> The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'document_hash': document_hash,
            'document_id': document_id,
            'timestamp': time()
        })
        
        return self.last_block['index'] + 1
    
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    @property
    def last_block(self):
        return self.chain[-1]
    
    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm
        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
            
        return proof
    
    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Validates the Proof
        :return: <bool> True if correct, False if not.
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
    
    def register_node(self, address):
        """Add a new node to the list of nodes"""
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        
    def valid_chain(self, chain):
        """Determine if a given blockchain is valid"""
        last_block = chain[0]
        current_index = 1
        
        while current_index < len(chain):
            block = chain[current_index]
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False
            
            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False
            
            last_block = block
            current_index += 1    
        
        return True
    
    def resolve_conflicts(self):
        """Consensus Algorithm"""
        neighbours = self.nodes
        new_chain = None
        
        # Look for chains longer than ours
        max_length = len(self.chain)
        
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
                    
        if new_chain:
            self.chain = new_chain
            return True
        
        return False

    def find_document_transaction(self, document_hash):
        """Find a document transaction by its hash"""
        for block in self.chain:
            for transaction in block['transactions']:
                if 'document_hash' in transaction and transaction['document_hash'] == document_hash:
                    return {
                        'block_index': block['index'],
                        'transaction': transaction,
                        'verified': True
                    }
        return None

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def compute_file_hash(file_path):
    """Compute SHA-256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

# Initialize blockchain
blockchain = Blockchain()
node_identifier = str(uuid4()).replace('-', '')

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Routes for web interface
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user_type = request.form.get('user_type')
        organization = request.form.get('organization') if user_type == 'issuer' else None
        
        # Check if user exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.')
            return redirect(url_for('register'))
        
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            user_type=user_type,
            organization=organization
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_type'] = user.user_type
            
            flash('Login successful.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.template_filter('datetime')
def format_datetime(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    if user.user_type == 'issuer':
        # For issuers, show documents they've issued
        documents = Document.query.filter_by(issuer_id=user_id).all()
        return render_template('issuer_dashboard.html', documents=documents)
    else:
        # For regular users, show their documents
        documents = Document.query.filter_by(user_id=user_id).all()
        return render_template('user_dashboard.html', documents=documents)

@app.route('/issue_document', methods=['GET', 'POST'])
def issue_document():
    if 'user_id' not in session or session['user_type'] != 'issuer':
        flash('You do not have permission to issue documents.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        
        # Check if recipient exists
        recipient = User.query.filter_by(username=recipient_username).first()
        if not recipient:
            flash('Recipient not found.')
            return redirect(url_for('issue_document'))
        
        # Check if file was uploaded
        if 'document' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['document']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Compute file hash
            file_hash = compute_file_hash(file_path)
            
            # Check if document already exists
            existing_doc = Document.query.filter_by(file_hash=file_hash).first()
            if existing_doc:
                flash('This document has already been issued.')
                return redirect(url_for('issue_document'))
            
            # Create document record
            new_document = Document(
                filename=filename,
                file_hash=file_hash,
                user_id=recipient.id,
                issuer_id=session['user_id']
            )
            
            db.session.add(new_document)
            db.session.commit()
            
            # Add to blockchain
            block_index = blockchain.new_transaction(
                sender=session['user_id'],
                recipient=recipient.id,
                document_hash=file_hash,
                document_id=new_document.id
            )
            
            # Mine a new block
            last_block = blockchain.last_block
            last_proof = last_block['proof']
            proof = blockchain.proof_of_work(last_proof)
            previous_hash = blockchain.hash(last_block)
            block = blockchain.new_block(proof, previous_hash)
            
            # Update document with block info
            new_document.block_index = block['index']
            db.session.commit()
            
            flash('Document issued successfully!')
            return redirect(url_for('dashboard'))
    
    # Get all users for the dropdown
    users = User.query.filter_by(user_type='user').all()
    return render_template('issue_document.html', users=users)

@app.route('/verify_document', methods=['GET', 'POST'])
def verify_document():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['document']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Compute file hash
            file_hash = compute_file_hash(file_path)
            
            # Check database
            document = Document.query.filter_by(file_hash=file_hash).first()
            
            if document:
                # Check blockchain
                verification = blockchain.find_document_transaction(file_hash)
                
                if verification:
                    issuer = User.query.get(document.issuer_id)
                    user = User.query.get(document.user_id)
                    
                    result = {
                        'verified': True,
                        'issuer': issuer.username,
                        'organization': issuer.organization,
                        'user': user.username,
                        'timestamp': document.timestamp,
                        'block_index': document.block_index
                    }
                else:
                    result = {'verified': False, 'reason': 'Document not found in blockchain'}
            else:
                result = {'verified': False, 'reason': 'Document not found in database'}
            
            return render_template('verify_result.html', result=result)
    
    return render_template('verify_document.html')

# API Routes
@app.route('/api/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    
    nodes = values.get('nodes')
    if nodes is None:
        return jsonify({"error": "Please supply a valid list of nodes"}), 400
    
    for node in nodes:
        blockchain.register_node(node)
        
    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/api/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
        
    return jsonify(response), 200

@app.route('/api/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/api/documents/verify', methods=['POST'])
def api_verify_document():
    if 'document' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['document']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        file_hash = compute_file_hash(file_path)
        document = Document.query.filter_by(file_hash=file_hash).first()
        
        if document:
            verification = blockchain.find_document_transaction(file_hash)
            
            if verification:
                issuer = User.query.get(document.issuer_id)
                user = User.query.get(document.user_id)
                
                result = {
                    'verified': True,
                    'issuer': issuer.username,
                    'organization': issuer.organization,
                    'user': user.username,
                    'timestamp': document.timestamp,
                    'block_index': document.block_index
                }
            else:
                result = {'verified': False, 'reason': 'Document not found in blockchain'}
        else:
            result = {'verified': False, 'reason': 'Document not found in database'}
        
        return jsonify(result), 200
    
    return jsonify({"error": "Invalid file type"}), 400

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)