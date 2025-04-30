import hashlib
import json
from time import time
from uuid import uuid4
import os
from textwrap import dedent
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session, send_from_directory
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import requests
import datetime
from bson.objectid import ObjectId

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# MongoDB setup
app.config['MONGO_URI'] = 'mongodb+srv://anshulujethva:M8fPEyVfXqZJteBK@cluster0.8wkwxwd.mongodb.net/'
mongo_client = MongoClient(app.config['MONGO_URI'])
db = mongo_client['blockchain_docs']

# Collection names
users_collection = db.users
documents_collection = db.documents
blockchain_collection = db.blockchain  # New collection for blockchain persistence

# Blockchain Class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        
        # Try to load existing blockchain from database
        self.load_from_db()
        
        # If no blockchain exists, create a genesis block
        if not self.chain:
            self.new_block(previous_hash=1, proof=100)
        
    def load_from_db(self):
        """Load blockchain from MongoDB"""
        blockchain_data = blockchain_collection.find_one({"_id": "blockchain"})
        if blockchain_data:
            self.chain = blockchain_data.get("chain", [])
            self.nodes = set(blockchain_data.get("nodes", []))
            # current_transactions is initialized as empty for safety
            self.current_transactions = []
    
    def save_to_db(self):
        """Save blockchain to MongoDB"""
        blockchain_collection.update_one(
            {"_id": "blockchain"},
            {"$set": {
                "chain": self.chain,
                "nodes": list(self.nodes)
            }},
            upsert=True
        )
        
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
        
        # Save the updated blockchain to database
        self.save_to_db()
        
        return block
    
    def new_transaction(self, sender, recipient, document_hash, document_id):
        """
        Creates a new transaction for document verification
        :param sender: <str> Issuer ID
        :param recipient: <str> User ID
        :param document_hash: <str> SHA-256 hash of the document
        :param document_id: <str> MongoDB ID of the document
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
        # Save the updated nodes to the database
        self.save_to_db()
        
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
            # Save the updated blockchain to the database
            self.save_to_db()
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
        if users_collection.find_one({"username": username}) or users_collection.find_one({"email": email}):
            flash('Username or email already exists.')
            return redirect(url_for('register'))
        
        new_user = {
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "user_type": user_type,
            "organization": organization
        }
        
        users_collection.insert_one(new_user)
        
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users_collection.find_one({"username": username})
        
        if user and check_password_hash(user["password_hash"], password):
            session['user_id'] = str(user["_id"])
            session['username'] = user["username"]
            session['user_type'] = user["user_type"]
            
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
def format_datetime(timestamp):
    dt = datetime.datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if user["user_type"] == 'issuer':
        # For issuers, show documents they've issued
        documents = list(documents_collection.find({"issuer_id": user_id}))
        return render_template('issuer_dashboard.html', documents=documents)
    else:
        # For regular users, show their documents
        documents = list(documents_collection.find({"user_id": user_id}))
        return render_template('user_dashboard.html', documents=documents)

@app.route('/issue_document', methods=['GET', 'POST'])
def issue_document():
    if 'user_id' not in session or session['user_type'] != 'issuer':
        flash('You do not have permission to issue documents.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        
        # Check if recipient exists
        recipient = users_collection.find_one({"username": recipient_username})
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
            existing_doc = documents_collection.find_one({"file_hash": file_hash})
            if existing_doc:
                flash('This document has already been issued.')
                return redirect(url_for('issue_document'))
            
            # Create document record
            new_document = {
                "filename": filename,
                "file_hash": file_hash,
                "user_id": str(recipient["_id"]),
                "issuer_id": session['user_id'],
                "timestamp": time(),
                "block_index": None,
                "transaction_index": None
            }
            
            result = documents_collection.insert_one(new_document)
            document_id = str(result.inserted_id)
            
            # Add to blockchain
            block_index = blockchain.new_transaction(
                sender=session['user_id'],
                recipient=str(recipient["_id"]),
                document_hash=file_hash,
                document_id=document_id
            )
            
            # Mine a new block
            last_block = blockchain.last_block
            last_proof = last_block['proof']
            proof = blockchain.proof_of_work(last_proof)
            previous_hash = blockchain.hash(last_block)
            block = blockchain.new_block(proof, previous_hash)
            
            # Update document with block info
            documents_collection.update_one(
                {"_id": ObjectId(document_id)},
                {"$set": {"block_index": block['index']}}
            )
            
            flash('Document issued successfully!')
            return redirect(url_for('dashboard'))
    
    # Get all users for the dropdown
    users = list(users_collection.find({"user_type": 'user'}))
    return render_template('issue_document.html', users=users)

@app.route('/document/<document_id>/update', methods=['GET', 'POST'])
def update_document(document_id):
    """Update a document"""
    if 'user_id' not in session or session['user_type'] != 'issuer':
        flash('You do not have permission to update documents.')
        return redirect(url_for('dashboard'))
    
    # Get the document
    document = documents_collection.find_one({"_id": ObjectId(document_id)})
    
    if not document:
        flash('Document not found.')
        return redirect(url_for('dashboard'))
    
    # Check if the issuer has permission to update the document
    if document['issuer_id'] != session['user_id']:
        flash('You do not have permission to update this document.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
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
            
            # Add to blockchain
            block_index = blockchain.new_transaction(
                sender=session['user_id'],
                recipient=document['user_id'],
                document_hash=file_hash,
                document_id=document_id
            )
            
            # Mine a new block
            last_block = blockchain.last_block
            last_proof = last_block['proof']
            proof = blockchain.proof_of_work(last_proof)
            previous_hash = blockchain.hash(last_block)
            block = blockchain.new_block(proof, previous_hash)
            
            # Update document with new info
            documents_collection.update_one(
                {"_id": ObjectId(document_id)},
                {"$set": {
                    "filename": filename,
                    "file_hash": file_hash,
                    "timestamp": time(),
                    "block_index": block['index']
                }}
            )
            
            flash('Document updated successfully!')
            return redirect(url_for('dashboard'))
    
    # Fetch user information
    user = users_collection.find_one({"_id": ObjectId(document['user_id'])})
    
    return render_template('update_document.html', document=document, user=user)

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
            document = documents_collection.find_one({"file_hash": file_hash})
            
            if document:
                # Check blockchain
                verification = blockchain.find_document_transaction(file_hash)
                
                if verification:
                    issuer = users_collection.find_one({"_id": ObjectId(document["issuer_id"])})
                    user = users_collection.find_one({"_id": ObjectId(document["user_id"])})
                    
                    result = {
                        'verified': True,
                        'issuer': issuer["username"],
                        'organization': issuer.get("organization"),
                        'user': user["username"],
                        'timestamp': document["timestamp"],
                        'block_index': document["block_index"]
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
        document = documents_collection.find_one({"file_hash": file_hash})
        
        if document:
            verification = blockchain.find_document_transaction(file_hash)
            
            if verification:
                issuer = users_collection.find_one({"_id": ObjectId(document["issuer_id"])})
                user = users_collection.find_one({"_id": ObjectId(document["user_id"])})
                
                result = {
                    'verified': True,
                    'issuer': issuer["username"],
                    'organization': issuer.get("organization"),
                    'user': user["username"],
                    'timestamp': document["timestamp"],
                    'block_index': document["block_index"]
                }
            else:
                result = {'verified': False, 'reason': 'Document not found in blockchain'}
        else:
            result = {'verified': False, 'reason': 'Document not found in database'}
        
        return jsonify(result), 200
    
    return jsonify({"error": "Invalid file type"}), 400

# Helper function to get user by id - for templates
@app.context_processor
def utility_processor():
    def get_user(user_id):
        return users_collection.find_one({"_id": ObjectId(user_id)})
    
    return dict(User={"query": {"get": get_user}})

# Add a debug route to view the blockchain
@app.route('/blockchain_debug')
def blockchain_debug():
    # Only allow access in debug mode
    if app.debug:
        return jsonify({
            'chain': blockchain.chain,
            'length': len(blockchain.chain),
            'current_transactions': blockchain.current_transactions
        })
    return jsonify({'error': 'Access denied'}), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)