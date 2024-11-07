from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'sua_chave_secreta'
db = SQLAlchemy(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    turmas = db.relationship('Turma', secondary='user_turma', backref='usuarios')
    materias = db.relationship('Materia', secondary='user_materia', backref='professores')

# Modelo de Turma
class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)

# Modelo de Cargo
class Cargo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)

# Tabela de Associação entre Usuário e Turma
class UserTurma(db.Model):
    __tablename__ = 'user_turma'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), primary_key=True)

# Tabela de Associação entre Usuário e Matéria
class UserMateria(db.Model):
    __tablename__ = 'user_materia'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    materia_id = db.Column(db.Integer, db.ForeignKey('materia.id'), primary_key=True)

# Modelo de Matéria
class Materia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)
    carga_horaria = db.Column(db.Integer, nullable=False)

# Função para criar o banco de dados e o administrador
def create_db():
    db.create_all()
    # Criação do usuário administrador padrão
    if not User.query.filter_by(email='admin@exemplo.com').first():
        hashed_password = generate_password_hash("Abc123hy")
        admin_user = User(fullname="Admin", email="admin@exemplo.com", password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print("Usuário administrador criado com sucesso.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Armazena o ID do usuário na sessão
            session['is_admin'] = user.is_admin
            flash('Login realizado com sucesso!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            flash('E-mail ou senha incorretos.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('As senhas não coincidem!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('E-mail já cadastrado!', 'danger')
            return redirect(url_for('register'))

        is_admin = email == "admin@exemplo.com" and password == "Abc123hy"
        hashed_password = generate_password_hash(password)
        new_user = User(fullname=fullname, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash('Registro realizado com sucesso! Você pode fazer login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin')
def admin_dashboard():
    # Verifica se o usuário logado é um administrador
    if 'user_id' in session and session.get('is_admin'):
        turmas = Turma.query.all()  # Recupera todas as turmas
        cargos = Cargo.query.all()  # Recupera todos os cargos
        users = User.query.all()  # Recupera todos os usuários
        materias = Materia.query.all()  # Recupera todas as matérias
        return render_template('admin_dashboard.html', turmas=turmas, users=users, cargos=cargos, materias=materias)
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
        return redirect(url_for('login'))

@app.route('/create_turma', methods=['POST'])
def create_turma():
    if 'user_id' in session and session.get('is_admin'):
        nome = request.form['nome']
        descricao = request.form['descricao']
        nova_turma = Turma(nome=nome, descricao=descricao)
        db.session.add(nova_turma)
        db.session.commit()
        flash('Turma criada com sucesso!', 'success')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/create_cargo', methods=['POST'])
def create_cargo():
    if 'user_id' in session and session.get('is_admin'):
        nome = request.form['nome']
        descricao = request.form['descricao']
        novo_cargo = Cargo(nome=nome, descricao=descricao)
        db.session.add(novo_cargo)
        db.session.commit()
        flash('Cargo criado com sucesso!', 'success')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/create_materia', methods=['POST'])
def create_materia():
    if 'user_id' in session and session.get('is_admin'):
        nome = request.form['nome_materia']
        descricao = request.form['descricao_materia']
        carga_horaria = request.form['carga_horaria']
        nova_materia = Materia(nome=nome, descricao=descricao, carga_horaria=carga_horaria)
        db.session.add(nova_materia)
        db.session.commit()
        flash('Matéria criada com sucesso!', 'success')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/assign_professor_to_materia/<int:materia_id>', methods=['POST'])
def assign_professor_to_materia(materia_id):
    if 'user_id' in session and session.get('is_admin'):
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        materia = Materia.query.get(materia_id)

        if user and materia and any(cargo.nome == 'Professor' for cargo in user.cargos):
            user.materias.append(materia)
            db.session.commit()
            flash('Professor associado à matéria com sucesso!', 'success')
        else:
            flash('Usuário não encontrado, não é professor ou matéria não encontrada.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_user_to_turma/<int:turma_id>', methods=['POST'])
def add_user_to_turma(turma_id):
    if 'user_id' in session and session.get('is_admin'):
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        turma = Turma.query.get(turma_id)
        if user and turma:
            user.turmas.append(turma)
            db.session.commit()
            flash('Usuário adicionado à turma com sucesso!', 'success')
        else:
            flash('Usuário ou Turma não encontrados!', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

# Rota para deletar um usuário
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' in session and session.get('is_admin'):
        try:
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('Usuário deletado com sucesso!', 'success')
            else:
                flash('Usuário não encontrado!', 'danger')
        except ValueError:
            flash('ID do usuário inválido!', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

# Rota de logout
@app.route('/logout')
def logout():
    session.clear()  # Limpa a sessão do usuário
    flash('Você saiu com sucesso.', 'success')
    return redirect(url_for('index'))  # Redireciona para a página principal

if __name__ == '__main__':
    with app.app_context():
        create_db()
    app.run(debug=True)
