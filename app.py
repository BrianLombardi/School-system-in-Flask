from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'sua_chave_secreta'
db = SQLAlchemy(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    turmas = db.relationship('Turma', secondary='user_turma', backref='usuarios')
    materias = db.relationship('Materia', secondary='user_materia', backref='professores')
    cargos = db.relationship('Cargo', secondary='user_cargo', backref='usuarios')

class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)

class Cargo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)

class UserTurma(db.Model):
    __tablename__ = 'user_turma'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), primary_key=True)

class UserMateria(db.Model):
    __tablename__ = 'user_materia'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    materia_id = db.Column(db.Integer, db.ForeignKey('materia.id'), primary_key=True)

class UserCargo(db.Model):
    __tablename__ = 'user_cargo'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    cargo_id = db.Column(db.Integer, db.ForeignKey('cargo.id'), primary_key=True)

class Materia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)
    carga_horaria = db.Column(db.Integer, nullable=False)

# Rotas e funcionalidades
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
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            flash('Login realizado com sucesso!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            elif any(cargo.nome == 'Professor' for cargo in user.cargos):
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
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
    if 'user_id' in session and session.get('is_admin'):
        turmas = Turma.query.all()
        cargos = Cargo.query.all()
        users = User.query.all()
        materias = Materia.query.all()
        professors = [user for user in users if any(cargo.nome == 'Professor' for cargo in user.cargos)]
        return render_template('admin_dashboard.html', turmas=turmas, users=users, cargos=cargos, materias=materias, professors=professors)
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
        return redirect(url_for('login'))

@app.route('/assignment_detail/<int:assignment_id>')
def assignment_detail(assignment_id):
    if 'user_id' in session and not session.get('is_admin'):
        assignment = Assignment.query.get(assignment_id)
        if not assignment:
            flash('Assignment not found.', 'danger')
            return redirect(url_for('student_dashboard'))
        return render_template('assignment_detail.html', assignment=assignment)
    else:
        flash("Acesso negado. Faça login como aluno para acessar essa página.", "danger")
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

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.fullname = request.form['fullname']
        user.email = request.form['email']
        # Adicione qualquer outro campo que precise ser editado
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html', user=user)


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

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu com sucesso.', 'success')
    return redirect(url_for('index'))

@app.route('/add_professor/<int:user_id>', methods=['POST'])
def add_professor(user_id):
    if 'user_id' in session and session.get('is_admin'):
        user = db.session.get(User, user_id)
        if user:
            print(f"Usuário encontrado: {user.fullname}")
            professor_cargo = Cargo.query.filter_by(nome='Professor').first()
            if not professor_cargo:
                print("Cargo 'Professor' não encontrado, criando novo cargo.")
                professor_cargo = Cargo(nome='Professor', descricao='Professor na escola')
                db.session.add(professor_cargo)
                db.session.commit()
            if professor_cargo not in user.cargos:
                print(f"Adicionando cargo 'Professor' ao usuário {user.fullname}.")
                user.cargos.append(professor_cargo)
                db.session.commit()
                print(f"Usuário {user.fullname} agora é um professor.")
                flash('Usuário transformado em professor com sucesso!', 'success')
            else:
                print(f"Usuário {user.fullname} já é um professor.")
                flash('Usuário já é um professor!', 'info')
        else:
            print("Usuário não encontrado!")
            flash('Usuário não encontrado!', 'danger')
    else:
        print("Acesso negado. Faça login como administrador.")
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))



def create_db():
    db.create_all()
    if not User.query.filter_by(email='admin@exemplo.com').first():
        hashed_password = generate_password_hash("Abc123hy")
        admin_user = User(fullname="Admin", email="admin@exemplo.com", password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print("Usuário administrador criado com sucesso.")

if __name__ == '__main__':
    with app.app_context():
        create_db()
    app.run(debug=True)

# Definição do modelo de aluno
class Aluno(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)

# Definição do modelo de turma
class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    descricao = db.Column(db.String(255))
    alunos = db.relationship('Aluno', backref='turma', lazy=True)

@app.route('/')
def index():
    turmas = Turma.query.all()
    return render_template('index.html', turmas=turmas)

@app.route('/turma/<int:turma_id>/alunos')
def turma_alunos(turma_id):
    turma = Turma.query.get_or_404(turma_id)
    alunos = Aluno.query.filter_by(turma_id=turma.id).all()
    return render_template('turma_alunos.html', turma=turma, alunos=alunos)

@app.route('/admin_dashboard')
def admin_dashboard():
    professors = User.query.filter_by(role='professor').all()
    return render_template('admin_dashboard.html', professors=professors)
