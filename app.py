from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'sua_chave_secreta'
db = SQLAlchemy(app)

# Modelos
# Modelo User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    turmas = db.relationship('Turma', secondary='user_turma', backref='usuarios')
    materias = db.relationship('Materia', secondary='user_materia', backref='professores')  # Relacionamento atualizado
    cargos = db.relationship('Cargo', secondary='user_cargo', backref='usuarios')

class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(255), nullable=False)
    materias = db.relationship('Materia', secondary='turma_materia', backref=db.backref('turmas', lazy='dynamic'))
    alunos = db.relationship('User', secondary='turma_aluno', backref=db.backref('turmas_associadas', lazy='dynamic'))
    materias_visiveis = db.Column(db.Boolean, default=True)
    alunos_visiveis = db.Column(db.Boolean, default=True)

# Tabelas de Associação
turma_materia = db.Table('turma_materia',
    db.Column('turma_id', db.Integer, db.ForeignKey('turma.id'), primary_key=True),
    db.Column('materia_id', db.Integer, db.ForeignKey('materia.id'), primary_key=True)
)

turma_aluno = db.Table('turma_aluno',
    db.Column('turma_id', db.Integer, db.ForeignKey('turma.id'), primary_key=True),
    db.Column('aluno_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

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
    professor_atual_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    professor_atual = db.relationship('User', backref='materias_atual')
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

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session and session.get('is_admin'):
        turmas = Turma.query.all()
        cargos = Cargo.query.all()
        users = User.query.all()
        materias = Materia.query.all()
        professors = [user for user in users if any(cargo.nome == 'Professor' for cargo in user.cargos)]
        alunos = [user for user in users if not any(cargo.nome == 'Professor' for cargo in user.cargos)]
        return render_template('admin_dashboard.html', turmas=turmas, users=users, cargos=cargos, materias=materias, professors=professors, alunos=alunos)
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

@app.route('/delete_turma/<int:turma_id>', methods=['POST'])
def delete_turma(turma_id):
    if 'user_id' in session and session.get('is_admin'):
        turma = Turma.query.get_or_404(turma_id)
        db.session.delete(turma)
        db.session.commit()
        flash('Turma deletada com sucesso!', 'success')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_materia/<int:materia_id>', methods=['POST'])
def delete_materia(materia_id):
    if 'user_id' in session and session.get('is_admin'):
        materia = Materia.query.get_or_404(materia_id)
        db.session.delete(materia)
        db.session.commit()
        flash('Matéria deletada com sucesso!', 'success')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))
@app.route('/delete_cargo/<int:cargo_id>', methods=['POST'])
def delete_cargo(cargo_id):
    if 'user_id' in session and session.get('is_admin'):
        cargo = Cargo.query.get_or_404(cargo_id)
        db.session.delete(cargo)
        db.session.commit()
        flash('Cargo deletado com sucesso!', 'success')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_professor/<int:user_id>', methods=['POST'])
def add_professor(user_id):
    if 'user_id' in session and session.get('is_admin'):
        user = db.session.get(User, user_id)
        if user:
            professor_cargo = Cargo.query.filter_by(nome='Professor').first()
            if not professor_cargo:
                professor_cargo = Cargo(nome='Professor', descricao='Professor na escola')
                db.session.add(professor_cargo)
                db.session.commit()
            if professor_cargo not in user.cargos:
                user.cargos.append(professor_cargo)
                db.session.commit()
                flash('Usuário transformado em professor com sucesso!', 'success')
            else:
                flash('Usuário já é um professor!', 'info')
        else:
            flash('Usuário não encontrado!', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/remove_professor/<int:user_id>', methods=['POST'])
def remove_professor(user_id):
    user = User.query.get_or_404(user_id)
    professor_cargo = Cargo.query.filter_by(nome='Professor').first()
    if professor_cargo in user.cargos:
        user.cargos.remove(professor_cargo)
        if not user.cargos:
            aluno_cargo = Cargo.query.filter_by(nome='Aluno').first()
            if not aluno_cargo:
                aluno_cargo = Cargo(nome='Aluno', descricao='Usuário sem cargos específicos')
                db.session.add(aluno_cargo)
            user.cargos.append(aluno_cargo)
        db.session.commit()
        flash(f'Cargo de professor removido de {user.fullname}.', 'success')
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

@app.route('/edit_turma/<int:turma_id>', methods=['POST'])
def edit_turma(turma_id):
    turma = Turma.query.get_or_404(turma_id)
    turma.nome = request.form['nome']
    turma.descricao = request.form['descricao']
    db.session.commit()
    flash('Turma atualizada com sucesso!', 'success')
    return redirect(url_for('admin_dashboard'))
@app.route('/edit_materia/<int:materia_id>', methods=['POST'])
def edit_materia(materia_id):
    if 'user_id' in session and session.get('is_admin'):
        materia = db.session.get(Materia, materia_id)
        if materia:
            materia.nome = request.form['nome']
            materia.descricao = request.form['descricao']
            materia.carga_horaria = request.form['carga_horaria']
            
            professor_atual_id = request.form['professor_atual_id']
            professor_atual = db.session.get(User, professor_atual_id)
            if professor_atual and any(cargo.nome == 'Professor' for cargo in professor_atual.cargos):
                materia.professor_atual = professor_atual
            
            db.session.commit()
            flash('Matéria atualizada com sucesso!', 'success')
        else:
            flash('Matéria não encontrada.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_cargo/<int:cargo_id>', methods=['POST'])
def edit_cargo(cargo_id):
    cargo = Cargo.query.get_or_404(cargo_id)
    cargo.nome = request.form['nome']
    cargo.descricao = request.form['descricao']
    db.session.commit()
    flash('Cargo atualizado com sucesso!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/assign_professor_to_materia/<int:materia_id>', methods=['POST'])
def assign_professor_to_materia(materia_id):
    if 'user_id' in session and session.get('is_admin'):
        professor_id = request.form['professor_atual_id']
        user = db.session.get(User, professor_id)
        materia = db.session.get(Materia, materia_id)

        if user and materia and any(cargo.nome == 'Professor' for cargo in user.cargos):
            materia.professor_atual = user  # Atribuindo o professor atual
            db.session.commit()
            flash('Professor associado à matéria com sucesso!', 'success')
        else:
            flash('Usuário não encontrado, não é professor ou matéria não encontrada.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/toggle_materias_visiveis/<int:turma_id>', methods=['POST'])
def toggle_materias_visiveis(turma_id):
    if 'user_id' in session and session.get('is_admin'):
        turma = db.session.get(Turma, turma_id)
        if turma:
            turma.materias_visiveis = not turma.materias_visiveis
            db.session.commit()
            status = "ativadas" if turma.materias_visiveis else "desativadas"
            flash(f'Matérias {status} com sucesso!', 'success')
        else:
            flash('Turma não encontrada.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/toggle_alunos_visiveis/<int:turma_id>', methods=['POST'])
def toggle_alunos_visiveis(turma_id):
    if 'user_id' in session and session.get('is_admin'):
        turma = db.session.get(Turma, turma_id)
        if turma:
            turma.alunos_visiveis = not turma.alunos_visiveis
            db.session.commit()
            status = "ativados" if turma.alunos_visiveis else "desativados"
            flash(f'Alunos {status} com sucesso!', 'success')
        else:
            flash('Turma não encontrada.', 'danger')
    else:
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

def assign_alunos_to_turma(turma_id):
    if 'user_id' in session and session.get('is_admin'):
        aluno_ids = request.form.getlist('aluno_ids')
        turma = Turma.query.get_or_404(turma_id)

        if turma:
            alunos = User.query.filter(User.id.in_(aluno_ids)).all()
            turma.alunos = alunos  # Sobrescreve os alunos atuais com os selecionados
            db.session.commit()
            flash('Alunos adicionados à turma com sucesso!', 'success')
        else:
            flash('Turma não encontrada.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))


# Rota para adicionar matérias à turma
@app.route('/assign_materias_to_turma/<int:turma_id>', methods=['POST'])
def assign_materias_to_turma(turma_id):
    if 'user_id' in session and session.get('is_admin'):
        materia_ids = request.form.getlist('materia_ids')
        turma = Turma.query.get_or_404(turma_id)

        if turma:
            for materia_id in materia_ids:
                materia = Materia.query.get(materia_id)
                if materia and materia not in turma.materias:
                    turma.materias.append(materia)
            db.session.commit()
            flash('Matérias adicionadas à turma com sucesso!', 'success')
        else:
            flash('Turma não encontrada.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

# Rota para adicionar alunos à turma
@app.route('/assign_alunos_to_turma/<int:turma_id>', methods=['POST'])
def assign_alunos_to_turma(turma_id):
    if 'user_id' in session and session.get('is_admin'):
        aluno_ids = request.form.getlist('aluno_ids')
        turma = Turma.query.get_or_404(turma_id)

        if turma:
            for aluno_id in aluno_ids:
                aluno = User.query.get(aluno_id)
                if aluno and aluno not in turma.alunos:
                    turma.alunos.append(aluno)
            db.session.commit()
            flash('Alunos adicionados à turma com sucesso!', 'success')
        else:
            flash('Turma não encontrada.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))



@app.route('/remove_materia_from_turma/<int:turma_id>/<int:materia_id>', methods=['POST'])
def remove_materia_from_turma(turma_id, materia_id):
    if 'user_id' in session and session.get('is_admin'):
        turma = db.session.get(Turma, turma_id)
        materia = db.session.get(Materia, materia_id)
        
        if turma and materia and materia in turma.materias:
            turma.materias.remove(materia)
            db.session.commit()
            flash('Matéria removida da turma com sucesso!', 'success')
        else:
            flash('Turma ou Matéria não encontradas.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/remove_aluno_from_turma/<int:turma_id>/<int:aluno_id>', methods=['POST'])
def remove_aluno_from_turma(turma_id, aluno_id):
    if 'user_id' in session and session.get('is_admin'):
        turma = db.session.get(Turma, turma_id)
        aluno = db.session.get(User, aluno_id)
        
        if turma and aluno and aluno in turma.alunos:
            turma.alunos.remove(aluno)
            db.session.commit()
            flash('Aluno removido da turma com sucesso!', 'success')
        else:
            flash('Turma ou Aluno não encontrados.', 'danger')
    else:
        flash('Acesso negado. Faça login como administrador.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/student_dashboard')
def student_dashboard():
    if 'user_id' in session and not session.get('is_admin'):
        user = User.query.get(session['user_id'])
        turmas = user.turmas_associadas  # Buscar turmas associadas ao aluno
        aulas = []  # Inicializando a lista de aulas
        for turma in turmas:
            aulas += turma.aulas  # Adiciona as aulas de cada turma à lista
        return render_template('student_dashboard.html', user=user, turmas=turmas, aulas=aulas)
    else:
        flash('Acesso negado. Faça login como aluno para acessar essa página.', 'danger')
        return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        create_db()
    app.run(debug=True)
