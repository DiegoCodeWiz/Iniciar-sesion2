from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import requests
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura_2026'

# ==================== CONFIGURACIÓN reCAPTCHA ====================
RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"

# ==================== CONFIGURACIÓN SQLITE ====================
DB_NAME = "usuarios.db"

def get_connection():
    """Crea y retorna una conexión a SQLite"""
    try:
        conn = sqlite3.connect(DB_NAME)
        return conn
    except Exception as e:
        print(f"Error conectando a SQLite: {e}")
        return None

# ==================== INICIALIZACIÓN BASE DE DATOS ====================
def init_db():
    """Crea la tabla de usuarios si no existe"""
    try:
        conn = get_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
            print("✅ Base de datos SQLite inicializada")
    except Exception as e:
        print(f"Error inicializando base de datos: {e}")

# ==================== FUNCIÓN VERIFICAR reCAPTCHA ====================
def verificar_recaptcha(respuesta_recaptcha):
    try:
        data = {'secret': RECAPTCHA_SECRET_KEY, 'response': respuesta_recaptcha}
        respuesta = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data, timeout=5)
        return respuesta.json().get('success', False)
    except:
        return False

# ==================== RUTAS ====================
@app.route('/')
def inicio():
    """Página de inicio con opciones de login y registro"""
    return render_template('inicio.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre, password FROM usuarios WHERE email = ?', (email,))
            user = cursor.fetchone()
            conn.close()
            
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['user_name'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                flash('Email o contraseña incorrectos', 'danger')
        except Exception as e:
            flash('Error en el sistema', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '') 
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        recaptcha_response = request.form.get('g-recaptcha-response', '')
        
        # 1. Validar reCAPTCHA
        if not verificar_recaptcha(recaptcha_response):
            flash('Por favor, completa el reCAPTCHA', 'danger')
            return redirect(url_for('register'))
        
        # 2. VALIDACIONES DE SEGURIDAD (Backend)
        errores = []
        
        # Validar Nombre
        if not nombre or len(nombre.strip()) < 3:
             errores.append('El nombre debe tener al menos 3 letras reales.')
        elif not re.match(r"^[A-Za-zñÑáéíóúÁÉÍÓÚ\s]+$", nombre):
             errores.append('El nombre solo puede contener letras.')

        # Validar Email
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            errores.append('Ingresa un correo válido.')

        # ==================== CAMBIO CLAVE AQUÍ ====================
        # Se eliminó (?=.*[\W_]) que era lo que obligaba a usar símbolos
        password_regex = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,20}$"
        
        if not re.match(password_regex, password):
            errores.append('La contraseña debe tener: 8-20 caracteres, Mayúscula, Minúscula y Número.')
        # ===========================================================

        if password != confirm_password:
            errores.append('Las contraseñas no coinciden.')

        if errores:
            for error in errores: flash(error, 'danger')
            return redirect(url_for('register'))
        
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT id FROM usuarios WHERE email = ?', (email,))
            if cursor.fetchone():
                conn.close()
                flash('Este correo ya está registrado', 'danger')
                return redirect(url_for('register'))
            
            hashed_pw = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)',
                (nombre.strip(), email, hashed_pw)
            )
            conn.commit()
            
            new_id = cursor.lastrowid
            conn.close()
            
            session['user_id'] = new_id
            session['user_name'] = nombre.strip()
            
            flash(f'¡Bienvenido {nombre.strip()}! Cuenta creada.', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error al registrar: {str(e)}', 'danger')
    
    return render_template('register.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Inicia sesión primero', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', nombre=session['user_name'])

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada', 'info')
    return redirect(url_for('inicio'))

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    init_db()
    app.run(debug=True, port=5000)