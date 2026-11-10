"""Music Manager - administrador personal de música escuchada (versión endurecida).

Mejoras de seguridad respecto a la versión original (ver INFORME_SEGURIDAD.md):
autenticación, CSRF, cabeceras, límites, validación en servidor, configuración
por entorno, registro de eventos y sin modo debug por defecto.
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, redirect, render_template, request, session, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager, UserMixin, current_user, login_required, login_user, logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

# ---------------------------------------------------------------------------
# Extensiones (se inicializan dentro de create_app)
# ---------------------------------------------------------------------------
db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
limiter = Limiter(
    get_remote_address,
    default_limits=["120 per minute"],
    default_limits_exempt_when=lambda: request.endpoint == "static",
)

COMMON_GENRES = [
    "Rock", "Pop", "Hip hop", "Reggaeton", "Salsa", "Cumbia", "Electrónica",
    "Jazz", "Clásica", "Metal", "Indie", "R&B", "Country", "Folk", "Blues",
    "Reggae", "Latino", "Baladas", "Bachata", "Vallenato",
]

# Límites de validación (CWE-20, CWE-770)
MAX_LEN = {"title": 150, "artist": 150, "album": 150, "genre": 60}
PER_PAGE = 20
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,40}$")
PASSWORD_MIN, PASSWORD_MAX = 10, 128
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
MIN_DATE = date(1900, 1, 1)
MAX_PAGE = 10_000
MAX_ID = 2_147_483_647  # evita desbordar el INTEGER de la base de datos (CWE-190)

# Contraseñas comunes (se comparan sin mayúsculas y sin dígitos/símbolos finales).
_COMMON_BASES = {
    "password", "contraseña", "contrasena", "passw0rd", "p@ssw0rd", "qwerty", "qwertyuiop",
    "qwertyuiopasdfghjkl", "asdfghjkl", "zxcvbnm", "iloveyou", "teamo", "tequiero", "admin",
    "administrator", "welcome", "bienvenido", "letmein", "monkey", "dragon", "football",
    "futbol", "baseball", "master", "login", "secret", "secreto", "princess", "sunshine",
    "shadow", "superman", "batman", "michael", "charlie", "jennifer", "football", "abc",
    "abcdefghij", "changeme", "cambiame", "default", "guest", "root", "usuario", "user",
    "music", "musica", "musicmanager", "canciones", "spotify", "freedom", "whatever",
    "trustno", "hello", "holamundo", "hola", "mypassword", "micontraseña", "micontrasena",
    "computer", "internet", "starwars", "pokemon", "minecraft", "liverpool", "barcelona",
    "realmadrid", "colombia", "ecuador", "mexico", "america",
}
_SEQUENCES = (
    "01234567890", "09876543210", "qwertyuiopasdfghjklzxcvbnm", "mnbvcxzlkjhgfdsapoiuytrewq",
    "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba",
)


def password_problem(password, username=""):
    """Devuelve un texto si la contraseña es predecible, o None si es aceptable (CWE-521)."""
    low = password.lower()
    flat = re.sub(r"[\W_]+", "", low)
    base = re.sub(r"[\d\W_]+$", "", low)
    if len(set(low)) < 5:
        return "usa muy pocos caracteres distintos"
    if re.fullmatch(r"(.+?)\1+", low):
        return "es un patrón repetido"
    if any(len(x) >= 6 and x in seq for x in (flat, base) for seq in _SEQUENCES):
        return "es una secuencia (numérica, de teclado o alfabética)"
    if base in _COMMON_BASES or flat in _COMMON_BASES:
        return "es una contraseña muy común"
    if len(username) >= 4 and username in low:
        return "contiene el nombre de usuario"
    return None

CSP = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": ["'self'", "data:"],
    "font-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
    "frame-ancestors": "'none'",
}
PERMISSIONS_POLICY = {
    "camera": "()", "microphone": "()", "geolocation": "()",
    "payment": "()", "usb": "()", "browsing-topics": "()",
}


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    # Se rota al cerrar sesión: invalida cualquier cookie anterior (CWE-613).
    session_token = db.Column(db.String(32), nullable=False, default=lambda: secrets.token_hex(16))

    def get_id(self):
        return f"{self.id}:{self.session_token}"


class Song(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(150), nullable=False)
    artist = db.Column(db.String(150), nullable=False)
    album = db.Column(db.String(150), nullable=True)
    genre = db.Column(db.String(60), nullable=False)
    listened_on = db.Column(db.Date, nullable=False, default=date.today)


# Hash falso para igualar el tiempo de respuesta cuando el usuario no existe
# (evita enumeración de usuarios por tiempo, CWE-204).
_DUMMY_HASH = generate_password_hash("contraseña-ficticia-para-igualar-tiempos")


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def is_production():
    return os.environ.get("APP_ENV", "development").strip().lower() == "production"


def _log_safe(value, limit=40):
    """Neutraliza caracteres de control para evitar inyección en logs (CWE-117)."""
    return re.sub(r"[^\w.\-@]", "?", str(value))[:limit]


def is_safe_next(target):
    """Solo se permiten redirecciones internas (evita open redirect, CWE-601)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return False
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc


def escape_like(text):
    """Escapa los comodines % y _ para que la búsqueda sea literal."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def create_app(test_config=None):
    app = Flask(__name__)
    prod = is_production()

    # --- Configuración desde el entorno (CWE-798) ---
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        if prod:
            raise RuntimeError(
                "SECRET_KEY es obligatoria en producción. "
                "Genera una con: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        # Desarrollo: clave aleatoria por ejecución (las sesiones se pierden al reiniciar).
        secret = secrets.token_hex(32)
        logging.getLogger(__name__).warning(
            "SECRET_KEY no definida: usando una clave temporal solo para desarrollo."
        )

    allowed_hosts = [
        h.strip() for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()
    ]

    app.config.update(
        SECRET_KEY=secret,
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///music.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=16 * 1024,
        MAX_FORM_MEMORY_SIZE=16 * 1024,
        TRUSTED_HOSTS=allowed_hosts,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=prod,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_STORAGE_URI=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
        ALLOW_REGISTRATION=os.environ.get("ALLOW_REGISTRATION", "1") != "0",
        REGISTRATION_CODE=os.environ.get("REGISTRATION_CODE", ""),
        IDLE_TIMEOUT_SECONDS=int(os.environ.get("IDLE_TIMEOUT_MINUTES", "30")) * 60,
    )
    if test_config:
        app.config.update(test_config)
    if prod and app.config["ALLOW_REGISTRATION"] and not app.config["REGISTRATION_CODE"]:
        logging.getLogger(__name__).warning(
            "Registro abierto sin REGISTRATION_CODE: cualquiera puede crear cuentas y "
            "enumerar nombres de usuario. Define REGISTRATION_CODE o ALLOW_REGISTRATION=0."
        )

    # Detrás de un proxy inverso (nginx, Caddy): indica cuántos proxies confiar.
    proxies = int(os.environ.get("TRUSTED_PROXY_COUNT", "0") or 0)
    if proxies:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies, x_host=proxies)

    # --- Registro de eventos (CWE-778) ---
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
    app.logger.setLevel(logging.INFO)

    # --- Extensiones y cabeceras de seguridad ---
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = "Inicia sesión para continuar."
    login_manager.login_message_category = "error"
    login_manager.session_protection = "strong"

    Talisman(
        app,
        force_https=prod,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        session_cookie_secure=prod,
        content_security_policy=CSP,
        frame_options="DENY",
        referrer_policy="same-origin",
        permissions_policy=PERMISSIONS_POLICY,
    )

    @app.after_request
    def extra_headers(resp):
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"  # páginas con datos del usuario
        return resp

    def audit(event, **extra):
        uid = current_user.id if current_user and current_user.is_authenticated else "-"
        detail = " ".join(f"{k}={_log_safe(v)}" for k, v in extra.items())
        app.logger.info("AUDIT %s user=%s ip=%s %s", event, uid, request.remote_addr, detail)

    def user_tag(username):
        """Etiqueta no reversible para correlacionar intentos sin registrar lo tecleado (CWE-532)."""
        key = app.config["SECRET_KEY"].encode()
        return hmac.new(key, username.encode(), hashlib.sha256).hexdigest()[:10]

    with app.app_context():
        db.create_all()
        try:  # el directorio de datos solo para el dueño
            if os.path.isdir(app.instance_path):
                os.chmod(app.instance_path, 0o700)
        except OSError:
            pass
        # El archivo SQLite solo debe ser legible por el dueño (mejor esfuerzo).
        try:
            path = db.engine.url.database
            if path and os.path.exists(path):
                os.chmod(path, 0o600)
        except OSError:
            pass

    @login_manager.user_loader
    def load_user(user_id):
        uid, _, token = str(user_id).partition(":")
        try:
            user = db.session.get(User, int(uid))
        except (TypeError, ValueError, OverflowError):
            return None
        if user is None or not token or not hmac.compare_digest(user.session_token, token):
            return None  # cookie antigua o revocada
        return user

    @app.before_request
    def enforce_idle_timeout():
        """Cierra la sesión tras un periodo de inactividad (CWE-613)."""
        if request.endpoint in (None, "static") or not current_user.is_authenticated:
            return None
        now = int(time.time())
        if now - session.get("last_seen", now) > app.config["IDLE_TIMEOUT_SECONDS"]:
            audit("session_idle_timeout")
            logout_user()
            session.clear()
            flash("Tu sesión expiró por inactividad.", "error")
            return redirect(url_for("login"))
        session["last_seen"] = now
        return None

    # -----------------------------------------------------------------------
    # Validación
    # -----------------------------------------------------------------------
    def read_form():
        """Lee y valida el formulario en el servidor. Devuelve (datos, errores)."""
        data = {
            name: request.form.get(name, "").strip()
            for name in ("title", "artist", "album", "genre", "listened_on")
        }
        labels = {"title": "El título", "artist": "El artista", "album": "El álbum", "genre": "El género"}
        errors = []
        if not data["title"]:
            errors.append("Escribe el título de la canción.")
        if not data["artist"]:
            errors.append("Escribe el nombre del artista.")
        if not data["genre"]:
            errors.append("Indica el género musical.")
        for name, limit in MAX_LEN.items():
            if len(data[name]) > limit:
                errors.append(f"{labels[name]} no puede superar {limit} caracteres.")
            if CONTROL_CHARS.search(data[name]):
                errors.append(f"{labels[name]} contiene caracteres no permitidos.")
        try:
            listened = datetime.strptime(data["listened_on"], "%Y-%m-%d").date()
            if not (MIN_DATE <= listened <= date.today() + timedelta(days=1)):
                raise ValueError
            data["listened_date"] = listened
        except ValueError:
            data["listened_date"] = None
            errors.append("Elige una fecha de escucha válida.")
        return data, errors

    def user_songs():
        return Song.query.filter_by(user_id=current_user.id)

    def user_genres():
        rows = (
            db.session.query(Song.genre)
            .filter(Song.user_id == current_user.id)
            .distinct().order_by(Song.genre).all()
        )
        return [r[0] for r in rows]

    def genre_options():
        return sorted(set(COMMON_GENRES) | set(user_genres()))

    # -----------------------------------------------------------------------
    # Autenticación
    # -----------------------------------------------------------------------
    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per hour", methods=["POST"])
    def register():
        if not app.config["ALLOW_REGISTRATION"]:
            abort(404)
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        form = {"username": ""}
        invite_required = bool(app.config["REGISTRATION_CODE"])
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            form["username"] = username
            if invite_required:
                supplied = request.form.get("invite", "").encode()
                if not hmac.compare_digest(supplied, app.config["REGISTRATION_CODE"].encode()):
                    audit("register_bad_code")
                    flash("Código de invitación incorrecto.", "error")  # antes de revelar si el usuario existe
                    return render_template("register.html", form=form, pw_min=PASSWORD_MIN, invite_required=True)
            errors = []
            if not USERNAME_RE.match(username):
                errors.append("El usuario debe tener 3 a 40 caracteres: letras, números, punto, guion o guion bajo.")
            if not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
                errors.append(f"La contraseña debe tener entre {PASSWORD_MIN} y {PASSWORD_MAX} caracteres.")
            else:
                problem = password_problem(password, username)
                if problem:
                    errors.append(f"La contraseña {problem}. Usa una frase larga de palabras poco relacionadas.")
            if password != confirm:
                errors.append("Las contraseñas no coinciden.")
            if not errors:
                user = User(username=username, password_hash=generate_password_hash(password))
                db.session.add(user)
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    errors.append("Ese nombre de usuario no está disponible.")
                else:
                    session.clear()
                    login_user(user)
                    session["last_seen"] = int(time.time())
                    audit("register_ok")
                    flash("Cuenta creada. ¡Bienvenido!", "ok")
                    return redirect(url_for("index"))
            for e in errors:
                flash(e, "error")
        return render_template("register.html", form=form, pw_min=PASSWORD_MIN, invite_required=invite_required)

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute; 30 per hour", methods=["POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        form = {"username": ""}
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()[:40]
            password = request.form.get("password", "")
            form["username"] = username
            user = User.query.filter_by(username=username).first() if username else None
            valid_len = 0 < len(password) <= PASSWORD_MAX  # evita hashear entradas enormes
            ok = check_password_hash(user.password_hash if user else _DUMMY_HASH, password if valid_len else "")
            if user and ok and valid_len:
                session.clear()  # evita fijación de sesión (CWE-384)
                login_user(user)
                session.permanent = True
                session["last_seen"] = int(time.time())
                audit("login_ok")
                nxt = request.args.get("next")
                return redirect(nxt if is_safe_next(nxt) else url_for("index"))
            audit("login_fail", tag=user_tag(username))
            flash("Usuario o contraseña incorrectos.", "error")  # mensaje genérico
        return render_template("login.html", form=form, registration=app.config["ALLOW_REGISTRATION"])

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        audit("logout")
        user = current_user._get_current_object()
        user.session_token = secrets.token_hex(16)  # invalida todas las cookies emitidas antes
        db.session.commit()
        logout_user()
        session.clear()
        flash("Sesión cerrada.", "ok")
        return redirect(url_for("login"))

    # -----------------------------------------------------------------------
    # Canciones (todas las rutas exigen sesión y filtran por dueño)
    # -----------------------------------------------------------------------
    @app.route("/")
    @login_required
    def index():
        q = request.args.get("q", "").strip()[:150]
        genre = request.args.get("genre", "").strip()[:60]
        page = min(max(request.args.get("page", 1, type=int) or 1, 1), MAX_PAGE)

        query = user_songs()
        if q:
            like = f"%{escape_like(q)}%"
            query = query.filter(
                or_(Song.title.ilike(like, escape="\\"), Song.artist.ilike(like, escape="\\"))
            )
        if genre:
            query = query.filter(Song.genre == genre)
        pagination = query.order_by(Song.listened_on.desc(), Song.id.desc()).paginate(
            page=page, per_page=PER_PAGE, error_out=False
        )

        count = db.session.query
        uid = current_user.id
        stats = {
            "songs": count(func.count(Song.id)).filter(Song.user_id == uid).scalar() or 0,
            "artists": count(func.count(func.distinct(func.lower(Song.artist))))
            .filter(Song.user_id == uid).scalar() or 0,
            "genres": count(func.count(func.distinct(func.lower(Song.genre))))
            .filter(Song.user_id == uid).scalar() or 0,
        }
        return render_template(
            "index.html", songs=pagination.items, pagination=pagination, stats=stats,
            genres=user_genres(), q=q, selected_genre=genre,
        )

    @app.route("/songs/new", methods=["GET", "POST"])
    @login_required
    def add_song():
        if request.method == "POST":
            data, errors = read_form()
            if not errors:
                song = Song(
                    user_id=current_user.id,
                    title=data["title"], artist=data["artist"],
                    album=data["album"] or None, genre=data["genre"],
                    listened_on=data["listened_date"],
                )
                db.session.add(song)
                db.session.commit()
                audit("song_create", song=song.id)
                flash("Canción guardada.", "ok")  # sin datos del usuario en la cookie
                return redirect(url_for("index"))
            for e in errors:
                flash(e, "error")
            form = data
        else:
            form = {"listened_on": date.today().isoformat()}
        return render_template("form.html", form=form, editing=False, genre_options=genre_options(), max_len=MAX_LEN)

    def get_own_song_or_404(song_id):
        song = user_songs().filter(Song.id == song_id).first()
        if song is None:
            abort(404)  # no revela si el id existe para otro usuario (IDOR, CWE-639)
        return song

    @app.route("/songs/<int(min=1, max=2147483647):song_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_song(song_id):
        song = get_own_song_or_404(song_id)
        if request.method == "POST":
            data, errors = read_form()
            if not errors:
                song.title = data["title"]
                song.artist = data["artist"]
                song.album = data["album"] or None
                song.genre = data["genre"]
                song.listened_on = data["listened_date"]
                db.session.commit()
                audit("song_update", song=song.id)
                flash("Cambios guardados.", "ok")
                return redirect(url_for("index"))
            for e in errors:
                flash(e, "error")
            form = data
        else:
            form = {
                "title": song.title, "artist": song.artist, "album": song.album or "",
                "genre": song.genre, "listened_on": song.listened_on.isoformat(),
            }
        return render_template(
            "form.html", form=form, editing=True, song=song,
            genre_options=genre_options(), max_len=MAX_LEN,
        )

    @app.route("/songs/<int(min=1, max=2147483647):song_id>/delete", methods=["POST"])
    @login_required
    def delete_song(song_id):
        song = get_own_song_or_404(song_id)
        db.session.delete(song)
        db.session.commit()
        audit("song_delete", song=song_id)
        flash("Canción eliminada.", "ok")
        return redirect(url_for("index"))

    # -----------------------------------------------------------------------
    # Páginas de error genéricas (CWE-209)
    # -----------------------------------------------------------------------
    messages = {
        400: ("Solicitud no válida", "La solicitud no se pudo procesar. Recarga la página e inténtalo de nuevo."),
        401: ("Sesión requerida", "Inicia sesión para continuar."),
        403: ("Acceso denegado", "No tienes permiso para ver esta página."),
        404: ("No encontrado", "La página que buscas no existe."),
        405: ("Método no permitido", "Esta acción no está permitida."),
        413: ("Solicitud demasiado grande", "Los datos enviados superan el tamaño permitido."),
        429: ("Demasiadas solicitudes", "Has hecho demasiadas solicitudes. Espera un momento e inténtalo de nuevo."),
        500: ("Error interno", "Ocurrió un error inesperado. Inténtalo más tarde."),
    }

    def render_error(code):
        code = code if code in messages else 500
        title, text = messages[code]
        try:
            return render_template("error.html", code=code, title=title, text=text), code
        except Exception:
            # Sin contexto de URL (p. ej. Host no confiable): respuesta mínima en texto plano.
            return f"{code} {title}", code, {"Content-Type": "text/plain; charset=utf-8"}

    @app.errorhandler(CSRFError)
    def handle_csrf(e):
        audit("csrf_rejected")
        return render_error(400)

    @app.errorhandler(Exception)
    def handle_any(e):
        if isinstance(e, HTTPException):
            if e.code in (301, 302, 303, 307, 308) or e.response is not None:
                return e  # redirecciones y respuestas ya construidas
            return render_error(e.code)
        app.logger.exception("Error no controlado")  # el detalle queda en el log, no en la respuesta
        return render_error(500)

    return app


app = create_app()

if __name__ == "__main__":
    from werkzeug.serving import WSGIRequestHandler

    class _Handler(WSGIRequestHandler):
        def version_string(self):  # el servidor de desarrollo no anuncia versiones (CWE-200)
            return "Music Manager"

    # El depurador de Werkzeug permite ejecutar código: NUNCA en producción.
    debug = os.environ.get("FLASK_DEBUG") == "1" and not is_production()
    app.run(
        host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
        debug=debug, request_handler=_Handler,
    )
