"""Pruebas de seguridad: verifican que cada hallazgo de la evaluación quedó corregido.

Ejecutar:  pip install pytest && pytest -q
"""
import re

import pytest

import app as music


@pytest.fixture()
def client(tmp_path):
    application = music.create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "WTF_CSRF_ENABLED": False,       # se activa explícitamente en las pruebas de CSRF
        "RATELIMIT_ENABLED": False,      # se activa explícitamente en las pruebas de límites
        "SECRET_KEY": "clave-de-pruebas",
    })
    music.limiter.reset()
    with application.test_client() as c:
        c.application = application
        yield c


def register(c, username="ana", password="una-clave-larga-123"):
    return c.post("/register", data={"username": username, "password": password, "confirm": password})


def add(c, **over):
    data = {"title": "Song", "artist": "Band", "album": "", "genre": "Rock", "listened_on": "2026-11-08"}
    data.update(over)
    return c.post("/songs/new", data=data)


# --- Hallazgo 1: autenticación y autorización (CWE-306, CWE-862, CWE-639) ---
def test_rutas_exigen_login(client):
    for path in ["/", "/songs/new", "/songs/1/edit"]:
        r = client.get(path)
        assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.post("/songs/1/delete").status_code == 302


def test_un_usuario_no_accede_a_datos_de_otro(client):
    register(client, "ana")
    add(client, title="Privada")
    client.post("/logout")
    register(client, "beto", "otra-clave-larga-456")
    assert "Privada" not in client.get("/").get_data(as_text=True)
    assert client.get("/songs/1/edit").status_code == 404
    assert client.post("/songs/1/delete").status_code == 404


def test_login_mensaje_generico_y_sin_open_redirect(client):
    register(client, "ana")
    client.post("/logout")
    r = client.post("/login", data={"username": "ana", "password": "incorrecta-123"})
    assert "Usuario o contraseña incorrectos" in r.get_data(as_text=True)
    r = client.post("/login", data={"username": "noexiste", "password": "incorrecta-123"})
    assert "Usuario o contraseña incorrectos" in r.get_data(as_text=True)
    for evil in ["https://evil.example", "//evil.example", "/\\evil.example"]:
        r = client.post(f"/login?next={evil}", data={"username": "ana", "password": "una-clave-larga-123"})
        assert r.status_code == 302 and "evil.example" not in r.headers["Location"]
        client.post("/logout")


def test_contrasena_debil_rechazada(client):
    r = register(client, "ana", "corta")
    assert r.status_code == 200 and "al menos" not in r.get_data(as_text=True) and "entre 10 y 128" in r.get_data(as_text=True)


# --- Hallazgo 2: debug (CWE-489) ---
def test_sin_consola_de_depuracion(client):
    assert client.get("/console").status_code == 404
    assert client.application.debug is False


# --- Hallazgo 3: CSRF (CWE-352) ---
def test_csrf_obligatorio(tmp_path):
    application = music.create_app({
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'c.db'}",
        "RATELIMIT_ENABLED": False, "SECRET_KEY": "k",
    })
    c = application.test_client()
    assert c.post("/login", data={"username": "a", "password": "b"}).status_code == 400
    page = c.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    r = c.post("/register", data={"csrf_token": token, "username": "ana",
                                  "password": "una-clave-larga-123", "confirm": "una-clave-larga-123"})
    assert r.status_code == 302


# --- Hallazgo 4: secretos (CWE-798) ---
def test_secret_key_no_esta_en_el_codigo(monkeypatch):
    src = open(music.__file__, encoding="utf-8").read()
    assert "cambia-esta-clave" not in src
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        music.create_app({"SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})


# --- Hallazgo 5: validación y límites (CWE-20, CWE-770) ---
def test_validacion_en_servidor(client):
    register(client)
    assert "no puede superar 150" in add(client, title="A" * 151).get_data(as_text=True)
    assert "no permitidos" in add(client, title="a\x00b").get_data(as_text=True)
    assert "fecha" in add(client, listened_on="2999-01-01").get_data(as_text=True)
    assert client.post("/songs/new", data={"title": "A" * 100000}).status_code == 413


def test_paginacion(client):
    register(client)
    for i in range(45):
        add(client, title=f"Cancion {i:02d}")
    html = client.get("/").get_data(as_text=True)
    assert html.count("data-confirm") == music.PER_PAGE and "Página 1 de 3" in html


def test_busqueda_con_comodines_es_literal(client):
    register(client)
    add(client, title="Normal")
    add(client, title="100% Amor")
    html = client.get("/?q=%25").get_data(as_text=True)
    assert "100% Amor" in html and "Normal" not in html


def test_limite_de_intentos_de_login(tmp_path):
    application = music.create_app({
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'r.db'}",
        "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": True, "SECRET_KEY": "k",
    })
    music.limiter.reset()
    c = application.test_client()
    codes = [c.post("/login", data={"username": "x", "password": "y"}).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
    music.limiter.reset()


# --- Hallazgos 6, 8, 11, 12: cabeceras, cookie, host (CWE-693, CWE-1021, CWE-614, CWE-644, CWE-200) ---
def test_cabeceras_de_seguridad(client):
    h = client.get("/login").headers
    for name in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
                 "Referrer-Policy", "Permissions-Policy", "Cache-Control"]:
        assert name in h, name
    assert h["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert "unsafe-inline" not in h["Content-Security-Policy"]
    assert "Werkzeug" not in h.get("Server", "") and "Python" not in h.get("Server", "")


def test_cookie_de_sesion(client):
    r = register(client)
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_flash_no_contiene_datos_del_usuario(client):
    register(client)
    r = add(client, title="TituloSecreto")
    assert "TituloSecreto" not in r.headers.get("Set-Cookie", "")


def test_host_no_confiable_rechazado(client):
    assert client.get("/login", headers={"Host": "evil.example"}).status_code == 400


# --- Hallazgos 13, 16: XSS / JS en línea y errores genéricos (CWE-79, CWE-116, CWE-209) ---
def test_sin_xss_ni_js_en_linea(client):
    register(client)
    add(client, title="<img src=x onerror=alert(1)>")
    html = client.get("/").get_data(as_text=True)
    assert "<img src=x" not in html and "onsubmit" not in html


def test_errores_genericos(client):
    r = client.get("/no-existe")
    assert r.status_code == 404 and "Traceback" not in r.get_data(as_text=True)


# ===================== Versión 3: correcciones de la segunda evaluación =====================

# --- Hallazgo N1: política de contraseñas (CWE-521) ---
@pytest.mark.parametrize("pw", ["1234567890", "aaaaaaaaaa", "password12", "qwertyuiop", "contraseña1", "0987654321"])
def test_contrasenas_predecibles_rechazadas(client, pw):
    assert register(client, "usuario1", pw).status_code == 200


def test_contrasena_con_nombre_de_usuario_rechazada(client):
    assert register(client, "carlos", "carlos-2026-xyz").status_code == 200


def test_frase_larga_aceptada(client):
    assert register(client, "ana", "tres lunas viejas cantan").status_code == 302


# --- Hallazgo N2: sesión revocable y caducidad por inactividad (CWE-613) ---
def test_cookie_vieja_no_sirve_tras_logout(client):
    register(client)
    old = client.get_cookie("session").value
    client.post("/logout")
    other = client.application.test_client()
    other.set_cookie("session", old)
    r = other.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_sesion_caduca_por_inactividad(tmp_path):
    import time
    application = music.create_app({
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'i.db'}",
        "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False, "SECRET_KEY": "k", "IDLE_TIMEOUT_SECONDS": 1,
    })
    c = application.test_client()
    register(c)
    assert c.get("/").status_code == 200
    time.sleep(2.1)
    assert c.get("/").status_code == 302


# --- Hallazgo N3: enteros enormes (CWE-190) ---
def test_enteros_enormes_no_causan_500(client):
    register(client)
    big = "9" * 20
    assert client.get(f"/?page={big}").status_code == 200
    assert client.get(f"/songs/{big}/edit").status_code == 404
    assert client.post(f"/songs/{big}/delete").status_code == 404
    assert client.get("/?page=-5").status_code == 200


# --- Hallazgo N4: registro por invitación (CWE-204) ---
def test_registro_exige_codigo_de_invitacion(tmp_path):
    application = music.create_app({
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'v.db'}",
        "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False, "SECRET_KEY": "k", "REGISTRATION_CODE": "codigo-secreto-1",
    })
    c = application.test_client()
    ok = {"username": "ana", "password": "tres lunas viejas cantan", "confirm": "tres lunas viejas cantan"}
    r = c.post("/register", data={**ok, "invite": "mal"})
    assert r.status_code == 200 and "Código de invitación incorrecto" in r.get_data(as_text=True)
    assert c.post("/register", data={**ok, "invite": "codigo-secreto-1"}).status_code == 302
    c.post("/logout")
    # sin el código no se puede saber si un usuario existe
    r = c.post("/register", data={**ok, "invite": "mal"})
    assert "no está disponible" not in r.get_data(as_text=True)


# --- Hallazgo N5: el log no guarda lo tecleado ni tokens (CWE-532) ---
def test_log_no_contiene_usuario_tecleado_ni_token(client, caplog):
    import logging
    caplog.set_level(logging.INFO)
    client.post("/login", data={"username": "MiClaveSecreta2026", "password": "x"})
    register(client, "ana")
    add(client)
    text = caplog.text.lower()
    assert "miclavesecreta2026" not in text and "login_fail" in text
    with client.application.app_context():
        token = music.User.query.filter_by(username="ana").first().session_token
    assert token not in caplog.text


# --- Permisos del directorio de datos ---
def test_directorio_de_datos_privado():
    import os, stat
    application = music.create_app({
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///_perm_check.db",
        "SECRET_KEY": "k", "RATELIMIT_ENABLED": False,
    })
    inst = application.instance_path
    try:
        assert stat.S_IMODE(os.stat(inst).st_mode) == 0o700
    finally:
        try:
            os.remove(os.path.join(inst, "_perm_check.db"))
            os.rmdir(inst)
        except OSError:
            pass
