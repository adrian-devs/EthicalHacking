"""Music Manager - administrador personal de música escuchada."""
import os
from datetime import date, datetime

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = "cambia-esta-clave-en-produccion"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "music.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

COMMON_GENRES = [
    "Rock", "Pop", "Hip hop", "Reggaeton", "Salsa", "Cumbia", "Electrónica",
    "Jazz", "Clásica", "Metal", "Indie", "R&B", "Country", "Folk", "Blues",
    "Reggae", "Latino", "Baladas", "Bachata", "Vallenato",
]


class Song(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    artist = db.Column(db.String(150), nullable=False)
    album = db.Column(db.String(150), nullable=True)
    genre = db.Column(db.String(60), nullable=False)
    listened_on = db.Column(db.Date, nullable=False, default=date.today)


# La base de datos se crea automáticamente al iniciar la aplicación.
with app.app_context():
    db.create_all()


def read_form():
    """Lee y valida el formulario. Devuelve (datos, errores)."""
    data = {
        "title": request.form.get("title", "").strip(),
        "artist": request.form.get("artist", "").strip(),
        "album": request.form.get("album", "").strip(),
        "genre": request.form.get("genre", "").strip(),
        "listened_on": request.form.get("listened_on", "").strip(),
    }
    errors = []
    if not data["title"]:
        errors.append("Escribe el título de la canción.")
    if not data["artist"]:
        errors.append("Escribe el nombre del artista.")
    if not data["genre"]:
        errors.append("Indica el género musical.")
    try:
        data["listened_date"] = datetime.strptime(data["listened_on"], "%Y-%m-%d").date()
    except ValueError:
        data["listened_date"] = None
        errors.append("Elige una fecha de escucha válida.")
    return data, errors


def existing_genres():
    rows = db.session.query(Song.genre).distinct().order_by(Song.genre).all()
    return [r[0] for r in rows]


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    genre = request.args.get("genre", "").strip()

    query = Song.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Song.title.ilike(like), Song.artist.ilike(like)))
    if genre:
        query = query.filter(Song.genre == genre)
    songs = query.order_by(Song.listened_on.desc(), Song.id.desc()).all()

    stats = {
        "songs": db.session.query(func.count(Song.id)).scalar() or 0,
        "artists": db.session.query(func.count(func.distinct(func.lower(Song.artist)))).scalar() or 0,
        "genres": db.session.query(func.count(func.distinct(func.lower(Song.genre)))).scalar() or 0,
    }
    return render_template(
        "index.html",
        songs=songs,
        stats=stats,
        genres=existing_genres(),
        q=q,
        selected_genre=genre,
    )


@app.route("/songs/new", methods=["GET", "POST"])
def add_song():
    if request.method == "POST":
        data, errors = read_form()
        if not errors:
            song = Song(
                title=data["title"],
                artist=data["artist"],
                album=data["album"] or None,
                genre=data["genre"],
                listened_on=data["listened_date"],
            )
            db.session.add(song)
            db.session.commit()
            flash(f"Canción guardada: {song.title}.", "ok")
            return redirect(url_for("index"))
        for e in errors:
            flash(e, "error")
        form = data
    else:
        form = {"listened_on": date.today().isoformat()}
    return render_template(
        "form.html", form=form, editing=False,
        genre_options=sorted(set(COMMON_GENRES) | set(existing_genres())),
    )


@app.route("/songs/<int:song_id>/edit", methods=["GET", "POST"])
def edit_song(song_id):
    song = db.get_or_404(Song, song_id)
    if request.method == "POST":
        data, errors = read_form()
        if not errors:
            song.title = data["title"]
            song.artist = data["artist"]
            song.album = data["album"] or None
            song.genre = data["genre"]
            song.listened_on = data["listened_date"]
            db.session.commit()
            flash(f"Cambios guardados: {song.title}.", "ok")
            return redirect(url_for("index"))
        for e in errors:
            flash(e, "error")
        form = data
    else:
        form = {
            "title": song.title,
            "artist": song.artist,
            "album": song.album or "",
            "genre": song.genre,
            "listened_on": song.listened_on.isoformat(),
        }
    return render_template(
        "form.html", form=form, editing=True, song=song,
        genre_options=sorted(set(COMMON_GENRES) | set(existing_genres())),
    )


@app.route("/songs/<int:song_id>/delete", methods=["POST"])
def delete_song(song_id):
    song = db.get_or_404(Song, song_id)
    title = song.title
    db.session.delete(song)
    db.session.commit()
    flash(f"Canción eliminada: {title}.", "ok")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
