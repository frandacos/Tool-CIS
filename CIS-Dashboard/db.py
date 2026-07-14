import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "cisdash.sqlite3"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"
BACKUP_DIR = Path(__file__).parent / "backups"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _backup_existing_db():
    """Copia cisdash.sqlite3 a backups/ antes de tocar nada. Se corre en
    cada arranque de la app, independientemente de si hay migracion
    pendiente o no -- mas vale una copia de mas que repetir el incidente de
    borrar la base sin backup."""
    if not DB_PATH.exists():
        return
    BACKUP_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(DB_PATH, BACKUP_DIR / f"cisdash_{stamp}.sqlite3")

    # no acumular backups sin limite: dejar los ultimos 20
    backups = sorted(BACKUP_DIR.glob("cisdash_*.sqlite3"))
    for old in backups[:-20]:
        old.unlink()


def _column_exists(conn, table, column):
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]
    return column in cols


def _table_exists(conn, table):
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _migrate(conn):
    """Migraciones aditivas, nunca destructivas. Cada paso se puede correr
    de nuevo sin romper nada (siempre chequea antes de aplicar)."""

    # audit_run.server_id: agregado para poder asociar cada corrida a un
    # servidor de un cliente. Las corridas importadas antes de esto quedan
    # con server_id NULL (se pueden asignar despues desde /runs/<id>).
    if _table_exists(conn, "audit_run") and not _column_exists(conn, "audit_run", "server_id"):
        conn.execute("ALTER TABLE audit_run ADD COLUMN server_id INTEGER REFERENCES server(id)")

    # manual_review paso de PK (control_id) a PK (server_id, control_id).
    # Las decisiones viejas (globales, sin servidor asociado) NO se pierden
    # ni se asignan a un servidor al azar: se preservan tal cual en
    # manual_review_legacy, solo para consulta historica.
    if _table_exists(conn, "manual_review") and not _column_exists(conn, "manual_review", "server_id"):
        conn.execute("ALTER TABLE manual_review RENAME TO manual_review_legacy")

    conn.commit()


def init_db():
    _backup_existing_db()
    conn = get_connection()
    _migrate(conn)
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
