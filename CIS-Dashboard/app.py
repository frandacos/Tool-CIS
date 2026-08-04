import csv
import io

from flask import Flask, render_template, request, redirect, url_for, flash

from db import get_connection, init_db

app = Flask(__name__)
app.secret_key = "cisdash-local-dev"  # app local de un solo usuario, no expuesta a internet

STATUS_ORDER = ["Fail", "ManualReviewRequired", "Error", "NotApplicable", "Pass"]
STATUS_COLORS = {
    "Pass": "#2e7d32",
    "Fail": "#c62828",
    "NotApplicable": "#757575",
    "ManualReviewRequired": "#ef6c00",
    "Error": "#6a1b9a",
}
LEVELS = ["Level 1", "Level 2", "Next Generation Windows Security"]
LEVEL_COLORS = {
    "Level 1": "#1565c0",
    "Level 2": "#c62828",
    "Next Generation Windows Security": "#6a1b9a",
    "Sin clasificar": "#9e9e9e",
}
LEVEL_HINTS = {
    "Level 1": "Hardening base, bajo impacto esperado en funcionalidad.",
    "Level 2": "\"Defense in depth\" — el benchmark advierte que puede afectar funcionalidad.",
    "Next Generation Windows Security": "Device Guard / VBS / Credential Guard / LSASS protegido — depende de hardware/firmware.",
    "Sin clasificar": "Control sin nivel asignado en el catálogo importado.",
}
CHAPTER_TITLES = {
    "1": "Account Policies",
    "2": "Local Policies",
    "5": "System Services",
    "9": "Windows Defender Firewall",
    "17": "Advanced Audit Policy Configuration",
    "18": "Administrative Templates (Computer)",
    "19": "Administrative Templates (User)",
}
DECISIONS = ["Pending", "Compliant", "NonCompliant", "RiskAccepted"]
DECISION_COLORS = {
    "Pending": "#ef6c00",
    "Compliant": "#2e7d32",
    "NonCompliant": "#c62828",
    "RiskAccepted": "#1565c0",
}
CRITICALITY_LEVELS = ["Critical", "High", "Medium", "Low"]
CRITICALITY_COLORS = {
    "Critical": "#b71c1c",
    "High": "#c62828",
    "Medium": "#ef6c00",
    "Low": "#2e7d32",
}


# --------------------------------------------------------------------------
# Helpers de datos
# --------------------------------------------------------------------------

def get_clients_with_servers(conn):
    clients = conn.execute("SELECT * FROM client ORDER BY name").fetchall()
    tree = []
    for c in clients:
        servers = conn.execute(
            "SELECT * FROM server WHERE client_id = ? ORDER BY name", (c["id"],)
        ).fetchall()
        tree.append({"client": c, "servers": servers})
    return tree


def latest_run_per_server(conn):
    """Devuelve (corridas_asignadas, corridas_sin_asignar): la ultima corrida
    de cada servidor con client/servidor asociado, y por separado las
    corridas legacy (importadas antes de asignarles un servidor, o todavia
    sin asignar), agrupadas por el hostname crudo del CSV."""
    assigned = conn.execute(
        """
        SELECT ar.*, s.name AS server_name, s.criticality AS criticality, cl.name AS client_name
        FROM audit_run ar
        INNER JOIN server s ON s.id = ar.server_id
        INNER JOIN client cl ON cl.id = s.client_id
        INNER JOIN (
            SELECT server_id, MAX(imported_at) AS max_imported
            FROM audit_run
            WHERE server_id IS NOT NULL
            GROUP BY server_id
        ) latest ON ar.server_id = latest.server_id AND ar.imported_at = latest.max_imported
        ORDER BY cl.name, s.name
        """
    ).fetchall()
    unassigned = conn.execute(
        """
        SELECT ar.*, NULL AS server_name, NULL AS criticality, NULL AS client_name
        FROM audit_run ar
        INNER JOIN (
            SELECT hostname, MAX(imported_at) AS max_imported
            FROM audit_run
            WHERE server_id IS NULL
            GROUP BY hostname
        ) latest ON ar.hostname = latest.hostname AND ar.imported_at = latest.max_imported
        WHERE ar.server_id IS NULL
        ORDER BY ar.hostname
        """
    ).fetchall()
    return list(assigned), list(unassigned)


def group_runs_by_client(assigned_runs):
    groups = {}
    order = []
    for r in assigned_runs:
        key = r["client_name"]
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)
    return [(k, groups[k]) for k in order]


def run_status_counts(conn, run_id):
    rows = conn.execute(
        "SELECT status, COUNT(*) AS n FROM control_result WHERE run_id = ? GROUP BY status",
        (run_id,),
    ).fetchall()
    counts = {s: 0 for s in STATUS_ORDER}
    for row in rows:
        counts[row["status"]] = row["n"]
    counts["Total"] = sum(counts.values())
    return counts


def run_chapter_breakdown(conn, run_id):
    rows = conn.execute(
        """
        SELECT COALESCE(cc.chapter, '?') AS chapter, cr.status, COUNT(*) AS n
        FROM control_result cr
        LEFT JOIN control_catalog cc ON cc.control_id = cr.control_id
        WHERE cr.run_id = ?
        GROUP BY chapter, cr.status
        """,
        (run_id,),
    ).fetchall()

    def chapter_sort_key(ch):
        try:
            return (0, [int(p) for p in ch.split(".")])
        except ValueError:
            return (1, [ch])

    chapters = {}
    for row in rows:
        chapters.setdefault(row["chapter"], {s: 0 for s in STATUS_ORDER})
        chapters[row["chapter"]][row["status"]] = row["n"]
    return sorted(chapters.items(), key=lambda kv: chapter_sort_key(kv[0]))


def run_level_breakdown(conn, run_id):
    rows = conn.execute(
        """
        SELECT COALESCE(cc.level, 'Sin clasificar') AS level, cr.status, COUNT(*) AS n
        FROM control_result cr
        LEFT JOIN control_catalog cc ON cc.control_id = cr.control_id
        WHERE cr.run_id = ?
        GROUP BY level, cr.status
        """,
        (run_id,),
    ).fetchall()

    order = LEVELS + ["Sin clasificar"]
    levels = {}
    for row in rows:
        levels.setdefault(row["level"], {s: 0 for s in STATUS_ORDER})
        levels[row["level"]][row["status"]] = row["n"]
    return sorted(levels.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)


def manual_review_decision_map(conn, server_id):
    if not server_id:
        return {}
    rows = conn.execute(
        "SELECT * FROM manual_review WHERE server_id = ?", (server_id,)
    ).fetchall()
    # dict(row), no el sqlite3.Row crudo: Row soporta indexado (row["x"]) pero
    # no .get(), y el resto del codigo llama reviews.get(id, {}).get("decision", ...).
    return {row["control_id"]: dict(row) for row in rows}


def chapter_sort_key(ch):
    try:
        return [int(p) for p in ch.split(".")]
    except ValueError:
        return [999]


# --------------------------------------------------------------------------
# Dashboard & Helpers Jerárquicos
# --------------------------------------------------------------------------

def get_clients_dashboard_overview(conn):
    """Obtiene el resumen ejecutivo de todos los clientes con métricas acumuladas de sus servidores."""
    clients = conn.execute("SELECT * FROM client ORDER BY name").fetchall()
    overview = []
    
    for c in clients:
        servers = conn.execute("SELECT * FROM server WHERE client_id = ? ORDER BY name", (c["id"],)).fetchall()
        server_list = []
        total_fail = 0
        total_pass = 0
        total_manual = 0
        total_controls = 0
        
        for s in servers:
            last_run = conn.execute(
                "SELECT * FROM audit_run WHERE server_id = ? ORDER BY imported_at DESC LIMIT 1",
                (s["id"],)
            ).fetchone()
            
            counts = run_status_counts(conn, last_run["id"]) if last_run else {st: 0 for st in STATUS_ORDER + ["Total"]}
            total_fail += counts.get("Fail", 0)
            total_pass += counts.get("Pass", 0)
            total_manual += counts.get("ManualReviewRequired", 0)
            total_controls += counts.get("Total", 0)
            
            server_list.append({
                "server": s,
                "last_run": last_run,
                "counts": counts
            })
            
        health_score = int((total_pass / total_controls * 100)) if total_controls > 0 else 0
        overview.append({
            "client": c,
            "servers": server_list,
            "n_servers": len(servers),
            "total_fail": total_fail,
            "total_pass": total_pass,
            "total_manual": total_manual,
            "total_controls": total_controls,
            "health_score": health_score
        })
    return overview


@app.route("/")
def dashboard():
    conn = get_connection()
    assigned_runs, unassigned_runs = latest_run_per_server(conn)
    all_runs = assigned_runs + unassigned_runs
    catalog_count = conn.execute("SELECT COUNT(*) AS n FROM control_catalog").fetchone()["n"]

    clients_overview = get_clients_dashboard_overview(conn)
    
    total_clients = len(clients_overview)
    total_servers = sum(c["n_servers"] for c in clients_overview)
    global_fails = sum(c["total_fail"] for c in clients_overview)
    global_passes = sum(c["total_pass"] for c in clients_overview)
    global_controls = sum(c["total_controls"] for c in clients_overview)
    global_health = int((global_passes / global_controls * 100)) if global_controls > 0 else 0

    run_id = request.args.get("run_id", type=int)
    selected_run = None
    if run_id:
        selected_run = conn.execute("SELECT * FROM audit_run WHERE id = ?", (run_id,)).fetchone()
    if selected_run is None and all_runs:
        selected_run = all_runs[0]

    counts = {}
    chapters = []
    levels = []
    fail_controls = []
    manual_pending = 0
    if selected_run:
        counts = run_status_counts(conn, selected_run["id"])
        chapters = run_chapter_breakdown(conn, selected_run["id"])
        levels = run_level_breakdown(conn, selected_run["id"])
        fail_controls = conn.execute(
            """
            SELECT cr.control_id, cr.title, cr.expected_value, cr.actual_value,
                   COALESCE(cc.chapter, '?') AS chapter, cc.level AS level
            FROM control_result cr
            LEFT JOIN control_catalog cc ON cc.control_id = cr.control_id
            WHERE cr.run_id = ? AND cr.status = 'Fail'
            ORDER BY cr.control_id
            """,
            (selected_run["id"],),
        ).fetchall()

        if selected_run["server_id"]:
            reviews = manual_review_decision_map(conn, selected_run["server_id"])
            manual_ids = conn.execute(
                "SELECT control_id FROM control_result WHERE run_id = ? AND status = 'ManualReviewRequired'",
                (selected_run["id"],),
            ).fetchall()
            manual_pending = sum(
                1 for r in manual_ids
                if reviews.get(r["control_id"], {}).get("decision", "Pending") == "Pending"
            )

    grouped_runs = group_runs_by_client(assigned_runs)

    conn.close()
    return render_template(
        "dashboard.html",
        clients_overview=clients_overview,
        total_clients=total_clients,
        total_servers=total_servers,
        global_fails=global_fails,
        global_passes=global_passes,
        global_health=global_health,
        grouped_runs=grouped_runs,
        unassigned_runs=unassigned_runs,
        selected_run=selected_run,
        counts=counts,
        chapters=chapters,
        levels=levels,
        fail_controls=fail_controls,
        manual_pending=manual_pending,
        status_colors=STATUS_COLORS,
        chapter_titles=CHAPTER_TITLES,
        level_colors=LEVEL_COLORS,
        level_hints=LEVEL_HINTS,
        catalog_count=catalog_count,
    )


# --------------------------------------------------------------------------
# Clientes y servidores
# --------------------------------------------------------------------------

@app.route("/clients", methods=["GET", "POST"])
def clients_list():
    conn = get_connection()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name:
            flash("El cliente necesita un nombre.", "error")
        else:
            conn.execute(
                "INSERT INTO client (name, description) VALUES (?, ?)",
                (name, description or None),
            )
            conn.commit()
            flash(f"Cliente '{name}' creado.", "success")
        conn.close()
        return redirect(url_for("clients_list"))

    clients = conn.execute(
        """
        SELECT c.*, (SELECT COUNT(*) FROM server WHERE client_id = c.id) AS n_servers
        FROM client c
        ORDER BY c.name
        """
    ).fetchall()
    conn.close()
    return render_template("clients.html", clients=clients)


@app.route("/clients/<int:client_id>", methods=["GET", "POST"])
def client_detail(client_id):
    conn = get_connection()
    client = conn.execute("SELECT * FROM client WHERE id = ?", (client_id,)).fetchone()
    if client is None:
        conn.close()
        flash("No se encontro ese cliente.", "error")
        return redirect(url_for("clients_list"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        hostname = request.form.get("hostname", "").strip()
        criticality = request.form.get("criticality", "Medium")
        description = request.form.get("description", "").strip()
        if not name:
            flash("El servidor necesita un nombre.", "error")
        else:
            if criticality not in CRITICALITY_LEVELS:
                criticality = "Medium"
            conn.execute(
                """
                INSERT INTO server (client_id, name, hostname, criticality, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (client_id, name, hostname or None, criticality, description or None),
            )
            conn.commit()
            flash(f"Servidor '{name}' agregado.", "success")
        conn.close()
        return redirect(url_for("client_detail", client_id=client_id))

    servers = conn.execute(
        "SELECT * FROM server WHERE client_id = ? ORDER BY name", (client_id,)
    ).fetchall()

    server_summaries = {}
    for s in servers:
        last_run = conn.execute(
            "SELECT * FROM audit_run WHERE server_id = ? ORDER BY imported_at DESC LIMIT 1",
            (s["id"],),
        ).fetchone()
        if last_run:
            server_summaries[s["id"]] = {
                "run": last_run,
                "counts": run_status_counts(conn, last_run["id"]),
            }

    conn.close()
    return render_template(
        "client_detail.html",
        client=client,
        servers=servers,
        server_summaries=server_summaries,
        criticality_levels=CRITICALITY_LEVELS,
        criticality_colors=CRITICALITY_COLORS,
        status_colors=STATUS_COLORS,
    )

@app.route("/clients/<int:client_id>/edit", methods=["POST"])
def edit_client(client_id):
    conn = get_connection()
    client = conn.execute("SELECT * FROM client WHERE id = ?", (client_id,)).fetchone()
    if client is None:
        conn.close()
        flash("No se encontró ese cliente.", "error")
        return redirect(url_for("clients_list"))

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name:
        flash("El cliente necesita un nombre.", "error")
    else:
        conn.execute(
            "UPDATE client SET name = ?, description = ? WHERE id = ?",
            (name, description or None, client_id),
        )
        conn.commit()
        flash(f"Cliente '{name}' actualizado correctamente.", "success")
    conn.close()
    return redirect(request.referrer or url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
def delete_client(client_id):
    conn = get_connection()
    client = conn.execute("SELECT * FROM client WHERE id = ?", (client_id,)).fetchone()
    if client is None:
        conn.close()
        flash("No se encontró ese cliente.", "error")
        return redirect(url_for("clients_list"))

    conn.execute("DELETE FROM client WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    flash(f"Cliente '{client['name']}' y sus servidores asociados fueron eliminados.", "success")
    return redirect(url_for("clients_list"))


@app.route("/servers/<int:server_id>/edit", methods=["POST"])
def edit_server(server_id):
    conn = get_connection()
    server = conn.execute("SELECT * FROM server WHERE id = ?", (server_id,)).fetchone()
    if server is None:
        conn.close()
        flash("No se encontró ese servidor.", "error")
        return redirect(url_for("clients_list"))

    name = request.form.get("name", "").strip()
    hostname = request.form.get("hostname", "").strip()
    criticality = request.form.get("criticality", "Medium")
    description = request.form.get("description", "").strip()

    if not name:
        flash("El servidor necesita un nombre.", "error")
    else:
        if criticality not in CRITICALITY_LEVELS:
            criticality = "Medium"
        conn.execute(
            """
            UPDATE server
            SET name = ?, hostname = ?, criticality = ?, description = ?
            WHERE id = ?
            """,
            (name, hostname or None, criticality, description or None, server_id),
        )
        conn.commit()
        flash(f"Servidor '{name}' actualizado.", "success")
    conn.close()
    return redirect(request.referrer or url_for("server_detail", server_id=server_id))


@app.route("/servers/<int:server_id>/delete", methods=["POST"])
def delete_server(server_id):
    conn = get_connection()
    server = conn.execute("SELECT * FROM server WHERE id = ?", (server_id,)).fetchone()
    if server is None:
        conn.close()
        flash("No se encontró ese servidor.", "error")
        return redirect(url_for("clients_list"))

    client_id = server["client_id"]
    conn.execute("DELETE FROM server WHERE id = ?", (server_id,))
    conn.commit()
    conn.close()
    flash(f"Servidor '{server['name']}' eliminado.", "success")
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/servers/<int:server_id>")
def server_detail(server_id):
    conn = get_connection()
    server = conn.execute(
        """
        SELECT s.*, c.name AS client_name
        FROM server s INNER JOIN client c ON c.id = s.client_id
        WHERE s.id = ?
        """,
        (server_id,),
    ).fetchone()
    if server is None:
        conn.close()
        flash("No se encontro ese servidor.", "error")
        return redirect(url_for("clients_list"))

    runs = conn.execute(
        """
        SELECT ar.*,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id) AS total,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id AND status = 'Fail') AS n_fail,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id AND status = 'Pass') AS n_pass,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id AND status = 'ManualReviewRequired') AS n_manual
        FROM audit_run ar
        WHERE ar.server_id = ?
        ORDER BY ar.imported_at DESC
        """,
        (server_id,),
    ).fetchall()

    latest_run = runs[0] if runs else None
    counts = {}
    chapters = []
    levels = []
    fail_controls = []
    manual_reviews = []
    
    if latest_run:
        counts = run_status_counts(conn, latest_run["id"])
        chapters = run_chapter_breakdown(conn, latest_run["id"])
        levels = run_level_breakdown(conn, latest_run["id"])
        fail_controls = conn.execute(
            """
            SELECT cr.control_id, cr.title, cr.expected_value, cr.actual_value,
                   COALESCE(cc.chapter, '?') AS chapter, cc.level AS level,
                   cc.remediation_hint AS remediation_hint,
                   cc.manual_remediation AS manual_remediation
            FROM control_result cr
            LEFT JOIN control_catalog cc ON cc.control_id = cr.control_id
            WHERE cr.run_id = ? AND cr.status = 'Fail'
            ORDER BY cr.control_id
            """,
            (latest_run["id"],),
        ).fetchall()

    reviews_map = manual_review_decision_map(conn, server_id)

    conn.close()
    return render_template(
        "server_detail.html",
        server=server,
        runs=runs,
        latest_run=latest_run,
        counts=counts,
        chapters=chapters,
        levels=levels,
        fail_controls=fail_controls,
        reviews_map=reviews_map,
        criticality_colors=CRITICALITY_COLORS,
        status_colors=STATUS_COLORS,
        chapter_titles=CHAPTER_TITLES,
    )


# --------------------------------------------------------------------------
# Runs
# --------------------------------------------------------------------------

@app.route("/runs")
def runs_list():
    conn = get_connection()
    runs = conn.execute(
        """
        SELECT ar.*, s.name AS server_name, cl.name AS client_name,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id) AS total,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id AND status = 'Fail') AS n_fail,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id AND status = 'Pass') AS n_pass,
               (SELECT COUNT(*) FROM control_result WHERE run_id = ar.id AND status = 'ManualReviewRequired') AS n_manual
        FROM audit_run ar
        LEFT JOIN server s ON s.id = ar.server_id
        LEFT JOIN client cl ON cl.id = s.client_id
        ORDER BY ar.imported_at DESC
        """
    ).fetchall()
    conn.close()
    return render_template("runs.html", runs=runs)


@app.route("/runs/<int:run_id>")
def run_detail(run_id):
    conn = get_connection()
    run = conn.execute(
        """
        SELECT ar.*, s.name AS server_name, cl.name AS client_name, cl.id AS client_id
        FROM audit_run ar
        LEFT JOIN server s ON s.id = ar.server_id
        LEFT JOIN client cl ON cl.id = s.client_id
        WHERE ar.id = ?
        """,
        (run_id,),
    ).fetchone()
    if run is None:
        conn.close()
        flash("No se encontro esa corrida.", "error")
        return redirect(url_for("runs_list"))

    status_filter = request.args.get("status", "")
    chapter_filter = request.args.get("chapter", "")
    level_filter = request.args.get("level", "")
    search = request.args.get("q", "").strip()

    query = """
        SELECT cr.*, COALESCE(cc.chapter, '?') AS chapter, cc.level AS level,
               cc.remediation_hint AS remediation_hint,
               cc.manual_remediation AS manual_remediation
        FROM control_result cr
        LEFT JOIN control_catalog cc ON cc.control_id = cr.control_id
        WHERE cr.run_id = ?
    """
    params = [run_id]
    if status_filter:
        query += " AND cr.status = ?"
        params.append(status_filter)
    if chapter_filter:
        query += " AND cc.chapter = ?"
        params.append(chapter_filter)
    if level_filter:
        query += " AND cc.level = ?"
        params.append(level_filter)
    if search:
        query += " AND (cr.control_id LIKE ? OR cr.title LIKE ?)"
        params += [f"%{search}%", f"%{search}%"]
    query += " ORDER BY cr.control_id"

    results = conn.execute(query, params).fetchall()
    chapters = [r["chapter"] for r in conn.execute(
        """
        SELECT DISTINCT COALESCE(cc.chapter, '?') AS chapter
        FROM control_result cr
        LEFT JOIN control_catalog cc ON cc.control_id = cr.control_id
        WHERE cr.run_id = ?
        """,
        (run_id,),
    ).fetchall()]
    chapters.sort(key=chapter_sort_key)

    counts = run_status_counts(conn, run_id)
    clients_tree = get_clients_with_servers(conn) if run["server_id"] is None else []
    conn.close()

    return render_template(
        "run_detail.html",
        run=run,
        results=results,
        chapters=chapters,
        counts=counts,
        status_filter=status_filter,
        chapter_filter=chapter_filter,
        level_filter=level_filter,
        levels=LEVELS,
        search=search,
        status_colors=STATUS_COLORS,
        clients_tree=clients_tree,
    )


@app.route("/runs/<int:run_id>/assign-server", methods=["POST"])
def assign_run_server(run_id):
    server_id = request.form.get("server_id", type=int)
    conn = get_connection()
    run = conn.execute("SELECT * FROM audit_run WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        conn.close()
        flash("No se encontro esa corrida.", "error")
        return redirect(url_for("runs_list"))
    if not server_id:
        conn.close()
        flash("Elegi un servidor para asignar esta corrida.", "error")
        return redirect(url_for("run_detail", run_id=run_id))
    conn.execute("UPDATE audit_run SET server_id = ? WHERE id = ?", (server_id, run_id))
    conn.commit()
    conn.close()
    flash("Corrida asignada al servidor.", "success")
    return redirect(url_for("run_detail", run_id=run_id))


@app.route("/runs/<int:run_id>/delete", methods=["POST"])
def delete_run(run_id):
    conn = get_connection()
    run = conn.execute("SELECT * FROM audit_run WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        conn.close()
        flash("No se encontró esa corrida.", "error")
        return redirect(url_for("runs_list"))
    
    server_id = run["server_id"]
    conn.execute("DELETE FROM audit_run WHERE id = ?", (run_id,))
    conn.commit()
    conn.close()
    
    flash("Corrida de auditoría eliminada correctamente.", "success")
    if server_id:
        return redirect(url_for("server_detail", server_id=server_id))
    return redirect(url_for("runs_list"))


# --------------------------------------------------------------------------
# Import
# --------------------------------------------------------------------------

def _sniff_csv_kind(header):
    header_set = {h.strip().lower() for h in header}
    if {"control_id", "status_impl", "chapter"}.issubset(header_set):
        return "catalog"
    if {"controlid", "status", "hostname"}.issubset(header_set):
        return "audit_run"
    if {"control_id", "remediation_hint"}.issubset(header_set) and len(header_set) == 2:
        return "remediation_hints"
    if {"control_id", "manual_remediation"}.issubset(header_set) and len(header_set) == 2:
        return "manual_remediation"
    return None


def _import_catalog(conn, reader):
    n = 0
    for row in reader:
        conn.execute(
            """
            INSERT INTO control_catalog (control_id, title, chapter, profile_scope, level, page)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(control_id) DO UPDATE SET
                title = excluded.title,
                chapter = excluded.chapter,
                profile_scope = excluded.profile_scope,
                level = excluded.level,
                page = excluded.page
            """,
            (row["control_id"], row["title"], row["chapter"], row.get("profile_scope"), row.get("level"), row.get("page")),
        )
        n += 1
    return n


def _import_remediation_hints(conn, reader):
    n = 0
    for row in reader:
        conn.execute(
            "UPDATE control_catalog SET remediation_hint = ? WHERE control_id = ?",
            (row["remediation_hint"], row["control_id"]),
        )
        n += 1
    return n


def _import_manual_remediation(conn, reader):
    n = 0
    for row in reader:
        conn.execute(
            "UPDATE control_catalog SET manual_remediation = ? WHERE control_id = ?",
            (row["manual_remediation"], row["control_id"]),
        )
        n += 1
    return n


def _import_audit_run(conn, reader, filename, label, server_id):
    rows = list(reader)
    if not rows:
        return None, 0
    hostname = rows[0].get("Hostname") or rows[0].get("hostname") or "desconocido"
    cur = conn.execute(
        "INSERT INTO audit_run (server_id, hostname, source_filename, label) VALUES (?, ?, ?, ?)",
        (server_id, hostname, filename, label or None),
    )
    run_id = cur.lastrowid
    for row in rows:
        conn.execute(
            """
            INSERT INTO control_result
                (run_id, control_id, title, status, expected_value, actual_value, notes, result_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                row.get("ControlId"),
                row.get("Title"),
                row.get("Status"),
                row.get("ExpectedValue"),
                row.get("ActualValue"),
                row.get("Notes"),
                row.get("Timestamp"),
            ),
        )
    return run_id, len(rows)


@app.route("/import", methods=["GET", "POST"])
def import_csv():
    conn = get_connection()
    clients_tree = get_clients_with_servers(conn)

    if request.method == "GET":
        conn.close()
        return render_template("import.html", clients_tree=clients_tree)

    file = request.files.get("file")
    label = request.form.get("label", "").strip()
    server_id = request.form.get("server_id", type=int)

    if not file or file.filename == "":
        flash("Elegi un archivo CSV.", "error")
        conn.close()
        return redirect(url_for("import_csv"))

    raw = file.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames:
        flash("El CSV esta vacio o no se pudo leer.", "error")
        conn.close()
        return redirect(url_for("import_csv"))

    kind = _sniff_csv_kind(reader.fieldnames)
    try:
        if kind == "catalog":
            n = _import_catalog(conn, reader)
            conn.commit()
            flash(f"Catálogo importado: {n} controles.", "success")
        elif kind == "remediation_hints":
            n = _import_remediation_hints(conn, reader)
            conn.commit()
            flash(f"Guías de remediación importadas: {n} controles.", "success")
        elif kind == "manual_remediation":
            n = _import_manual_remediation(conn, reader)
            conn.commit()
            flash(f"Procedimientos manuales importados: {n} controles.", "success")
        elif kind == "audit_run":
            if not server_id:
                flash("Para importar una corrida de auditoría elegí a qué servidor pertenece.", "error")
                return redirect(url_for("import_csv"))
            run_id, n = _import_audit_run(conn, reader, file.filename, label, server_id)
            conn.commit()
            flash(f"Corrida importada: {n} resultados.", "success")
            return redirect(url_for("run_detail", run_id=run_id))
        else:
            flash(
                "No reconozco el formato de este CSV. Esperaba las columnas de "
                "cis2025_controls_master.csv (catálogo) o las que exporta "
                "Invoke-CISAudit -OutputPath (corrida de auditoría).",
                "error",
            )
    finally:
        conn.close()

    return redirect(url_for("import_csv"))


# --------------------------------------------------------------------------
# Control detail + Manual Review
# --------------------------------------------------------------------------

@app.route("/controls/<control_id>", methods=["GET", "POST"])
def control_detail(control_id):
    conn = get_connection()
    server_id = request.values.get("server_id", type=int)

    if request.method == "POST":
        if not server_id:
            flash("No se pudo guardar: falta elegir a qué servidor corresponde esta revisión.", "error")
            conn.close()
            return redirect(url_for("control_detail", control_id=control_id))

        decision = request.form.get("decision", "Pending")
        reviewer = request.form.get("reviewer", "").strip()
        evidence_notes = request.form.get("evidence_notes", "").strip()
        if decision not in DECISIONS:
            decision = "Pending"
        conn.execute(
            """
            INSERT INTO manual_review (server_id, control_id, decision, reviewer, evidence_notes, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(server_id, control_id) DO UPDATE SET
                decision = excluded.decision,
                reviewer = excluded.reviewer,
                evidence_notes = excluded.evidence_notes,
                updated_at = datetime('now')
            """,
            (server_id, control_id, decision, reviewer, evidence_notes),
        )
        conn.commit()
        flash("Revisión guardada.", "success")
        conn.close()
        return redirect(url_for("control_detail", control_id=control_id, server_id=server_id))

    catalog = conn.execute(
        "SELECT * FROM control_catalog WHERE control_id = ?", (control_id,)
    ).fetchone()
    history = conn.execute(
        """
        SELECT cr.*, ar.hostname, ar.imported_at, ar.label, ar.server_id
        FROM control_result cr
        INNER JOIN audit_run ar ON ar.id = cr.run_id
        WHERE cr.control_id = ?
        ORDER BY ar.imported_at DESC
        """,
        (control_id,),
    ).fetchall()

    review = None
    server = None
    if server_id:
        review = conn.execute(
            "SELECT * FROM manual_review WHERE server_id = ? AND control_id = ?",
            (server_id, control_id),
        ).fetchone()
        server = conn.execute(
            """
            SELECT s.*, c.name AS client_name
            FROM server s INNER JOIN client c ON c.id = s.client_id
            WHERE s.id = ?
            """,
            (server_id,),
        ).fetchone()

    servers = conn.execute(
        """
        SELECT s.*, c.name AS client_name
        FROM server s INNER JOIN client c ON c.id = s.client_id
        ORDER BY c.name, s.name
        """
    ).fetchall()
    conn.close()

    if catalog is None and not history:
        flash(f"No hay datos para el control {control_id} (importa el catálogo o una corrida primero).", "error")
        return redirect(url_for("dashboard"))

    return render_template(
        "control_detail.html",
        control_id=control_id,
        catalog=catalog,
        history=history,
        review=review,
        server=server,
        server_id=server_id,
        servers=servers,
        decisions=DECISIONS,
        decision_colors=DECISION_COLORS,
        status_colors=STATUS_COLORS,
        level_colors=LEVEL_COLORS,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5057)
