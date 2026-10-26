import os
import json
import time
import hashlib
import sqlite3
import threading
import mimetypes
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "scan_cache.db"
STATIC_DIR = BASE_DIR / "static"


def _load_dotenv():
    """Загружает переменные из .env (если файл есть). Уже заданные не переопределяет."""
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()

DEFAULT_ROOT = os.environ.get("PHOTO_ROOT") or os.path.expanduser("~/Pictures")
CHUNK = 8 * 1024 * 1024
MAX_PAIRS_STORED = 5000

app = FastAPI(title="Foto-razbor")

_state_lock = threading.Lock()
_state = {
    "phase": "idle",
    "progress": None,
    "message": "",
    "file_count": 0,
    "folder_count": 0,
    "last_scan": None,
}


def set_state(phase=None, progress=None, message=None):
    with _state_lock:
        if phase is not None:
            _state["phase"] = phase
        if progress is not None:
            _state["progress"] = progress
        if message is not None:
            _state["message"] = message


def get_state():
    with _state_lock:
        return dict(_state)


def db_connect():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = db_connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS files(
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime INTEGER NOT NULL,
                hash TEXT,
                scan_id INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_files_size ON files(size);
            CREATE TABLE IF NOT EXISTS folders(
                path TEXT PRIMARY KEY,
                parent TEXT,
                scan_id INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS folder_pairs(
                a TEXT, b TEXT, common INTEGER, files_json TEXT, scan_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS folder_stats(path TEXT, count INTEGER, scan_id INTEGER);
            CREATE TABLE IF NOT EXISTS expanded_cache(
                a TEXT, b TEXT, threshold REAL, min_common INTEGER,
                scan_id INTEGER, result_json TEXT,
                PRIMARY KEY(a, b, scan_id, threshold, min_common)
            );
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
            """
        )
        conn.commit()
    finally:
        conn.close()


init_db()


def get_root():
    conn = db_connect()
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='root'").fetchone()
        return row["value"] if row else DEFAULT_ROOT
    finally:
        conn.close()


class RootModel(BaseModel):
    root: str


class OpenFolderModel(BaseModel):
    path: str


@app.post("/api/open-folder")
def api_open_folder(m: OpenFolderModel):
    """Открывает папку в проводнике. Разрешены только пути внутри корня сканирования."""
    p = os.path.abspath(os.path.expandvars(m.path.strip()))
    root_nc = os.path.normcase(get_root())
    p_nc = os.path.normcase(p)
    if not (p_nc == root_nc or p_nc.startswith(root_nc + os.sep)):
        raise HTTPException(400, "Путь вне корня сканирования")
    if not os.path.isdir(p):
        raise HTTPException(404, f"Папка не найдена: {p}")
    if hasattr(os, "startfile"):
        os.startfile(p)  # noqa: S606 — открытие папки в проводнике Windows
    else:
        import subprocess  # noqa: PLC0415 — резерв для не-Windows
        subprocess.Popen(["xdg-open", p])
    return {"opened": True}


def set_root(path):
    p = os.path.abspath(os.path.expandvars(path.strip()))
    if not os.path.isdir(p):
        raise HTTPException(400, f"Папка не найдена: {p}")
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('root',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (p,),
        )
        conn.commit()
    finally:
        conn.close()
    return p


def latest_scan_id():
    conn = db_connect()
    try:
        row = conn.execute("SELECT MAX(scan_id) FROM files").fetchone()
        return row[0] or 0
    finally:
        conn.close()


def _get_meta(key, default=None):
    conn = db_connect()
    try:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def _set_meta(key, value):
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- folder composition

FOLDER_LOGIC_VERSION = "direct-v2"


def rebuild_folder_composition(scan_id):
    """Строит folder_pairs и folder_stats для заданного скана.

    В сравнениях участвуют только папки, где файлы лежат НЕПОСРЕДСТВЕННО:
    состав папки — это файлы прямо в ней; содержимое вложенных папок
    наверх не поднимается, а папки без файлов ни в каком сравнении не участвуют.
    Пары «родитель ↔ вложенная папка» не создаются.
    """
    set_state("folders", 0.0, "Сравнение составов папок...")
    conn = db_connect()
    try:
        file_rows = conn.execute(
            "SELECT path, name, size FROM files WHERE scan_id=?", (scan_id,)
        ).fetchall()
        folder_paths = [
            r["path"] for r in conn.execute("SELECT path FROM folders WHERE scan_id=?", (scan_id,))
        ]
    finally:
        conn.close()

    folder_set = set(folder_paths)
    sets = {}
    for r in file_rows:
        sig = r["name"].lower() + "|" + str(r["size"])
        cur = os.path.dirname(r["path"])
        if cur not in folder_set:
            continue
        s = sets.get(cur)
        if s is None:
            s = sets[cur] = set()
        s.add(sig)

    sig_map = defaultdict(list)
    for f, s in sets.items():
        for sig in s:
            sig_map[sig].append(f)

    common = {}
    for fl in sig_map.values():
        if len(fl) < 2:
            continue
        fl.sort()
        for i in range(len(fl)):
            a = fl[i]
            na = os.path.normcase(a)
            for j in range(i + 1, len(fl)):
                b = fl[j]
                nb = os.path.normcase(b)
                if nb.startswith(na + os.sep) or na.startswith(nb + os.sep):
                    continue  # вложенные папки между собой не сравниваются
                key = (a, b)
                common[key] = common.get(key, 0) + 1

    items = sorted(common.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_PAIRS_STORED]
    pair_rows = []
    for (a, b), c in items:
        shared = sorted(sets[a] & sets[b])[:200]
        pair_rows.append((a, b, c, json.dumps(shared), scan_id))

    conn = db_connect()
    try:
        conn.execute("BEGIN")
        conn.execute("DELETE FROM folder_pairs WHERE scan_id=?", (scan_id,))
        conn.executemany(
            "INSERT INTO folder_pairs(a,b,common,files_json,scan_id) VALUES(?,?,?,?,?)", pair_rows
        )
        conn.execute("DELETE FROM folder_stats WHERE scan_id=?", (scan_id,))
        conn.executemany(
            "INSERT INTO folder_stats(path,count,scan_id) VALUES(?,?,?)",
            [(f, len(s), scan_id) for f, s in sets.items() if s],
        )
        conn.commit()
    finally:
        conn.close()

    set_state("folders", None, f"Состав папок пересчитан: {len(items):,} пар")
    return len(items)


def ensure_folder_composition():
    """При старте пересобирает состав папок, если он был сохранён старой логикой
    (файлы размазывались по всем родительским папкам)."""
    try:
        if _get_meta("folder_logic") == FOLDER_LOGIC_VERSION:
            return
        sid = latest_scan_id()
        if not sid:
            _set_meta("folder_logic", FOLDER_LOGIC_VERSION)
            return
        if get_state()["phase"] in ("scan", "hash", "folders"):
            return  # идёт полный скан — он пересоберёт состав сам
        rebuild_folder_composition(sid)
        set_state("idle", 1.0, "Состав папок пересчитан: кэш соответствует прямой иерархии")
        _set_meta("folder_logic", FOLDER_LOGIC_VERSION)
    except Exception as e:  # noqa: BLE001
        set_state("error", None, f"Ошибка пересчёта состава папок: {e}")


# ---------------------------------------------------------------- scan

# Пересобираем состав папок (см. комментарий в ensure_folder_composition),
# если в кэше данные прежней логики — без полного перескана, из таблицы files.
threading.Thread(target=ensure_folder_composition, daemon=True).start()

def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def run_scan():
    scan_id = int(time.time() * 1000)
    try:
        root = get_root()
        if not os.path.isdir(root):
            set_state("error", None, f"Корневая папка не найдена: {root}")
            return

        # ---- phase 1: walk -------------------------------------------------
        set_state("scan", 0.0, "Обход файловой системы...")
        files = []
        folders = {}
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            parent = os.path.dirname(dirpath) if os.path.normcase(os.path.abspath(dirpath)) != root else None
            folders[dirpath] = parent
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                files.append((p, fn, int(st.st_size), int(st.st_mtime)))

        set_state("scan", 1.0, f"Найдено файлов: {len(files):,}, папок: {len(folders):,}")

        conn = db_connect()
        try:
            conn.execute("BEGIN")
            conn.executemany(
                "INSERT OR REPLACE INTO files(path,name,size,mtime,hash,scan_id) VALUES(?,?,?,?,NULL,?)",
                [(p, n, s, m, scan_id) for (p, n, s, m) in files],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO folders(path,parent,scan_id) VALUES(?,?,?)",
                [(d, par, scan_id) for d, par in folders.items()],
            )
            conn.execute("DELETE FROM files WHERE scan_id != ?", (scan_id,))
            conn.execute("DELETE FROM folders WHERE scan_id != ?", (scan_id,))
            conn.commit()
        finally:
            conn.close()

        # ---- phase 2: hash candidates --------------------------------------
        set_state("hash", 0.0, "Поиск кандидатов по размеру...")
        conn = db_connect()
        try:
            rows = conn.execute(
                """SELECT id, path FROM files WHERE scan_id=? AND size IN (
                       SELECT size FROM files WHERE scan_id=? GROUP BY size HAVING COUNT(*) > 1)""",
                (scan_id, scan_id),
            ).fetchall()
        finally:
            conn.close()

        total = len(rows)
        done = 0
        if total:
            set_state("hash", 0.0, f"Хеширование {total:,} файлов...")
            with ThreadPoolExecutor(max_workers=8) as ex:
                futs = {ex.submit(_sha256_file, r["path"]): r["id"] for r in rows}
                for fut in as_completed(futs):
                    fid = futs[fut]
                    try:
                        h = fut.result()
                    except OSError:
                        continue
                    c = db_connect()
                    try:
                        c.execute("UPDATE files SET hash=? WHERE id=?", (h, fid))
                        c.commit()
                    finally:
                        c.close()
                    done += 1
                    if done % 25 == 0 or done == total:
                        set_state("hash", round(done / total, 4), f"Хеширование: {done:,}/{total:,}")

        # ---- phase 3: folder composition ------------------------------------
        rebuild_folder_composition(scan_id)

        with _state_lock:
            _state["file_count"] = len(files)
            _state["folder_count"] = len(folders)
            _state["last_scan"] = int(time.time())
        set_state("done", 1.0, "Готово")

    except Exception as e:  # noqa: BLE001
        set_state("error", None, f"Ошибка скана: {e}")


# ---------------------------------------------------------------- api

@app.get("/api/status")
def api_status():
    st = get_state()
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) c, MAX(scan_id) ms FROM files WHERE scan_id=(SELECT MAX(scan_id) FROM files)"
        ).fetchone()
        st["db_file_count"] = row["c"]
        # scan_id — это unix-время в мс, по нему восстанавливаем время прошлого скана
        if st.get("last_scan") is None and row["ms"]:
            st["last_scan"] = int(row["ms"] // 1000)
    finally:
        conn.close()
    st["root"] = get_root()
    st["scan_required"] = st["db_file_count"] == 0
    return st


@app.post("/api/scan")
def api_scan():
    if get_state()["phase"] in ("scan", "hash", "folders"):
        raise HTTPException(409, "Скан уже выполняется")
    threading.Thread(target=run_scan, daemon=True).start()
    return {"started": True}


@app.get("/api/config")
def api_config():
    return {"root": get_root()}


@app.post("/api/config")
def api_config_set(m: RootModel):
    return {"root": set_root(m.root)}


def _dup_where(mode, min_size, ext, q):
    where = ["scan_id=?", "size>=?"]
    args = [latest_scan_id(), int(min_size)]
    if mode == "hash":
        where.append("hash IS NOT NULL")
    e = (ext or "").strip().lower().lstrip(".")
    if e:
        where.append("lower(name) LIKE ?")
        args.append("%." + e)
    qq = (q or "").strip().lower()
    if qq:
        where.append("(lower(name) LIKE ? OR lower(path) LIKE ?)")
        args += ["%" + qq, "%" + qq]
    return " AND ".join(where), args


def _dup_groups(mode, min_size, ext, q, limit):
    where, args = _dup_where(mode, min_size, ext, q)
    conn = db_connect()
    try:
        if mode == "hash":
            sql = (
                f"SELECT hash AS key, COUNT(*) c, MIN(size) size FROM files WHERE {where} "
                "GROUP BY hash HAVING COUNT(*)>1 ORDER BY c*size DESC LIMIT ?"
            )
            groups = conn.execute(sql, args + [limit]).fetchall()
        else:
            sql = (
                f"SELECT size, mtime, COUNT(*) c FROM files WHERE {where} "
                "GROUP BY size, mtime HAVING COUNT(*)>1 ORDER BY c*size DESC LIMIT ?"
            )
            groups = conn.execute(sql, args + [limit]).fetchall()

        out = []
        for g in groups:
            if mode == "hash":
                members = conn.execute(
                    "SELECT id,path,name,size,mtime FROM files WHERE scan_id=? AND hash=? ORDER BY path",
                    (args[0], g["key"]),
                ).fetchall()
                key = str(g["key"])
            else:
                members = conn.execute(
                    "SELECT id,path,name,size,mtime FROM files WHERE scan_id=? AND size=? AND mtime=? ORDER BY path",
                    (args[0], g["size"], g["mtime"]),
                ).fetchall()
                key = f"{g['size']}|{g['mtime']}"
            out.append(
                {
                    "key": key,
                    "count": len(members),
                    "size": g["size"] if mode == "hash" else g["size"],
                    "waste": (len(members) - 1) * (g["size"]),
                    "files": [dict(r) for r in members],
                }
            )
        return out
    finally:
        conn.close()


def _dup_totals(mode, min_size, ext, q):
    where, args = _dup_where(mode, min_size, ext, q)
    conn = db_connect()
    try:
        if mode == "hash":
            inner = f"SELECT hash k, MIN(size) size, COUNT(*) c FROM files WHERE {where} GROUP BY hash HAVING COUNT(*)>1"
        else:
            inner = f"SELECT size, mtime, COUNT(*) c FROM files WHERE {where} GROUP BY size, mtime HAVING COUNT(*)>1"
        row = conn.execute(
            f"SELECT COALESCE(SUM((c-1)*size),0) waste, COALESCE(SUM(c),0) files FROM ({inner})",
            args,
        ).fetchone()
        return {"waste": row["waste"], "files": row["files"]}
    finally:
        conn.close()


@app.get("/api/duplicates")
def api_duplicates(mode="hash", min_size=0, ext="", q="", limit=200):
    if mode not in ("hash", "meta"):
        raise HTTPException(400, "mode должен быть hash или meta")
    groups = _dup_groups(mode, min_size, ext, q, int(limit))
    totals = _dup_totals(mode, min_size, ext, q)
    return {"mode": mode, "groups": groups, **totals}


class ExportModel(BaseModel):
    mode: str = "hash"
    min_size: int = 0
    ext: str = ""
    q: str = ""
    keep: list[int] = []


@app.post("/api/export/duplicates")
def api_export_duplicates(m: ExportModel):
    if m.mode not in ("hash", "meta"):
        raise HTTPException(400, "mode должен быть hash или meta")
    groups = _dup_groups(m.mode, m.min_size, m.ext, m.q, 100000)
    keep = set(m.keep)

    def gen():
        yield "\ufeff"
        yield "group_key,mode,file_count,single_size,waste_bytes,keep,path\n"
        for g in groups:
            for f in g["files"]:
                k = 1 if f["id"] in keep else 0
                path = f['path'].replace('"', '""')
                yield f'"{g["key"]}",{m.mode},{g["count"]},{g["size"]},{g["waste"]},{k},"{path}"\n'

    return StreamingResponse(
        gen(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="duplicates.csv"'},
    )


@app.get("/api/folders")
def api_folders(threshold: float = 0.5, min_common: int = 1, limit: int = 300):
    sid = latest_scan_id()
    conn = db_connect()
    try:
        rows = conn.execute(
            """SELECT p.a, p.b, p.common, p.files_json, sa.count ca, sb.count cb
               FROM folder_pairs p
               JOIN folder_stats sa ON sa.path=p.a AND sa.scan_id=p.scan_id
               JOIN folder_stats sb ON sb.path=p.b AND sb.scan_id=p.scan_id
               WHERE p.scan_id=?""",
            (sid,),
        ).fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        mn = min(r["ca"], r["cb"])
        if mn <= 0 or r["common"] < int(min_common):
            continue
        # страховка от устаревших строк кэша: вложенные папки не сравниваются
        na, nb = os.path.normcase(r["a"]), os.path.normcase(r["b"])
        if nb.startswith(na + os.sep) or na.startswith(nb + os.sep):
            continue
        sim = r["common"] / mn
        if not (sim > threshold - 1e-9):
            continue
        out.append(
            {
                "a": r["a"],
                "b": r["b"],
                "similarity": round(sim, 4),
                "common": r["common"],
                "count_a": r["ca"],
                "count_b": r["cb"],
                "only_in_a": r["ca"] - r["common"],
                "only_in_b": r["cb"] - r["common"],
                "files": json.loads(r["files_json"] or "[]"),
            }
        )
    out.sort(key=lambda x: (-x["similarity"], -x["common"]))
    return {"pairs": out[: int(limit)], "total_pairs": len(out)}


@app.get("/api/export/folders")
def api_export_folders(threshold: float = 0.5, min_common: int = 1):
    data = api_folders(threshold=threshold, min_common=min_common, limit=100000)

    def gen():
        yield "\ufeff"
        yield "folder_a,folder_b,similarity_pct,common_files,files_in_a,files_in_b,only_in_a,only_in_b\n"
        for p in data["pairs"]:
            a = p['a'].replace('"', '""')
            b = p['b'].replace('"', '""')
            yield (
                f'"{a}","{b}",{int(round(p["similarity"] * 100))},{p["common"]},'
                f'{p["count_a"]},{p["count_b"]},{p["only_in_a"]},{p["only_in_b"]}\n'
            )

    return StreamingResponse(
        gen(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="similar_folders.csv"'},
    )


class ExpandModel(BaseModel):
    a: str
    b: str
    threshold: float = 0.5
    min_common: int = 1


class DeletePairModel(BaseModel):
    a: str
    b: str
    confirm: bool = False


MAX_EXPAND_GROUPS = 500
MAX_EXPAND_CHIPS = 200


def _inside_root(p, root):
    pn = os.path.normcase(os.path.abspath(p))
    rn = os.path.normcase(os.path.abspath(root))
    return pn == rn or pn.startswith(rn + os.sep)


def _subtree_pair_analysis(pa, pb, threshold, min_common, scan_id):
    """Рекурсивное сравнение двух папок «с учётом всех подпапок».

    Помимо сравнения самих деревьев (pa целиком ↔ pb целиком) собирает
    пары похожих подпапок между двумя деревьями — так на уровень выше
    могут проявиться целые группы схожих папок.
    """
    conn = db_connect()
    try:
        folder_set = {
            r["path"] for r in conn.execute("SELECT path FROM folders WHERE scan_id=?", (scan_id,))
        }
        file_rows = conn.execute(
            "SELECT path, name, size FROM files WHERE scan_id=?", (scan_id,)
        ).fetchall()
    finally:
        conn.close()

    sep = os.sep
    na, nb = os.path.normcase(pa), os.path.normcase(pb)

    leaf = {}
    tree_a, tree_b = set(), set()
    for r in file_rows:
        cur = os.path.dirname(r["path"])
        if cur not in folder_set:
            continue
        cn = os.path.normcase(cur)
        in_a = cn == na or cn.startswith(na + sep)
        in_b = cn == nb or cn.startswith(nb + sep)
        if not (in_a or in_b):
            continue
        sig = r["name"].lower() + "|" + str(r["size"])
        leaf.setdefault(cur, set()).add(sig)
        if in_a:
            tree_a.add(sig)
        if in_b:
            tree_b.add(sig)

    common = tree_a & tree_b
    mn = min(len(tree_a), len(tree_b))
    result = {
        "a": pa,
        "b": pb,
        "similarity": round(len(common) / mn, 4) if mn else 0.0,
        "common": len(common),
        "count_a": len(tree_a),
        "count_b": len(tree_b),
        "only_in_a": len(tree_a) - len(common),
        "only_in_b": len(tree_b) - len(common),
        "common_files": [
            {"name": s.rsplit("|", 1)[0], "size": int(s.rsplit("|", 1)[1])}
            for s in sorted(common)[:MAX_EXPAND_CHIPS]
        ],
        "groups": [],
    }

    sig_owners = defaultdict(list)
    for f, s in leaf.items():
        cn = os.path.normcase(f)
        tree = 1 if (cn == na or cn.startswith(na + sep)) else 2
        for sig in s:
            sig_owners[sig].append((tree, f))

    pair_common = defaultdict(int)
    for sig, owners in sig_owners.items():
        ones = [f for t, f in owners if t == 1]
        twos = [f for t, f in owners if t == 2]
        if not ones or not twos:
            continue
        if len(ones) * len(twos) > 100000:
            continue
        for a in ones:
            for b in twos:
                pair_common[(a, b)] += 1

    groups = []
    for (a, b), cnt in pair_common.items():
        if cnt < min_common:
            continue
        sa, sb = leaf[a], leaf[b]
        mn = min(len(sa), len(sb))
        if mn <= 0:
            continue
        sim = cnt / mn
        if not (sim > threshold - 1e-9):
            continue
        groups.append(
            {
                "a": a,
                "b": b,
                "similarity": round(sim, 4),
                "common": cnt,
                "count_a": len(sa),
                "count_b": len(sb),
                "only_in_a": len(sa) - cnt,
                "only_in_b": len(sb) - cnt,
                "files": sorted(sa & sb)[:MAX_EXPAND_CHIPS],
            }
        )
    groups.sort(key=lambda x: (-x["similarity"], -x["common"]))
    result["groups"] = groups[:MAX_EXPAND_GROUPS]
    return result


@app.post("/api/folders/expand")
def api_folders_expand(m: ExpandModel):
    """Анализ пары «на уровень выше»: сравниваются родительские папки A и B
    рекурсивно — каждая со всеми своими подпапками."""
    sid = latest_scan_id()
    if not sid:
        raise HTTPException(400, "Нет данных скана — сначала запустите скан")
    root = get_root()
    pa = os.path.dirname(os.path.abspath(m.a))
    pb = os.path.dirname(os.path.abspath(m.b))
    for p, label in ((pa, "A"), (pb, "B")):
        if _inside_root(p, root) and os.path.isdir(p):
            continue
        raise HTTPException(
            400, f"Папка {label} уже на верхнем уровне — выше только корень сканирования"
        )
    na, nb = os.path.normcase(pa), os.path.normcase(pb)
    if na == nb:
        raise HTTPException(
            400, "У обеих папок общий родитель — сравнивать его с самим собой бессмысленно"
        )
    if nb.startswith(na + os.sep) or na.startswith(nb + os.sep):
        raise HTTPException(400, "Один из родителей вложен в другой — такое сравнение некорректно")
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT result_json FROM expanded_cache WHERE a=? AND b=? AND scan_id=? AND threshold=? AND min_common=?",
            (pa, pb, sid, m.threshold, int(m.min_common)),
        ).fetchone()
    finally:
        conn.close()
    if row:
        return json.loads(row["result_json"])
    result = _subtree_pair_analysis(pa, pb, m.threshold, int(m.min_common), sid)
    payload = json.dumps(result, ensure_ascii=False)
    conn = db_connect()
    try:
        conn.execute("BEGIN")
        conn.execute("DELETE FROM expanded_cache WHERE scan_id != ?", (sid,))
        conn.execute(
            "INSERT OR REPLACE INTO expanded_cache(a,b,threshold,min_common,scan_id,result_json) VALUES(?,?,?,?,?,?)",
            (pa, pb, m.threshold, int(m.min_common), sid, payload),
        )
        conn.commit()
    finally:
        conn.close()
    return result


@app.post("/api/folders/delete-pair")
def api_folders_delete_pair(m: DeletePairModel):
    """Удаление отработанной пары из выдачи.

    Из кэша стирается та папка пары (и все её подпапки с файлами), которой
    больше нет на диске. Если обе папки существуют — ничего не удаляется.
    Первый вызов (confirm=false) только считает, что будет удалено.
    """
    sid = latest_scan_id()
    if not sid:
        raise HTTPException(400, "Нет данных скана — сначала запустите скан")
    root = get_root()

    missing = []
    for p in (m.a, m.b):
        p = os.path.abspath(p.strip())
        if not _inside_root(p, root):
            raise HTTPException(400, f"Путь вне корня сканирования: {p}")
        if not os.path.isdir(p):
            missing.append(p)
    if not missing:
        raise HTTPException(
            400, "Обе папки пары ещё существуют на диске — удалять из кэша нечего"
        )

    conn = db_connect()
    try:
        folder_paths = [
            r["path"] for r in conn.execute("SELECT path FROM folders WHERE scan_id=?", (sid,))
        ]
        drop = set()
        for x in missing:
            xn = os.path.normcase(x)
            for fp in folder_paths:
                pn = os.path.normcase(fp)
                if pn == xn or pn.startswith(xn + os.sep):
                    drop.add(fp)

        prefixes = [os.path.normcase(x) + os.sep for x in drop]
        file_ids = []
        if prefixes:
            for r in conn.execute("SELECT id, path FROM files WHERE scan_id=?", (sid,)):
                pn = os.path.normcase(r["path"])
                if any(pn.startswith(pref) for pref in prefixes):
                    file_ids.append(r["id"])

        if not m.confirm:
            return {"missing": missing, "folders": len(drop), "files": len(file_ids)}

        def chunks(seq, size):
            seq = list(seq)
            for i in range(0, len(seq), size):
                yield seq[i:i + size]

        conn.execute("BEGIN")
        for chunk in chunks(file_ids, 500):
            conn.execute(
                f"DELETE FROM files WHERE id IN ({','.join('?' * len(chunk))})", chunk
            )
        for chunk in chunks(drop, 500):
            marks = ",".join("?" * len(chunk))
            conn.execute(f"DELETE FROM folders WHERE path IN ({marks})", chunk)
            conn.execute(
                f"DELETE FROM folder_stats WHERE scan_id=? AND path IN ({marks})", [sid] + chunk
            )
            conn.execute(
                f"DELETE FROM folder_pairs WHERE scan_id=? AND (a IN ({marks}) OR b IN ({marks}))",
                [sid] + chunk + chunk,
            )
        conn.execute("DELETE FROM expanded_cache WHERE scan_id=?", (sid,))
        conn.commit()
    finally:
        conn.close()

    set_state(None, None, f"Из кэша удалено: папок {len(drop)}, файлов {len(file_ids)}")
    return {"deleted": sorted(drop), "files": len(file_ids)}


@app.get("/api/file/{fid}/raw")
def api_file_raw(fid: int):
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT path,name FROM files WHERE id=? ORDER BY scan_id DESC LIMIT 1", (fid,)
        ).fetchone()
    finally:
        conn.close()
    if not row or not os.path.isfile(row["path"]):
        raise HTTPException(404, "Файл не найден")
    media = mimetypes.guess_type(row["name"])[0] or "application/octet-stream"
    return FileResponse(row["path"], media_type=media, filename=row["name"])


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

uvicorn.run(app, host="127.0.0.1", port=8765)
