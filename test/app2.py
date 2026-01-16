from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_apscheduler import APScheduler
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from services.pancake import PancakeService
from datetime import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests, time, random, string, re

app = Flask(__name__)

# --- CONFIG ---
MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"
client = MongoClient(MONGO_URI)
db = client.CRM_Production
app.config['SECRET_KEY'] = 'crm_thg_ultimate_2025_secure_final_v5'

login_manager = LoginManager()
login_manager.user_loader(lambda uid: User(db.users.find_one({"_id": ObjectId(uid)})) if db.users.find_one({"_id": ObjectId(uid)}) else None)
login_manager.login_view = 'login'
login_manager.login_message = None
login_manager.init_app(app)

# LARK CONFIG
LARK_APP_ID, LARK_APP_SECRET = "cli_a87a40a3d6b85010", "wFMNBqGMhcuZsyNDZVAnYgOv6XuZyAqn"
LARK_APP_TOKEN, LARK_TABLE_ID = "Vqfqbm1Lda7vdVsvABQlk8KSgog", "tblEUCxBUVUUDt4R"
LARK_TASK_APP_TOKEN, LARK_TASK_TABLE_ID = "Ajhqblaj9aT34JsuQ8PlTi7xgZe", "tblKknj4Pp8HStO9"

scheduler = APScheduler()
LAST_SYNC_TIMESTAMP = time.time()

# ---------------------------
# Corp Task: Departments + Status
# ---------------------------
CORP_DEPARTMENTS = ["Vận Hành", "Marketing", "Kế toán", "Nhân sự", "CSKH/Sale"]

# internal keys (stable)
CORP_STATUSES = ["Unreceived", "Received", "In_progress", "Pending_approval", "Done", "Cancelled"]
CORP_STATUS_LABELS = {
    "Unreceived": "Chưa nhận task",
    "Received": "Đã nhận task",
    "In_progress": "Đang làm",
    "Pending_approval": "Đang chờ duyệt",
    "Done": "Done",
    "Cancelled": "Cancelled",
}

def now_dt():
    return datetime.now()

def parse_due_at(raw: str):
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M")
    except Exception:
        return None

# ---------------------------
# Helpers (Task thường)
# ---------------------------
def is_overdue(task_doc):
    due = task_doc.get("due_at")
    return bool(due and isinstance(due, datetime) and due < now_dt())

def mark_missed(task_id: str, reason: str = "auto"):
    t = db.tasks.find_one({"id": task_id})
    if not t:
        return
    now = now_dt()
    if t.get("status") == "Done":
        return
    upd = {
        "status": "Missed",
        "missed_at": now,
        "updated_at": now,
        "miss_reason": reason,
        "missed_notify_pending": True,
    }
    db.tasks.update_one({"id": task_id}, {"$set": upd})

def link_customer_for_task(customer_name: str):
    if not customer_name:
        return None, None
    name = customer_name.strip()
    if not name:
        return None, None
    lead = db.leads.find_one({"full_name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
    if lead:
        return lead.get("psid"), lead.get("full_name")
    lead = db.leads.find_one({"full_name": {"$regex": re.escape(name), "$options": "i"}}, sort=[("updated_at", -1)])
    if lead:
        return lead.get("psid"), lead.get("full_name")
    return None, None

def can_user_quick_update(task_doc):
    if current_user.role == "admin":
        return True
    me = ObjectId(current_user.id)
    return task_doc.get("user_id") == me or task_doc.get("assigned_to") == me

def allowed_next_status(task_doc):
    overdue = is_overdue(task_doc)
    cur = task_doc.get("status", "Not_yet")
    if not overdue:
        if cur == "Done":
            return "Not_yet"
        return "Done"
    if cur == "Not_yet":
        return "Missed"
    if cur == "Done":
        return "Missed"
    return "Done"

# ---------------------------
# Corp Task permissions + transitions
# ---------------------------
def can_update_corp_status(corp_task):
    if current_user.role == "admin":
        return True
    return corp_task.get("assigned_to") == ObjectId(current_user.id)

def can_edit_corp_task(corp_task):
    return current_user.role == "admin"

def validate_corp_status_change(new_status: str, corp_task):
    if new_status not in CORP_STATUSES:
        return False, "Invalid status"
    if new_status == "Cancelled" and current_user.role != "admin":
        return False, "Only admin can cancel"
    return True, ""

# ---------------------------
# Lark / Pancake sync
# ---------------------------
def get_lark_token():
    url = "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal"
    try:
        res = requests.post(url, json={"app_id": LARK_APP_ID, "app_secret": LARK_APP_SECRET}, timeout=30)
        return res.json().get("tenant_access_token")
    except Exception as e:
        print("[LARK] get_lark_token error:", repr(e))
        return None

def classify_sector(fields):
    k = str(fields.get('Dịch vụ', '')).upper()
    if "POD" in k or "DROPSHIP" in k:
        return "Pod_Drop"
    elif "WAREHOUSE" in k:
        return "Warehouse"
    return "Express"

# ✅ FIX: luôn refresh pages/username/token để tránh “kẹt” token cũ => sync quay vòng
def init_pancake_pages(force_refresh: bool = True):
    """
    Refresh pages into db.pages:
    - username
    - access_token
    If force_refresh=True => regenerate token (best for fixing stuck state).
    """
    service = PancakeService()

    pages = []
    try:
        pages = service.fetch_pages()
    except Exception as e:
        print("[PANCAKE] fetch_pages error:", repr(e))
        return

    if not pages:
        print("[PANCAKE] fetch_pages returned empty. Check PANCAKE_USER_TOKEN / network.")
        return

    for p in pages:
        p_id = str(p.get('id') or '')
        if not p_id:
            continue

        p_username = p.get('username') or p.get('slug') or p_id
        if p.get('platform') == 'zalo' and not str(p_username).startswith('pzl_'):
            p_username = f"pzl_{p_username}"
        elif p.get('platform') == 'telegram' and not str(p_username).startswith('tl_'):
            p_username = f"tl_{p_username}"

        existing = db.pages.find_one({"id": p_id})
        access_token = existing.get("access_token") if existing else None

        if force_refresh or not access_token:
            try:
                tk = service.get_token(p_id)
                if tk:
                    access_token = tk
                else:
                    print(f"[PANCAKE] Cannot generate page token for page_id={p_id}")
            except Exception as e:
                print(f"[PANCAKE] get_token error page_id={p_id}:", repr(e))

        db.pages.update_one(
            {"id": p_id},
            {"$set": {
                "id": p_id,
                "name": p.get('name'),
                "platform": p.get('platform'),
                "username": p_username,
                "access_token": access_token,
                "updated_at": now_dt()
            }},
            upsert=True
        )

def sync_all_lark_task():
    global LAST_SYNC_TIMESTAMP
    tk = get_lark_token()
    if not tk:
        return
    try:
        res = requests.get(
            f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_APP_TOKEN}/tables/{LARK_TABLE_ID}/records",
            headers={"Authorization": f"Bearer {tk}"},
            params={"page_size": 500},
            timeout=60
        ).json()

        for item in res.get('data', {}).get('items', []):
            f = item.get('fields', {})
            db.leads.update_one(
                {"psid": item.get('record_id')},
                {"$set": {
                    "full_name": f.get('Tên khách hàng'),
                    "phone_number": f.get('Link FB/username tele'),
                    "sector": classify_sector(f),
                    "status": f.get('Trạng thái', 'Khách Mới'),
                    "page_id": "LARK_AUTO",
                    "source_platform": "Lark",
                    "updated_at": now_dt()
                }},
                upsert=True
            )
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception as e:
        print("[LARK] sync_all_lark_task error:", repr(e))

def sync_lark_tasks_task():
    global LAST_SYNC_TIMESTAMP
    tk = get_lark_token()
    if not tk:
        return
    try:
        res = requests.get(
            f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_TASK_APP_TOKEN}/tables/{LARK_TASK_TABLE_ID}/records",
            headers={"Authorization": f"Bearer {tk}"},
            timeout=60
        ).json()

        for item in res.get('data', {}).get('items', []):
            f = item.get('fields', {})
            assignee = f.get('Chịu trách nhiệm', [])[0].get('name', '---') if f.get('Chịu trách nhiệm') else '---'
            u_id = None
            lu = db.users.find_one({"username": assignee})
            if lu:
                u_id = lu['_id']

            db.tasks.update_one(
                {"id": item.get('record_id')},
                {"$set": {
                    "todo_content": f.get('Nội Dung Todo', ''),
                    "status": f.get('Tình trạng', 'Not_yet'),
                    "assignee": assignee,
                    "assigned_to": u_id,
                    "customer_name": f.get('Tên Nhóm Khách/Khách mới', ''),
                    "due_at": None,
                    "updated_at": now_dt()
                }},
                upsert=True
            )
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception as e:
        print("[LARK] sync_lark_tasks_task error:", repr(e))

def pancake_sync_task():
    global LAST_SYNC_TIMESTAMP
    service = PancakeService()

    try:
        # ✅ refresh pages mỗi lần sync để tránh stuck token/username
        init_pancake_pages(force_refresh=True)

        for p_doc in db.pages.find({}, {"id": 1, "access_token": 1, "username": 1}):
            page_id = p_doc.get("id")
            token = p_doc.get("access_token")
            p_username = p_doc.get("username")

            if not page_id or not token:
                print(f"[PANCAKE] Skip page (missing token): page_id={page_id}")
                continue

            # giữ API call y như hiện tại của bạn (get_all_leads returns conversation_id)
            leads = service.get_all_leads(page_id, token)

            for l in leads:
                db.leads.update_one(
                    {"psid": l['psid']},
                    {"$set": {
                        "full_name": l['name'],
                        "phone_number": l['phone'],
                        "sector": l['sector'],
                        "status": l['status'],
                        "page_id": page_id,
                        "page_username": p_username,       # ✅ always write username from pages
                        "conversation_id": l.get('conversation_id'),
                        "source_platform": "Pancake",
                        "updated_at": now_dt()
                    }},
                    upsert=True
                )

        LAST_SYNC_TIMESTAMP = time.time()
        print("[PANCAKE] Sync OK:", now_dt())
    except Exception as e:
        print("[PANCAKE] Sync FAILED:", repr(e))

# ---------------------------
# Auto Missed for Task thường
# ---------------------------
def auto_mark_missed_tasks():
    now = now_dt()
    try:
        overdue = list(db.tasks.find({"status": "Not_yet", "due_at": {"$ne": None, "$lt": now}}, {"id": 1}))
        for t in overdue:
            mark_missed(t.get("id"), reason="auto_deadline")
    except Exception as e:
        print("[TASK] auto_mark_missed_tasks error:", repr(e))

# ---------------------------
# AUTH
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        if db.users.find_one({"username": u}):
            flash('Username exists!', 'danger')
            return redirect(url_for('register'))
        role = 'admin' if db.users.count_documents({}) == 0 else 'user'
        db.users.insert_one({"username": u, "password_hash": generate_password_hash(p), "role": role, "created_at": now_dt()})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        user = db.users.find_one({"username": u})
        if user and check_password_hash(user['password_hash'], p):
            login_user(User(user))
            return redirect(url_for('index'))
        flash('Tên đăng nhập hoặc mật khẩu không đúng', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------------------
# Pages / CRM
# ---------------------------
@app.route('/')
@login_required
def index():
    stats = {
        "pod_drop": db.leads.count_documents({"sector": "Pod_Drop"}),
        "express": db.leads.count_documents({"sector": "Express"}),
        "warehouse": db.leads.count_documents({"sector": "Warehouse"}),
        "total_staff": db.users.count_documents({})
    }
    return render_template('pages.html', stats=stats)

@app.route('/sector/<name>')
@login_required
def view_sector(name):
    q = {"sector": name}
    search, status = request.args.get('search'), request.args.get('status')
    if search:
        q["full_name"] = {"$regex": search, "$options": "i"}
    if status:
        q["status"] = status
    leads = list(db.leads.find(q).sort("updated_at", -1))
    return render_template('leads.html', sector_name=name, sector_id=name, leads=leads)

@app.route('/customer/<psid>')
@login_required
def view_customer_detail(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead:
        return "Not Found", 404

    t_q = {"$or": [{"customer_psid": psid}, {"customer_name": lead.get("full_name")}]}
    n_q = {"customer_psid": psid}

    if current_user.role != 'admin':
        t_q = {"$and": [
            t_q,
            {"$or": [{"user_id": ObjectId(current_user.id)}, {"assigned_to": ObjectId(current_user.id)}]}
        ]}
        n_q["user_id"] = ObjectId(current_user.id)

    tasks = list(db.tasks.find(t_q).sort("created_at", -1))
    notes = list(db.notes.find(n_q).sort("created_at", -1))

    users_list = list(db.users.find({}, {"username": 1, "_id": 1})) if current_user.role == 'admin' else []
    return render_template('customer.html', lead=lead, tasks=tasks, notes=notes, users_list=users_list)

@app.route('/customer/update/<psid>', methods=['POST'])
@login_required
def update_customer(psid):
    upd = {k: v for k, v in request.form.items() if v}
    upd['updated_at'] = now_dt()
    db.leads.update_Many if False else db.leads.update_one({"psid": psid}, {"$set": upd})  # keep behavior
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"status": "success"})
    return redirect(url_for('view_customer_detail', psid=psid))

# ---------------------------
# Task thường
# ---------------------------
@app.route('/tasks')
@login_required
def view_tasks():
    if current_user.role == 'admin':
        base_q = {}
    else:
        base_q = {"$or": [{"user_id": ObjectId(current_user.id)}, {"assigned_to": ObjectId(current_user.id)}]}

    search = request.args.get('search')
    status = request.args.get('status')

    filter_q = {}
    if search:
        filter_q["$or"] = [
            {"todo_content": {"$regex": search, "$options": "i"}},
            {"customer_name": {"$regex": search, "$options": "i"}},
            {"assignee": {"$regex": search, "$options": "i"}}
        ]
    if status:
        filter_q["status"] = status

    final_q = {}
    if base_q and filter_q:
        final_q = {"$and": [base_q, filter_q]}
    elif base_q:
        final_q = base_q
    elif filter_q:
        final_q = filter_q

    tasks = list(db.tasks.find(final_q).sort("updated_at", -1))
    u_list = list(db.users.find({}, {"username": 1, "_id": 1})) if current_user.role == 'admin' else []
    return render_template('tasks.html', tasks=tasks, users_list=u_list)

@app.route('/task/add', methods=['POST'])
@login_required
def add_task():
    tid = 'task_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    aid = request.form.get('assigned_user_id') or current_user.id
    target = db.users.find_one({"_id": ObjectId(aid)})

    status = "Not_yet"
    due_at = parse_due_at(request.form.get('due_at'))
    customer_name = (request.form.get('customer_name') or '').strip()

    customer_psid, normalized_name = link_customer_for_task(customer_name)
    if normalized_name:
        customer_name = normalized_name

    assigned_to_oid = ObjectId(aid)
    created_by_oid = ObjectId(current_user.id)
    notify_pending = (assigned_to_oid != created_by_oid)

    db.tasks.insert_one({
        "id": tid,
        "todo_content": request.form.get('todo_content'),
        "customer_name": customer_name,
        "customer_psid": customer_psid,
        "assignee": target['username'] if target else '---',
        "assigned_to": assigned_to_oid,
        "status": status,
        "due_at": due_at,
        "user_id": created_by_oid,
        "created_at": now_dt(),
        "updated_at": now_dt(),
        "notify_pending": notify_pending,
        "assigned_by": current_user.username,
        "assigned_at": now_dt() if notify_pending else None,
        "missed_notify_pending": False
    })
    return redirect(url_for('view_tasks'))

@app.route('/task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_task(id):
    t = db.tasks.find_one({"id": id})
    if not t:
        return jsonify({"status": "not_found"}), 404
    if not can_user_quick_update(t):
        return jsonify({"status": "forbidden"}), 403

    next_status = allowed_next_status(t)
    now = now_dt()
    upd = {"status": next_status, "updated_at": now}
    if next_status == "Missed":
        upd["missed_at"] = now
        upd["missed_notify_pending"] = True
    db.tasks.update_one({"id": id}, {"$set": upd})
    return jsonify({"status": "success", "next": next_status})

# ---------------------------
# ✅ Task Tổng công ty
# ---------------------------
@app.route('/corp-tasks')
@login_required
def view_corp_tasks():
    dept = request.args.get('dept', '').strip()
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()

    q = {}
    if current_user.role != 'admin':
        q["assigned_to"] = ObjectId(current_user.id)

    if dept:
        q["department"] = dept
    if status:
        q["status"] = status
    if search:
        q["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"assignee": {"$regex": search, "$options": "i"}},
            {"department": {"$regex": search, "$options": "i"}}
        ]

    corp_tasks = list(db.corp_tasks.find(q).sort("updated_at", -1))
    users_list = list(db.users.find({}, {"username": 1, "_id": 1})) if current_user.role == 'admin' else []

    return render_template(
        'corp_tasks.html',
        corp_tasks=corp_tasks,
        corp_departments=CORP_DEPARTMENTS,
        corp_statuses=CORP_STATUSES,
        corp_status_labels=CORP_STATUS_LABELS,
        users_list=users_list
    )

@app.route('/corp-task/add', methods=['POST'])
@login_required
def add_corp_task():
    if current_user.role != 'admin':
        return redirect(url_for('view_corp_tasks'))

    cid = 'corp_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    title = (request.form.get('title') or '').strip()
    department = request.form.get('department')
    assigned_user_id = request.form.get('assigned_user_id')
    due_at = parse_due_at(request.form.get('due_at'))

    if not title or department not in CORP_DEPARTMENTS or not assigned_user_id or not due_at:
        flash('Thiếu thông tin khi tạo corp task', 'danger')
        return redirect(url_for('view_corp_tasks'))

    u = db.users.find_one({"_id": ObjectId(assigned_user_id)})
    if not u:
        flash('Assignee không tồn tại', 'danger')
        return redirect(url_for('view_corp_tasks'))

    assigned_to_oid = u["_id"]
    notify_pending = (assigned_to_oid != ObjectId(current_user.id))

    db.corp_tasks.insert_one({
        "id": cid,
        "title": title,
        "department": department,
        "assigned_to": assigned_to_oid,
        "assignee": u.get("username", "user"),
        "status": "Unreceived",
        "due_at": due_at,

        "created_at": now_dt(),
        "updated_at": now_dt(),
        "assigned_by": current_user.username,
        "assigned_at": now_dt(),

        "notify_pending": True if notify_pending else False,
        "notified_at": None
    })
    return redirect(url_for('view_corp_tasks'))

@app.route('/corp-task/update/<id>', methods=['POST'])
@login_required
def update_corp_task(id):
    t = db.corp_tasks.find_one({"id": id})
    if not t:
        return redirect(url_for('view_corp_tasks'))
    if not can_edit_corp_task(t):
        return redirect(url_for('view_corp_tasks'))

    title = (request.form.get('title') or '').strip()
    department = request.form.get('department')
    assigned_user_id = request.form.get('assigned_user_id')
    due_at = parse_due_at(request.form.get('due_at'))

    if not title or department not in CORP_DEPARTMENTS or not assigned_user_id or not due_at:
        flash('Thiếu thông tin khi update corp task', 'danger')
        return redirect(url_for('view_corp_tasks'))

    u = db.users.find_one({"_id": ObjectId(assigned_user_id)})
    if not u:
        flash('Assignee không tồn tại', 'danger')
        return redirect(url_for('view_corp_tasks'))

    upd = {
        "title": title,
        "department": department,
        "assigned_to": u["_id"],
        "assignee": u.get("username", "user"),
        "due_at": due_at,
        "updated_at": now_dt()
    }

    if u["_id"] != t.get("assigned_to"):
        upd["notify_pending"] = True
        upd["assigned_by"] = current_user.username
        upd["assigned_at"] = now_dt()
        upd["status"] = "Unreceived"

    db.corp_tasks.update_one({"id": id}, {"$set": upd})
    return redirect(url_for('view_corp_tasks'))

@app.route('/corp-task/status/<id>', methods=['POST'])
@login_required
def update_corp_status(id):
    t = db.corp_tasks.find_one({"id": id})
    if not t:
        return jsonify({"status": "not_found"}), 404
    if not can_update_corp_status(t):
        return jsonify({"status": "forbidden", "message": "No permission"}), 403

    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status")

    ok, msg = validate_corp_status_change(new_status, t)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400

    db.corp_tasks.update_one({"id": id}, {"$set": {"status": new_status, "updated_at": now_dt()}})
    return jsonify({"status": "success"})

# ---------------------------
# Notifications (task thường + corp task)
# ---------------------------
@app.route('/api/notifications')
@login_required
def api_notifications():
    me = ObjectId(current_user.id)

    q1 = {"assigned_to": me, "notify_pending": True, "status": {"$ne": "Done"}}
    items1 = list(db.tasks.find(q1).sort("assigned_at", -1).limit(10))

    q2 = {"assigned_to": me, "notify_pending": True, "status": {"$ne": "Done"}}
    items2 = list(db.corp_tasks.find(q2).sort("assigned_at", -1).limit(10))

    def fmt_task(x):
        due = x.get("due_at")
        return {
            "id": x.get("id"),
            "kind": "task",
            "todo_content": x.get("todo_content", ""),
            "customer_name": x.get("customer_name", ""),
            "assigned_by": x.get("assigned_by", ""),
            "assigned_at": x.get("assigned_at").strftime("%d/%m %H:%M") if x.get("assigned_at") else "",
            "due_at": due.strftime("%d/%m %H:%M") if due else ""
        }

    def fmt_corp(x):
        due = x.get("due_at")
        return {
            "id": x.get("id"),
            "kind": "corp",
            "todo_content": f"[{x.get('department','')}] {x.get('title','')}",
            "customer_name": "",
            "assigned_by": x.get("assigned_by", ""),
            "assigned_at": x.get("assigned_at").strftime("%d/%m %H:%M") if x.get("assigned_at") else "",
            "due_at": due.strftime("%d/%m %H:%M") if due else ""
        }

    merged = [fmt_task(i) for i in items1] + [fmt_corp(i) for i in items2]
    merged = sorted(merged, key=lambda z: z.get("assigned_at", ""), reverse=True)[:15]
    return jsonify({"items": merged})

@app.route('/api/notifications/ack', methods=['POST'])
@login_required
def api_notifications_ack():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    if not isinstance(ids, list) or not ids:
        return jsonify({"status": "no_ids"}), 400

    me = ObjectId(current_user.id)
    now = now_dt()

    db.tasks.update_many(
        {"id": {"$in": ids}, "assigned_to": me},
        {"$set": {"notify_pending": False, "notified_at": now, "updated_at": now}}
    )
    db.corp_tasks.update_many(
        {"id": {"$in": ids}, "assigned_to": me},
        {"$set": {"notify_pending": False, "notified_at": now, "updated_at": now}}
    )
    return jsonify({"status": "success"})

# ---------------------------
# Admin missed notifications (task thường)
# ---------------------------
@app.route('/api/admin/missed')
@login_required
def api_admin_missed():
    if current_user.role != "admin":
        return jsonify({"items": []})

    q = {"status": "Missed", "missed_notify_pending": True}
    items = list(db.tasks.find(q).sort("missed_at", -1).limit(20))

    def fmt(x):
        due = x.get("due_at")
        miss = x.get("missed_at")
        return {
            "id": x.get("id"),
            "todo_content": x.get("todo_content", ""),
            "customer_name": x.get("customer_name", ""),
            "assignee": x.get("assignee", ""),
            "due_at": due.strftime("%d/%m %H:%M") if due else "",
            "missed_at": miss.strftime("%d/%m %H:%M") if miss else ""
        }

    return jsonify({"items": [fmt(i) for i in items]})

@app.route('/api/admin/missed/ack', methods=['POST'])
@login_required
def api_admin_missed_ack():
    if current_user.role != "admin":
        return jsonify({"status": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    if not isinstance(ids, list) or not ids:
        return jsonify({"status": "no_ids"}), 400

    db.tasks.update_many(
        {"id": {"$in": ids}},
        {"$set": {"missed_notify_pending": False, "missed_notified_at": now_dt(), "updated_at": now_dt()}}
    )
    return jsonify({"status": "success"})

# ---------------------------
# Sync utilities
# ---------------------------
@app.route('/sync-status')
@login_required
def sync_status():
    return jsonify({"last_sync": LAST_SYNC_TIMESTAMP})

@app.route('/sync-now')
@login_required
def sync_now():
    # ✅ refresh mạnh để tránh stuck token/username
    init_pancake_pages(force_refresh=True)
    pancake_sync_task()
    sync_all_lark_task()
    sync_lark_tasks_task()
    return redirect(request.referrer or url_for('index'))

@app.route('/webhook/lark', methods=['POST'])
def lark_webhook():
    d = request.json
    if d and "challenge" in d:
        return jsonify({"challenge": d["challenge"]})
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    if db.users.count_documents({"username": "admin"}) == 0:
        db.users.insert_one({
            "username": "admin",
            "password_hash": generate_password_hash('admin123'),
            "role": "admin",
            "created_at": now_dt()
        })

    # ✅ refresh ngay khi start app
    init_pancake_pages(force_refresh=True)

    if not scheduler.running:
        scheduler.add_job(id='p_sync', func=pancake_sync_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_leads', func=sync_all_lark_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_tasks', func=sync_lark_tasks_task, trigger='interval', seconds=60)

        scheduler.add_job(id='auto_missed', func=auto_mark_missed_tasks, trigger='interval', seconds=60)

        scheduler.start()

    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
