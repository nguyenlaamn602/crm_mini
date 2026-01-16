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
import uuid
import os
from dotenv import load_dotenv
load_dotenv()

# Lấy Token trực tiếp từ .env giống ttest.py
PANCAKE_USER_TOKEN = os.getenv("PANCAKE_USER_TOKEN")
BASE_URL = "https://pages.fm/api/v1"
PUBLIC_V1 = "https://pages.fm/api/public_api/v1"
PUBLIC_V2 = "https://pages.fm/api/public_api/v2"

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
CORP_DEPARTMENTS = ["Vận Hành", "Marketing", "Kế toán", "Nhân sự", "CSKH/Sale", "Ngoại giao"]

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
# Helpers (Personal Task)
# ---------------------------

def next_personal_status(cur):
    if cur == "Not_yet":
        return "Done"
    if cur == "Done":
        return "Missed"
    return "Not_yet"

def auto_mark_personal_tasks():
    now = now_dt()
    overdue = db.personal_tasks.find({
        "status": "Not_yet",
        "due_at": {"$ne": None, "$lt": now}
    })

    for t in overdue:
        db.personal_tasks.update_one(
            {"id": t["id"]},
            {"$set": {
                "status": "Missed",
                "updated_at": now,
                "missed_notify_pending": True
            }}
        )



# ---------------------------
# Corp Task permissions + transitions
# ---------------------------
def can_update_corp_status(corp_task):
    if current_user.role == "admin":
        return True

    assigned = corp_task.get("assigned_to")

    # THG FIX: support legacy single assignee (ObjectId) and new list
    if isinstance(assigned, ObjectId):
        return ObjectId(current_user.id) == assigned

    if isinstance(assigned, list):
        return ObjectId(current_user.id) in assigned

    return False

def can_edit_corp_task(corp_task):
    if current_user.role == "admin":
        return True
    assigned = corp_task.get("assigned_to", [])
    if isinstance(assigned, list):
        return ObjectId(current_user.id) in assigned
    return ObjectId(current_user.id) == assigned

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

            # NOTE: Lark field "Time" trước đây hay map vào time_log.
            # Theo yêu cầu: time_log -> deadline. Nếu Lark trả string không parse được thì giữ None.
            # Bạn có thể chỉnh lại khi biết format "Time" thực tế bên Lark.
            raw_deadline = f.get('Time') or f.get('Deadline') or None
            due_at = None
            if isinstance(raw_deadline, str):
                due_at = parse_due_at(raw_deadline)

            db.tasks.update_one(
                {"id": item.get('record_id')},
                {"$set": {
                    "todo_content": f.get('Nội Dung Todo', ''),
                    "status": f.get('Tình trạng', 'Not_yet'),
                    "assignee": assignee,
                    "assigned_to": u_id,
                    "customer_name": f.get('Tên Nhóm Khách/Khách mới', ''),
                    "due_at": due_at,
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
                        "page_username": p_username,
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

def sync_pancake_conversation_for_customer(customer):
    service = PancakeService()

    pages = service.fetch_pages()
    for page in pages:
        page_id = page["id"]
        page_username = page["username"]

        conversations = service.fetch_conversations(page_id)

        for c in conversations:
            if c.get("psid") == customer.get("psid"):
                return {
                    "page_id": page_id,
                    "page_username": page_username,
                    "conversation_id": c["id"]
                }
    return None


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
        "total_staff": db.users.count_documents({}),
        "personal_tasks": db.personal_tasks.count_documents({"user_id": ObjectId(current_user.id),"status": {"$ne": "Done"}})
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

@app.route('/customer/add', methods=['POST'])
@login_required
def add_customer():
    full_name = (request.form.get("full_name") or "").strip()
    if not full_name:
        flash("Thiếu tên khách hàng", "danger")
        return redirect(request.referrer or url_for("index"))

    phone_number = (request.form.get("phone_number") or "").strip()
    sector = request.form.get("sector") or "Pod_Drop"
    status = request.form.get("status") or "Khách Mới"

    psid = str(uuid.uuid4())

    db.leads.insert_one({
        "psid": psid,
        "full_name": full_name,
        "phone_number": phone_number if phone_number else "N/A",
        "sector": sector,
        "status": status,
        "page_id": "MANUAL",
        "source_platform": "Manual",
        "updated_at": now_dt(),
        "created_at": now_dt(),
    })
    return redirect(url_for("view_sector", name=sector))

@app.route('/customer/<cid>/sync-pancake', methods=['POST'])
@login_required
def sync_customer_pancake(cid):
    customer = db.customers.find_one({"_id": ObjectId(cid)})
    if not customer:
        return jsonify({"status": "not_found"}), 404

    if not customer.get("psid"):
        return jsonify({"status": "missing_psid"}), 400

    result = sync_pancake_conversation_for_customer(customer)
    if not result:
        return jsonify({"status": "not_found_conversation"})

    db.customers.update_one(
        {"_id": customer["_id"]},
        {"$set": result}
    )

    return jsonify({"status": "success"})


# ✅ DELETE CUSTOMER (Admin only)
@app.route('/customer/delete/<psid>', methods=['POST'])
@login_required
def delete_customer(psid):
    if current_user.role != 'admin':
        return redirect(request.referrer or url_for('index'))

    db.leads.delete_one({"psid": psid})
    # optional: cleanup tasks/notes for this customer (không bắt buộc)
    # db.tasks.delete_many({"customer_psid": psid})
    # db.notes.delete_many({"customer_psid": psid})
    return redirect(url_for('index'))

# ✅ Add Note in customer detail
@app.route('/customer/note/add/<psid>', methods=['POST'])
@login_required
def add_customer_note(psid):
    content = (request.form.get("content") or "").strip()
    if content:
        db.notes.insert_one({
            "content": content,
            "customer_psid": psid,
            "user_id": ObjectId(current_user.id),
            "created_at": now_dt()
        })
    return redirect(url_for("view_customer_detail", psid=psid))

# ✅ Add Activity (Task) from customer profile
# time_log -> deadline (store as due_at)
@app.route('/customer/activity/add/<psid>', methods=['POST'])
@login_required
def add_customer_activity(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead:
        return redirect(url_for("index"))

    tid = 'act_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    todo_content = (request.form.get("todo_content") or "").strip()
    if not todo_content:
        return redirect(url_for("view_customer_detail", psid=psid))

    status = request.form.get("status") or "Not_yet"

    # ✅ deadline preferred (datetime-local). Fallback to old time_log to avoid breaking UI.
    raw_deadline = request.form.get("deadline")
    if not raw_deadline:
        # old field "time_log" (often only HH:MM). We'll store None or keep as string in legacy field.
        raw_deadline = request.form.get("time_log")

    due_at = None
    legacy_time_log = None

    # If it's datetime-local
    if isinstance(raw_deadline, str) and "T" in raw_deadline:
        due_at = parse_due_at(raw_deadline)
    else:
        # HH:MM only -> keep legacy, no due date
        legacy_time_log = raw_deadline if raw_deadline else None

    assigned_to_oid = ObjectId(current_user.id)
    assignee_name = current_user.username

    # Admin can assign to user via dropdown
    if current_user.role == "admin":
        assigned_user_id = request.form.get("assigned_user_id")
        if assigned_user_id:
            u = db.users.find_one({"_id": ObjectId(assigned_user_id)})
            if u:
                assigned_to_oid = u["_id"]
                assignee_name = u.get("username", assignee_name)

    created_by_oid = ObjectId(current_user.id)

    db.tasks.insert_one({
        "id": tid,
        "todo_content": todo_content,
        "customer_name": lead.get("full_name"),
        "customer_psid": psid,

        "assignee": assignee_name,
        "assigned_to": assigned_to_oid,

        "status": status,
        "due_at": due_at,                 # ✅ deadline stored here
        "deadline": due_at,               # optional alias
        "time_log": legacy_time_log,      # legacy fallback

        "user_id": created_by_oid,
        "created_at": now_dt(),
        "updated_at": now_dt(),

        # for delete permission
        "assigned_by": current_user.username,
        "assigned_by_role": current_user.role,
        "assigned_at": now_dt() if assigned_to_oid != created_by_oid else None,
        "notify_pending": True if assigned_to_oid != created_by_oid else False,
        "missed_notify_pending": False
    })

    return redirect(url_for("view_customer_detail", psid=psid))

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
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))  # ✅ accept deadline alias
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
        "due_at": due_at,                  # ✅ deadline stored here
        "deadline": due_at,                # optional alias
        "user_id": created_by_oid,
        "created_at": now_dt(),
        "updated_at": now_dt(),
        "notify_pending": notify_pending,

        "assigned_by": current_user.username,
        "assigned_by_role": current_user.role,   # ✅ used for delete permission
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

# ✅ DELETE TASK (Admin can delete all; user cannot delete tasks assigned by admin)
@app.route('/task/delete/<id>', methods=['POST'])
@login_required
def delete_task(id):
    t = db.tasks.find_one({"id": id})
    if not t:
        return redirect(url_for('view_tasks'))

    if current_user.role == "admin":
        db.tasks.delete_one({"id": id})
        return redirect(request.referrer or url_for('view_tasks'))

    # user rule:
    # - allow delete only if user is creator
    # - but forbid if task was assigned by admin
    me = ObjectId(current_user.id)
    if t.get("user_id") != me:
        return redirect(request.referrer or url_for('view_tasks'))

    if t.get("assigned_by_role") == "admin":
        flash("Bạn không thể xoá task do admin phân bổ.", "danger")
        return redirect(request.referrer or url_for('view_tasks'))

    db.tasks.delete_one({"id": id})
    return redirect(request.referrer or url_for('view_tasks'))

# ---------------------------
# Personal Tasks
# ---------------------------
@app.route('/personal-tasks')
@login_required
def view_personal_tasks():
    q = {
        "user_id": ObjectId(current_user.id)
    }

    status = request.args.get('status')
    search = request.args.get('search')

    if status:
        q["status"] = status

    if search:
        q["title"] = {"$regex": search, "$options": "i"}

    tasks = list(
        db.personal_tasks
        .find(q)
        .sort("updated_at", -1)
    )

    return render_template(
        "personal_tasks.html",
        tasks=tasks
    )


@app.route('/personal-task/add', methods=['POST'])
@login_required
def add_personal_task():
    tid = 'ptask_' + ''.join(
        random.choices(string.ascii_lowercase + string.digits, k=8)
    )

    title = (request.form.get("title") or "").strip()
    if not title:
        return redirect(url_for("view_personal_tasks"))

    due_at = parse_due_at(request.form.get("due_at"))

    db.personal_tasks.insert_one({
        "id": tid,
        "title": title,
        "description": request.form.get("description"),

        "status": "Not_yet",
        "due_at": due_at,

        "user_id": ObjectId(current_user.id),

        "created_at": now_dt(),
        "updated_at": now_dt(),

        "notify_pending": False,
        "missed_notify_pending": False
    })

    return redirect(url_for("view_personal_tasks"))


@app.route('/personal-task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_personal_task(id):
    t = db.personal_tasks.find_one({
        "id": id,
        "user_id": ObjectId(current_user.id)
    })

    if not t:
        return jsonify({"status": "not_found"}), 404

    next_status = next_personal_status(t.get("status", "Not_yet"))

    upd = {
        "status": next_status,
        "updated_at": now_dt()
    }

    if next_status == "Missed":
        upd["missed_notify_pending"] = True

    db.personal_tasks.update_one(
        {"id": id},
        {"$set": upd}
    )

    return jsonify({"status": "success", "next": next_status})


@app.route('/personal-task/delete/<id>', methods=['POST'])
@login_required
def delete_personal_task(id):
    db.personal_tasks.delete_one({
        "id": id,
        "user_id": ObjectId(current_user.id)
    })
    return redirect(url_for("view_personal_tasks"))



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
        q["assigned_to"] = {"$in": [ObjectId(current_user.id)]}

    if dept:
        q["department"] = dept
    if status:
        q["status"] = status
    if search:
        q["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"assignees": {"$regex": search, "$options": "i"}},
            {"department": {"$regex": search, "$options": "i"}}
        ]

    corp_tasks = list(db.corp_tasks.find(q).sort("updated_at", -1))

    # ===== NORMALIZE TASK DATA (UI) =====
    for t in corp_tasks:
        if isinstance(t.get("assigned_to"), ObjectId):
            t["assigned_to"] = [t["assigned_to"]]

        if "assignees" not in t:
            t["assignees"] = [t["assignee"]] if t.get("assignee") else []

    users_list = list(db.users.find({}, {"username": 1, "_id": 1}))

    # ===== SERIALIZE FOR CHART (NO ObjectId) =====
    corp_tasks_chart = []
    for t in corp_tasks:
        corp_tasks_chart.append({
            "id": t.get("id"),
            "title": t.get("title"),
            "department": t.get("department"),
            "status": t.get("status"),
        })

    return render_template(
        'corp_tasks.html',
        corp_tasks=corp_tasks,                
        corp_tasks_chart=corp_tasks_chart,     
        corp_departments=CORP_DEPARTMENTS,
        corp_statuses=CORP_STATUSES,
        corp_status_labels=CORP_STATUS_LABELS,
        users_list=users_list
    )


@app.route('/corp-task/add', methods=['POST'])
@login_required
def add_corp_task():
    # Tạo ID ngẫu nhiên cho task
    cid = 'corp_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    title = (request.form.get('title') or '').strip()
    department = request.form.get('department')
    
    # LẤY DANH SÁCH NGƯỜI ĐƯỢC GÁN (Mở cho tất cả các Role)
    assigned_user_ids = request.form.getlist('assigned_user_ids')
    
    # Nếu là User thường mà không chọn ai, thì mặc định tự gán cho mình
    if not assigned_user_ids:
        assigned_user_ids = [str(current_user.id)]

    # Parse thời hạn
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    # Kiểm tra dữ liệu đầu vào
    if not title or department not in CORP_DEPARTMENTS or not due_at:
        flash('Thiếu thông tin hoặc phòng ban không hợp lệ', 'danger')
        return redirect(url_for('view_corp_tasks'))

    # Xử lý OID và lấy tên hiển thị
    try:
        # Chuyển string ID thành ObjectId, bọc trong try-except để tránh crash nếu ID lỗi
        user_oids = [ObjectId(uid) for uid in assigned_user_ids]
        users = list(db.users.find({"_id": {"$in": user_oids}}))
        
        assignees = [u.get("username", "user") for u in users]
    except Exception as e:
        flash('Lỗi định dạng người dùng', 'danger')
        return redirect(url_for('view_corp_tasks'))

    # Lưu vào Database
    db.corp_tasks.insert_one({
        "id": cid,
        "title": title,
        "department": department,
        "assigned_to": [u["_id"] for u in users], # Lưu mảng OID
        "assignees": assignees,                   # Lưu mảng tên để hiển thị nhanh
        "assignee": assignees[0] if assignees else '---',
        "status": "Unreceived",
        "due_at": due_at,
        "created_at": now_dt(),
        "updated_at": now_dt(),
        "assigned_by": current_user.username,
        "assigned_by_role": current_user.role,
        "assigned_at": now_dt(),
        "notify_pending": True,
        "admin_request": None 
    })

    flash('Đã tạo task công ty thành công', 'success')
    return redirect(url_for('view_corp_tasks'))

# Thêm Route mới để User gửi yêu cầu Edit/Xoá
@app.route('/corp-task/request-action/<id>', methods=['POST'])
@login_required
def request_corp_action(id):
    action_type = request.form.get('action_type') # 'edit' hoặc 'delete'
    reason = request.form.get('reason', '')
    
    if action_type not in ['edit', 'delete']:
        return jsonify({"status": "error", "message": "Invalid action"}), 400
        
    db.corp_tasks.update_one(
        {"id": id},
        {"$set": {
            "admin_request": action_type,
            "request_reason": reason,
            "request_by": current_user.username,
            "updated_at": now_dt()
        }}
    )
    flash(f"Đã gửi yêu cầu {action_type} tới Admin", "info")
    return redirect(url_for('view_corp_tasks'))

@app.route('/corp-task/update/<id>', methods=['POST'])
@login_required
def update_corp_task(id):
    t = db.corp_tasks.find_one({"id": id})
    if not t or not can_edit_corp_task(t):
        flash("Bạn không có quyền chỉnh sửa task này", "danger")
        return redirect(url_for('view_corp_tasks'))

    title = (request.form.get('title') or '').strip()
    department = request.form.get('department')
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    # Admin được quyền đổi người phụ trách, User thì giữ nguyên
    if current_user.role == 'admin':
        assigned_user_ids = request.form.getlist('assigned_user_ids')
        users = list(db.users.find({"_id": {"$in": [ObjectId(uid) for uid in assigned_user_ids]}}))
        assigned_to_oids = [u["_id"] for u in users]
        assignees = [u.get("username", "user") for u in users]
    else:
        assigned_to_oids = t.get("assigned_to")
        assignees = t.get("assignees")

    upd = {
        "title": title,
        "department": department,
        "assigned_to": assigned_to_oids,
        "assignees": assignees,
        "due_at": due_at,
        "updated_at": now_dt(),
        "admin_request": None # Xóa trạng thái pending nếu có sau khi sửa
    }

    db.corp_tasks.update_one({"id": id}, {"$set": upd})
    flash("Cập nhật task thành công", "success")
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

# ✅ DELETE CORP TASK (Admin only)
@app.route('/corp-task/delete/<id>', methods=['POST'])
@login_required
def delete_corp_task(id):
    if current_user.role != "admin":
        return redirect(request.referrer or url_for("view_corp_tasks"))
    db.corp_tasks.delete_one({"id": id})
    return redirect(request.referrer or url_for("view_corp_tasks"))

@app.route('/corp-task/request-delete/<id>', methods=['POST'])
@login_required
def request_corp_delete(id):
    reason = request.form.get('reason', '')
    db.corp_tasks.update_one(
        {"id": id},
        {"$set": {
            "admin_request": "delete",
            "request_reason": reason,
            "request_by": current_user.username,
            "updated_at": now_dt()
        }}
    )
    flash("Đã gửi yêu cầu xóa task tới Admin", "info")
    return redirect(url_for('view_corp_tasks'))

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

    q3 = {"user_id": me, "notify_pending": True, "status": {"$ne": "Done"}}
    items3 = list(db.personal_tasks.find(q3).sort("created_at", -1).limit(5))

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
    
    def fmt_personal(x):
        due = x.get("due_at")
        return {
            "id": x.get("id"),
            "kind": "personal",
            "todo_content": x.get("title"),
            "customer_name": "",
            "assigned_by": "Self",
            "assigned_at": x.get("created_at").strftime("%d/%m %H:%M"),
            "due_at": due.strftime("%d/%m %H:%M") if due else ""
        }

    merged = [fmt_task(i) for i in items1] + [fmt_corp(i) for i in items2]
    merged = sorted(merged, key=lambda z: z.get("assigned_at", ""), reverse=True)[:15]
    merged = ([fmt_task(i) for i in items1] +[fmt_corp(i) for i in items2] +[fmt_personal(i) for i in items3])

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
    db.personal_tasks.update_many(
    {"id": {"$in": ids}, "user_id": me},
    {"$set": {"notify_pending": False, "updated_at": now}}
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

@app.route('/api/admin/corp-requests')
@login_required
def api_admin_corp_requests():
    if current_user.role != "admin":
        return jsonify({"items": []})
    
    # Tìm các task có yêu cầu từ user
    requests = list(db.corp_tasks.find({"admin_request": {"$ne": None}}))
    
    output = []
    for r in requests:
        output.append({
            "id": r.get("id"),
            "title": r.get("title"),
            "request_type": r.get("admin_request"),
            "reason": r.get("request_reason", ""),
            "user": r.get("request_by", "User")
        })
    return jsonify({"items": output})
# ---------------------------
# ✅ ADMIN: User Management (Admin access)
# ---------------------------
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    users = []
    for u in db.users.find():
        uo = User(u)
        uo.pending_tasks = db.tasks.count_documents({
            "assigned_to": ObjectId(u["_id"]),
            "status": {"$ne": "Done"}
        })
        users.append(uo)

    return render_template('user.html', users=users)

@app.route('/admin/user/detail/<user_id>')
@login_required
def admin_user_detail(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    uid = ObjectId(user_id)

    u = db.users.find_one({"_id": uid})
    if not u:
        return redirect(url_for('admin_users'))

    # =========================
    # CUSTOMER TASKS
    # =========================
    task_q = {"assigned_to": uid}

    stats_tasks = {
        "total": db.tasks.count_documents(task_q),
        "done": db.tasks.count_documents({**task_q, "status": "Done"}),
        "not_yet": db.tasks.count_documents({**task_q, "status": "Not_yet"}),
        "missed": db.tasks.count_documents({**task_q, "status": "Missed"}),
    }

    tasks = list(
        db.tasks.find(task_q).sort("updated_at", -1)
    )

    # =========================
    # PERSONAL TASKS
    # =========================
    ptask_q = {"user_id": uid}

    stats_personal = {
        "total": db.personal_tasks.count_documents(ptask_q),
        "done": db.personal_tasks.count_documents({**ptask_q, "status": "Done"}),
        "not_yet": db.personal_tasks.count_documents({**ptask_q, "status": "Not_yet"}),
        "missed": db.personal_tasks.count_documents({**ptask_q, "status": "Missed"}),
    }

    personal_tasks = list(
        db.personal_tasks.find(ptask_q).sort("updated_at", -1)
    )

    # =========================
    # COMPANY / CORP TASKS
    # =========================
    corp_q = {"assigned_to": {"$in": [uid]}}

    stats_corp = {
        "total": db.corp_tasks.count_documents(corp_q),
        "done": db.corp_tasks.count_documents({**corp_q, "status": "Done"}),
        # Corp task không có Missed – tất cả trạng thái chưa Done coi là Not yet
        "not_yet": db.corp_tasks.count_documents({
            **corp_q,
            "status": {"$nin": ["Done", "Cancelled"]}
        }),
        "missed": 0
    }

    corp_tasks = list(
        db.corp_tasks.find(corp_q).sort("updated_at", -1)
    )

    # =========================
    # MERGED STATS (ALL TASKS)
    # =========================
    stats = {
        "total": (
            stats_tasks["total"]
            + stats_personal["total"]
            + stats_corp["total"]
        ),
        "done": (
            stats_tasks["done"]
            + stats_personal["done"]
            + stats_corp["done"]
        ),
        "not_yet": (
            stats_tasks["not_yet"]
            + stats_personal["not_yet"]
            + stats_corp["not_yet"]
        ),
        "missed": (
            stats_tasks["missed"]
            + stats_personal["missed"]
        ),
    }

    task_breakdown = {
        "customer": stats_tasks,
        "personal": stats_personal,
        "corp": stats_corp
    }

    return render_template(
        'user_detail.html',
        staff=u,
        stats=stats,
        tasks=tasks,
        personal_tasks=personal_tasks,
        corp_tasks=corp_tasks,
        task_breakdown=task_breakdown
    )


@app.route('/admin/user/update_role/<user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    # prevent self role change if needed (optional)
    if ObjectId(user_id) == ObjectId(current_user.id):
        return redirect(url_for('admin_users'))

    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": request.form.get('role')}})
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    if ObjectId(user_id) != ObjectId(current_user.id):
        db.users.delete_one({"_id": ObjectId(user_id)})
    return redirect(url_for('admin_users'))

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

@app.route('/pancake/broadcast')
@login_required
def pancake_broadcast():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    sectors = ["Pod_Drop", "Express", "Warehouse"]
    return render_template('pancake_broadcast.html', sectors=sectors)

@app.route('/api/pancake/broadcast/leads')
@login_required
def api_pancake_broadcast_leads():
    sector = request.args.get('sector')

    q = {
        "source_platform": "Pancake"
    }
    if sector:
        q["sector"] = sector

    leads = list(db.leads.find(q, {
        "_id": 0,                     # ✅ FIX Ở ĐÂY
        "psid": 1,
        "full_name": 1,
        "page_id": 1,
        "page_username": 1,
        "conversation_id": 1,
        "sector": 1
    }).sort("updated_at", -1))

    return jsonify({"leads": leads})


@app.route('/api/pancake/upload', methods=['POST'])
@login_required
def pancake_upload():
    if current_user.role != 'admin':
        return jsonify({"error": "forbidden"}), 403

    file = request.files.get('file')
    page_id = request.form.get('page_id')

    if not file or not page_id:
        return jsonify({"error": "missing file or page_id"}), 400

    page = db.pages.find_one({"id": page_id})
    if not page or not page.get("access_token"):
        return jsonify({"error": "page token not found"}), 400

    service = PancakeService()
    content = service.upload_content(
        page_id=page_id,
        access_token=page["access_token"],
        file=file
    )

    return jsonify(content)

@app.route('/api/pancake/broadcast/send', methods=['POST'])
@login_required
def pancake_broadcast_send():
    if current_user.role != 'admin':
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json() or {}
    message = data.get("message")
    content_ids = data.get("content_ids", [])
    lead_ids = data.get("lead_ids", [])
    send_all = data.get("send_all", False)
    sector = data.get("sector")

    if not message and not content_ids:
        return jsonify({"error": "empty message"}), 400

    q = {
        "source_platform": "Pancake"
    }

    if not send_all:
        q["psid"] = {"$in": lead_ids}
    elif sector:
        q["sector"] = sector

    leads = list(db.leads.find(q))
    service = PancakeService()

    results = []

    for lead in leads:
        # 🚫 CHƯA TỪNG CHAT → KHÔNG GỬI ĐƯỢC
        if not lead.get("conversation_id"):
            results.append({
                "psid": lead["psid"],
                "status": "skipped",
                "reason": "no_conversation"
            })
            continue

        page = db.pages.find_one({
    "$or": [
        {"id": lead.get("page_id")},
        {"id": service._normalize_page_id(lead.get("page_id"))}
    ]
})

        if not page or not page.get("access_token"):
            results.append({
                "psid": lead["psid"],
                "status": "fail",
                "error": "missing_page_token"
            })
            continue

        try:
            service.send_message(
                page_id=lead["page_id"], 
                conversation_id=lead["conversation_id"],
                access_token=page["access_token"],
                message=message,
                content_ids=content_ids
            )
            results.append({
                "psid": lead["psid"],
                "status": "success"
            })
        except Exception as e:
            results.append({
                "psid": lead["psid"],
                "status": "fail",
                "error": str(e)
            })

    return jsonify({
        "total": len(results),
        "results": results
    })

@app.route('/secret')
@login_required
def secret_crm_page():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    return render_template('secret_crm.html')

@app.route('/api/secret/get-pages')
@login_required
def api_get_pancake_pages():
    # Logic lấy danh sách page từ ttest.py
    resp = requests.get(f"{BASE_URL}/pages", params={"access_token": PANCAKE_USER_TOKEN})
    if resp.status_code == 200:
        data = resp.json().get("pages", [])
        if not data:
            cat = resp.json().get("categorized", {})
            data = cat.get("activated", []) + cat.get("inactivated", [])
        return jsonify({"pages": data})
    return jsonify({"error": "Failed to fetch pages"}), resp.status_code

@app.route('/api/secret/get-conversations/<page_id>')
@login_required
def api_get_pancake_conversations(page_id):
    # 1. Tạo Page Access Token giống ttest.py
    t_res = requests.post(
        f"{BASE_URL}/pages/{page_id}/generate_page_access_token",
        params={"access_token": PANCAKE_USER_TOKEN, "page_id": page_id}
    )
    if t_res.status_code != 200:
        return jsonify({"error": "Failed to generate page token"}), 400
    
    page_token = t_res.json().get("page_access_token")
    
    # 2. Lấy hội thoại
    c_res = requests.get(
        f"{PUBLIC_V2}/pages/{page_id}/conversations",
        params={"page_access_token": page_token, "page_id": page_id, "type": "INBOX"}
    )
    if c_res.status_code == 200:
        return jsonify({
            "conversations": c_res.json().get("conversations", []),
            "page_token": page_token
        })
    return jsonify({"error": "Failed to fetch conversations"}), 400

@app.route('/api/secret/bulk-send', methods=['POST'])
@login_required
def api_secret_bulk_send():
    data = request.form
    page_id = data.get('page_id')
    page_token = data.get('page_token')
    message = data.get('message')
    conversation_ids = request.form.getlist('ids[]')
    image_file = request.files.get('image')

    content_ids = []
    # Logic upload ảnh từ ttest.py
    if image_file:
        files = {"file": (image_file.filename, image_file.read(), image_file.content_type)}
        u_res = requests.post(
            f"{PUBLIC_V1}/pages/{page_id}/upload_contents",
            params={"page_access_token": page_token},
            files=files
        )
        if u_res.status_code == 200:
            content_ids = [u_res.json().get("id")]

    success_count = 0
    # Logic gửi tin nhắn bulk
    for conv_id in conversation_ids:
        payload = {"action": "reply_inbox", "message": message}
        if content_ids:
            payload["content_ids"] = content_ids
            payload["attachment_type"] = "PHOTO"

        s_res = requests.post(
            f"{PUBLIC_V1}/pages/{page_id}/conversations/{conv_id}/messages",
            params={"page_access_token": page_token},
            json=payload
        )
        if s_res.status_code == 200:
            success_count += 1
        time.sleep(1) # Giãn cách để tránh lỗi 429

    return jsonify({"success": success_count, "total": len(conversation_ids)})


if __name__ == '__main__':
    if db.users.count_documents({"username": "admin"}) == 0:
        db.users.insert_one({
            "username": "admin",
            "password_hash": generate_password_hash('admin123'),
            "role": "admin",
            "created_at": now_dt()
        })

    init_pancake_pages(force_refresh=True)

    if not scheduler.running:
        scheduler.add_job(id='p_sync', func=pancake_sync_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_leads', func=sync_all_lark_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_tasks', func=sync_lark_tasks_task, trigger='interval', seconds=60)

        scheduler.add_job(id='auto_missed', func=auto_mark_missed_tasks, trigger='interval', seconds=60)
        scheduler.add_job(id='auto_missed_personal', func=auto_mark_personal_tasks, trigger='interval', seconds=60)


        scheduler.start()

    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
