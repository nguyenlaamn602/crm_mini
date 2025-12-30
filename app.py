from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_apscheduler import APScheduler
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import User 
from services.pancake import PancakeService
from datetime import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests, json, time, random, string

app = Flask(__name__)

# --- CONFIG ---
MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"
client = MongoClient(MONGO_URI)
db = client.CRM_Production
app.config['SECRET_KEY'] = 'crm_thg_ultimate_2025_secure_final_v5'

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = None 
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None

# LARK CONFIG
LARK_APP_ID, LARK_APP_SECRET = "cli_a87a40a3d6b85010", "wFMNBqGMhcuZsyNDZVAnYgOv6XuZyAqn"
LARK_APP_TOKEN, LARK_TABLE_ID = "Vqfqbm1Lda7vdVsvABQlk8KSgog", "tblEUCxBUVUUDt4R"
LARK_TASK_APP_TOKEN, LARK_TASK_TABLE_ID = "Ajhqblaj9aT34JsuQ8PlTi7xgZe", "tblKknj4Pp8HStO9"

scheduler = APScheduler()
LAST_SYNC_TIMESTAMP = time.time()

# --- UTILS & SYNC ---

def get_lark_token():
    url = "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal"
    try:
        res = requests.post(url, json={"app_id": LARK_APP_ID, "app_secret": LARK_APP_SECRET})
        return res.json().get("tenant_access_token")
    except Exception: return None

def classify_sector(fields):
    k = str(fields.get('Dịch vụ', '')).upper()
    if "POD" in k or "DROPSHIP" in k: return "Pod_Drop"
    elif "WAREHOUSE" in k: return "Warehouse"
    return "Express"

def init_pancake_pages():
    if db.pages.count_documents({}) == 0:
        service = PancakeService()
        for p in service.fetch_pages():
            p_id = str(p.get('id'))
            tk = service.get_token(p_id)
            if tk:
                # Xử lý username/slug để tạo link hội thoại đúng chuẩn
                p_username = p.get('username') or p.get('slug') or p_id
                if p.get('platform') == 'zalo' and not str(p_username).startswith('pzl_'):
                    p_username = f"pzl_{p_username}"
                elif p.get('platform') == 'telegram' and not str(p_username).startswith('tl_'):
                    p_username = f"tl_{p_username}"
                
                db.pages.update_one({"id": p_id}, {"$set": {"name": p.get('name'), "platform": p.get('platform'), "username": p_username, "access_token": tk}}, upsert=True)

def sync_all_lark_task():
    global LAST_SYNC_TIMESTAMP
    tk = get_lark_token()
    if not tk: return
    try:
        res = requests.get(f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_APP_TOKEN}/tables/{LARK_TABLE_ID}/records", headers={"Authorization": f"Bearer {tk}"}, params={"page_size": 500}).json()
        for item in res.get('data', {}).get('items', []):
            f = item.get('fields', {})
            db.leads.update_one({"psid": item.get('record_id')}, {"$set": {"full_name": f.get('Tên khách hàng'), "phone_number": f.get('Link FB/username tele'), "sector": classify_sector(f), "status": f.get('Trạng thái', 'Khách Mới'), "page_id": "LARK_AUTO", "source_platform": "Lark", "updated_at": datetime.now()}}, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception: pass

def sync_lark_tasks_task():
    global LAST_SYNC_TIMESTAMP
    tk = get_lark_token()
    if not tk: return
    try:
        res = requests.get(f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_TASK_APP_TOKEN}/tables/{LARK_TASK_TABLE_ID}/records", headers={"Authorization": f"Bearer {tk}"}).json()
        for item in res.get('data', {}).get('items', []):
            f = item.get('fields', {})
            assignee = f.get('Chịu trách nhiệm', [])[0].get('name', '---') if f.get('Chịu trách nhiệm') else '---'
            u_id = None
            lu = db.users.find_one({"username": assignee})
            if lu: u_id = lu['_id']
            db.tasks.update_one({"id": item.get('record_id')}, {"$set": {"todo_content": f.get('Nội Dung Todo', ''), "time_log": f.get('Time', ''), "status": f.get('Tình trạng', 'Not_yet'), "assignee": assignee, "assigned_to": u_id, "customer_name": f.get('Tên Nhóm Khách/Khách mới', ''), "updated_at": datetime.now()}}, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception: pass

def pancake_sync_task():
    global LAST_SYNC_TIMESTAMP
    service = PancakeService()
    try:
        for p_doc in db.pages.find():
            p_username = p_doc.get('username')
            for l in service.get_all_leads(p_doc['id'], p_doc['access_token']):
                db.leads.update_one({"psid": l['psid']}, {"$set": {
                    "full_name": l['name'], "phone_number": l['phone'], 
                    "sector": l['sector'], "status": l['status'], 
                    "page_id": p_doc['id'], "page_username": p_username, # Lưu username trang
                    "conversation_id": l['conversation_id'], # Lưu ID hội thoại chuẩn
                    "source_platform": "Pancake", "updated_at": datetime.now()}}, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception: pass

# --- ROUTES: AUTH ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        if db.users.find_one({"username": u}): flash('Username exists!', 'danger'); return redirect(url_for('register'))
        role = 'admin' if db.users.count_documents({}) == 0 else 'user'
        db.users.insert_one({"username": u, "password_hash": generate_password_hash(p), "role": role, "created_at": datetime.now()})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        user = db.users.find_one({"username": u})
        if user and check_password_hash(user['password_hash'], p): login_user(User(user)); return redirect(url_for('index'))
        flash('Tên đăng nhập hoặc mật khẩu không đúng', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    stats = {"pod_drop": db.leads.count_documents({"sector": "Pod_Drop"}), "express": db.leads.count_documents({"sector": "Express"}), "warehouse": db.leads.count_documents({"sector": "Warehouse"}), "total_staff": db.users.count_documents({})}
    return render_template('pages.html', stats=stats)

# --- ROUTES: CRM ---

@app.route('/sector/<name>')
@login_required
def view_sector(name):
    q = {"sector": name}
    search, status = request.args.get('search'), request.args.get('status')
    if search: q["full_name"] = {"$regex": search, "$options": "i"}
    if status: q["status"] = status
    leads = list(db.leads.find(q).sort("updated_at", -1))
    return render_template('leads.html', sector_name=name, sector_id=name, leads=leads)

@app.route('/customer/<psid>')
@login_required
def view_customer_detail(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead: return "Not Found", 404
    t_q, n_q = {"customer_psid": psid}, {"customer_psid": psid}
    if current_user.role != 'admin':
        t_q["$or"] = [{"user_id": ObjectId(current_user.id)}, {"assigned_to": ObjectId(current_user.id)}]
        n_q["user_id"] = ObjectId(current_user.id)
    tasks, notes = list(db.tasks.find(t_q).sort("created_at", -1)), list(db.notes.find(n_q).sort("created_at", -1))
    return render_template('customer.html', lead=lead, tasks=tasks, notes=notes)

@app.route('/customer/update/<psid>', methods=['POST'])
@login_required
def update_customer(psid):
    upd = {k: v for k, v in request.form.items() if v}
    upd['updated_at'] = datetime.now()
    db.leads.update_one({"psid": psid}, {"$set": upd})
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest': return jsonify({"status": "success"})
    return redirect(url_for('view_customer_detail', psid=psid))

@app.route('/customer/delete/<psid>', methods=['POST'])
@login_required
def delete_customer(psid):
    if current_user.role == 'admin': db.leads.delete_one({"psid": psid})
    return redirect(url_for('index'))

@app.route('/customer/note/add/<psid>', methods=['POST'])
@login_required
def add_customer_note(psid):
    c = request.form.get('content')
    if c: db.notes.insert_one({"content": c, "customer_psid": psid, "user_id": ObjectId(current_user.id), "created_at": datetime.now()})
    return redirect(url_for('view_customer_detail', psid=psid))

# --- ROUTES: TASKS & SEARCH/FILTER UPDATED ---

@app.route('/tasks')
@login_required
def view_tasks():
    # 1. Khởi tạo điều kiện phân quyền
    if current_user.role == 'admin':
        base_q = {}
    else:
        base_q = {"$or": [{"user_id": ObjectId(current_user.id)}, {"assigned_to": ObjectId(current_user.id)}]}
    
    # 2. Tiếp nhận các tham số Search và Status từ giao diện
    search = request.args.get('search')
    status = request.args.get('status')
    
    filter_q = {}
    if search:
        # Tìm kiếm đa trường: nội dung task, tên khách hàng hoặc tên assignee
        filter_q["$or"] = [
            {"todo_content": {"$regex": search, "$options": "i"}},
            {"customer_name": {"$regex": search, "$options": "i"}},
            {"assignee": {"$regex": search, "$options": "i"}}
        ]
    if status:
        filter_q["status"] = status
        
    # 3. Kết hợp điều kiện phân quyền và điều kiện lọc
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
    db.tasks.insert_one({"id": tid, "todo_content": request.form.get('todo_content'), "customer_name": request.form.get('customer_name'), "assignee": target['username'] if target else '---', "assigned_to": ObjectId(aid), "status": 'Not_yet', "user_id": ObjectId(current_user.id), "created_at": datetime.now(), "updated_at": datetime.now()})
    return redirect(url_for('view_tasks'))

@app.route('/customer/activity/add/<psid>', methods=['POST'])
@login_required
def add_customer_task(psid):
    lead = db.leads.find_one({"psid": psid})
    tid = 'act_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    db.tasks.insert_one({"id": tid, "todo_content": request.form.get('todo_content'), "customer_name": lead['full_name'], "customer_psid": psid, "assignee": request.form.get('assignee') or current_user.username, "assigned_to": ObjectId(current_user.id), "status": 'Not_yet', "created_at": datetime.now(), "updated_at": datetime.now()})
    return redirect(url_for('view_customer_detail', psid=psid))

@app.route('/task/update/<id>', methods=['POST'])
@login_required
def update_task(id):
    t = db.tasks.find_one({"id": id})
    if current_user.role != 'admin' and t.get('user_id') != ObjectId(current_user.id): return redirect(url_for('view_tasks'))
    upd = {"todo_content": request.form.get('todo_content'), "customer_name": request.form.get('customer_name'), "status": request.form.get('status'), "time_log": request.form.get('time_log'), "updated_at": datetime.now()}
    if current_user.role == 'admin' and request.form.get('assigned_user_id'):
        u = db.users.find_one({"_id": ObjectId(request.form.get('assigned_user_id'))})
        if u: upd["assigned_to"], upd["assignee"] = u["_id"], u["username"]
    db.tasks.update_one({"id": id}, {"$set": upd}); return redirect(url_for('view_tasks'))

@app.route('/task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_task(id):
    db.tasks.update_one({"id": id}, {"$set": {"status": request.form.get('status'), "updated_at": datetime.now()}})
    return jsonify({"status": "success"})

@app.route('/task/delete/<id>', methods=['POST'])
@login_required
def delete_task(id):
    t = db.tasks.find_one({"id": id})
    if t.get('user_id') == ObjectId(current_user.id) or current_user.role == 'admin': db.tasks.delete_one({"id": id})
    return redirect(url_for('view_tasks'))

# --- ROUTES: ADMIN ---

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin': return redirect(url_for('index'))
    users = []
    for u in db.users.find():
        uo = User(u)
        # SỬA LỖI DASHBOARD: Sử dụng ObjectId để đếm đúng mọi task chưa xong (kể cả Missed)
        uo.pending_tasks = db.tasks.count_documents({"assigned_to": ObjectId(u["_id"]), "status": {"$ne": "Done"}})
        users.append(uo)
    return render_template('user.html', users=users)

@app.route('/admin/user/detail/<user_id>')
@login_required
def admin_user_detail(user_id):
    u = db.users.find_one({"_id": ObjectId(user_id)})
    s = {"total": db.tasks.count_documents({"assigned_to": ObjectId(user_id)}),
         "done": db.tasks.count_documents({"assigned_to": ObjectId(user_id), "status": "Done"}),
         "not_yet": db.tasks.count_documents({"assigned_to": ObjectId(user_id), "status": "Not_yet"}),
         "missed": db.tasks.count_documents({"assigned_to": ObjectId(user_id), "status": "Missed"})}
    tasks = list(db.tasks.find({"assigned_to": ObjectId(user_id)}).sort("updated_at", -1))
    return render_template('user_detail.html', staff=u, stats=s, tasks=tasks)

@app.route('/admin/user/update_role/<user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": request.form.get('role')}}); return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if ObjectId(user_id) != ObjectId(current_user.id): db.users.delete_one({"_id": ObjectId(user_id)})
    return redirect(url_for('admin_users'))

# --- ROUTES: SYSTEM ---

@app.route('/sync-status')
@login_required
def sync_status(): return jsonify({"last_sync": LAST_SYNC_TIMESTAMP})

@app.route('/sync-now')
@login_required
def sync_now():
    init_pancake_pages(); pancake_sync_task(); sync_all_lark_task(); sync_lark_tasks_task()
    return redirect(request.referrer or url_for('index'))

@app.route('/webhook/lark', methods=['POST'])
def lark_webhook():
    d = request.json
    if d and "challenge" in d: return jsonify({"challenge": d["challenge"]})
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    if db.users.count_documents({"username": "admin"}) == 0:
        db.users.insert_one({"username": "admin", "password_hash": generate_password_hash('admin123'), "role": "admin", "created_at": datetime.now()})
    init_pancake_pages()
    if not scheduler.running:
        scheduler.add_job(id='p_sync', func=pancake_sync_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_leads', func=sync_all_lark_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_tasks', func=sync_lark_tasks_task, trigger='interval', seconds=60)
        scheduler.start()
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)