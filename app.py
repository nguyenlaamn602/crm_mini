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

# --- MONGO CONFIGURATION ---
MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"
client = MongoClient(MONGO_URI)
db = client.CRM_Production

app.config['SECRET_KEY'] = 'crm_thg_ultimate_2025_secure_final_v5'

# --- 1. LOGIN MANAGER SETUP ---
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None

# --- LARK API CONFIGURATION ---
LARK_APP_ID = "cli_a87a40a3d6b85010" 
LARK_APP_SECRET = "wFMNBqGMhcuZsyNDZVAnYgOv6XuZyAqn" 
LARK_APP_TOKEN = "Vqfqbm1Lda7vdVsvABQlk8KSgog" 
LARK_TABLE_ID = "tblEUCxBUVUUDt4R" 
LARK_TASK_APP_TOKEN = "Ajhqblaj9aT34JsuQ8PlTi7xgZe" 
LARK_TASK_TABLE_ID = "tblKknj4Pp8HStO9"

scheduler = APScheduler()
LAST_SYNC_TIMESTAMP = time.time()

# --- 2. SYSTEM UTILITIES ---

def init_pancake_pages():
    if db.pages.count_documents({}) == 0:
        print("🚀 Initializing Fanpage list from Pancake...")
        service = PancakeService()
        pages_list = service.fetch_pages()
        for p in pages_list:
            p_id = str(p.get('id'))
            token = service.get_token(p_id)
            if token:
                db.pages.update_one({"id": p_id}, {"$set": {"name": p.get('name'), "platform": p.get('platform'), "access_token": token}}, upsert=True)
        print(f"✅ Loaded pages.")

def get_lark_token():
    url = "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal"
    payload = {"app_id": LARK_APP_ID, "app_secret": LARK_APP_SECRET}
    try:
        res = requests.post(url, json=payload)
        return res.json().get("tenant_access_token")
    except Exception as e:
        print(f"❌ Lark Token Error: {e}")
        return None

def fetch_lark_record(record_id):
    token = get_lark_token()
    if not token: return None
    url = f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_APP_TOKEN}/tables/{LARK_TABLE_ID}/records/{record_id}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        res = requests.get(url, headers=headers).json()
        return res.get('data', {}).get('record', {}).get('fields', {})
    except Exception as e:
        print(f"❌ Fetch Lark Record Error: {e}")
        return None

def classify_sector(fields):
    raw_kind = str(fields.get('Dịch vụ', '')).upper()
    if "POD" in raw_kind or "DROPSHIP" in raw_kind: return "Pod_Drop"
    elif "WAREHOUSE" in raw_kind: return "Warehouse"
    return "Express"

# --- 3. BACKGROUND SYNC TASKS ---

def sync_all_lark_task():
    global LAST_SYNC_TIMESTAMP
    token = get_lark_token()
    if not token: return
    url = f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_APP_TOKEN}/tables/{LARK_TABLE_ID}/records"
    try:
        res = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params={"page_size": 500}).json()
        items = res.get('data', {}).get('items', [])
        for item in items:
            record_id, fields = item.get('record_id'), item.get('fields', {})
            db.leads.update_one({"psid": record_id}, {"$set": {"full_name": fields.get('Tên khách hàng'), "phone_number": fields.get('Link FB/username tele'), "sector": classify_sector(fields), "status": fields.get('Trạng thái', 'Khách Mới'), "page_id": "LARK_AUTO", "source_platform": "Lark", "updated_at": datetime.now()}}, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception as e:
        print(f"❌ Lark Leads Sync Error: {e}")

def sync_lark_tasks_task():
    global LAST_SYNC_TIMESTAMP
    token = get_lark_token()
    if not token: return
    url = f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_TASK_APP_TOKEN}/tables/{LARK_TASK_TABLE_ID}/records"
    try:
        res = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params={"page_size": 100}).json()
        items = res.get('data', {}).get('items', [])
        for item in items:
            record_id, f = item.get('record_id'), item.get('fields', {})
            assignees = f.get('Chịu trách nhiệm', [])
            assignee_name = assignees[0].get('name', '---') if assignees else '---'
            user_id = None
            if assignee_name != '---':
                local_user = db.users.find_one({"username": assignee_name})
                if local_user: user_id = local_user['_id']
            db.tasks.update_one({"id": record_id}, {"$set": {"todo_content": f.get('Nội Dung Todo', ''), "time_log": f.get('Time', ''), "status": f.get('Tình trạng', 'Not_yet'), "assignee": assignee_name, "user_id": user_id, "customer_name": f.get('Tên Nhóm Khách/Khách mới', ''), "updated_at": datetime.now()}}, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception as e:
        print(f"❌ Lark Tasks Sync Error: {e}")

def pancake_sync_task():
    global LAST_SYNC_TIMESTAMP
    service = PancakeService()
    try:
        for page in db.pages.find():
            for l in service.get_all_leads(page['id'], page['access_token']):
                db.leads.update_one({"psid": l['psid']}, {"$set": {"full_name": l['name'], "phone_number": l['phone'], "sector": l['sector'], "status": l['status'], "page_id": page['id'], "source_platform": "Pancake", "updated_at": datetime.now()}}, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except Exception as e:
        print(f"❌ Pancake Sync Error: {e}")

# --- 4. AUTHENTICATION ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if db.users.find_one({"username": username}):
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        role = 'admin' if db.users.count_documents({}) == 0 else 'user'
        db.users.insert_one({"username": username, "password_hash": generate_password_hash(password), "role": role, "created_at": datetime.now()})
        flash('Account created! Please sign in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = db.users.find_one({"username": username})
        if user_data and check_password_hash(user_data['password_hash'], password):
            login_user(User(user_data))
            return redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- 5. INTERFACE & DASHBOARD ---

@app.route('/')
@login_required
def index():
    stats = {"pod_drop": db.leads.count_documents({"sector": "Pod_Drop"}),
             "express": db.leads.count_documents({"sector": "Express"}),
             "warehouse": db.leads.count_documents({"sector": "Warehouse"})}
    return render_template('pages.html', stats=stats)

@app.route('/sector/<name>')
@login_required
def view_sector(name):
    search_query = request.args.get('search', '')
    status_query = request.args.get('status', '')
    query = {"sector": name}
    if search_query: query["full_name"] = {"$regex": search_query, "$options": "i"}
    if status_query: query["status"] = status_query
    leads = list(db.leads.find(query).sort("updated_at", -1))
    return render_template('leads.html', sector_name=name.replace("_", " / "), sector_id=name, leads=leads)

@app.route('/customer/<psid>')
@login_required
def view_customer_detail(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead: return "Not Found", 404
    task_q = {"customer_psid": psid}
    note_q = {"customer_psid": psid}
    if current_user.role != 'admin':
        task_q["user_id"] = ObjectId(current_user.id)
        note_q["user_id"] = ObjectId(current_user.id)
    tasks = list(db.tasks.find(task_q).sort("created_at", -1))
    notes = list(db.notes.find(note_q).sort("created_at", -1))
    return render_template('customer.html', lead=lead, tasks=tasks, notes=notes)

# --- 6. TASK MANAGEMENT ---

@app.route('/tasks')
@login_required
def view_tasks():
    search_q = request.args.get('search', '')
    status_f = request.args.get('status', '')
    query = {} if current_user.role == 'admin' else {"user_id": ObjectId(current_user.id)}
    if search_q:
        query["$or"] = [{"todo_content": {"$regex": search_q, "$options": "i"}}, {"customer_name": {"$regex": search_q, "$options": "i"}}]
    if status_f: query["status"] = status_f
    tasks = list(db.tasks.find(query).sort("updated_at", -1))
    return render_template('tasks.html', tasks=tasks)

@app.route('/task/add', methods=['POST'])
@login_required
def add_task():
    task_id = 'man_task_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    db.tasks.insert_one({"id": task_id, "todo_content": request.form.get('todo_content'), "customer_name": request.form.get('customer_name'), "assignee": current_user.username, "status": 'Not_yet', "time_log": request.form.get('time_log'), "user_id": ObjectId(current_user.id), "created_at": datetime.now(), "updated_at": datetime.now()})
    return redirect(url_for('view_tasks'))

@app.route('/customer/activity/add/<psid>', methods=['POST'])
@login_required
def add_customer_task(psid):
    lead = db.leads.find_one({"psid": psid})
    task_id = 'task_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    db.tasks.insert_one({"id": task_id, "todo_content": request.form.get('todo_content'), "customer_name": lead['full_name'], "customer_psid": psid, "assignee": current_user.username, "status": 'Not_yet', "time_log": datetime.now().strftime('%d/%m %H:%M'), "user_id": ObjectId(current_user.id), "created_at": datetime.now(), "updated_at": datetime.now()})
    return redirect(url_for('view_customer_detail', psid=psid))

@app.route('/task/update/<id>', methods=['POST'])
@login_required
def update_task(id):
    task = db.tasks.find_one({"id": id})
    if current_user.role != 'admin' and task.get('user_id') != ObjectId(current_user.id):
        flash('Access Denied', 'danger'); return redirect(url_for('view_tasks'))
    db.tasks.update_one({"id": id}, {"$set": {"todo_content": request.form.get('todo_content'), "customer_name": request.form.get('customer_name'), "assignee": request.form.get('assignee') or task.get('assignee'), "status": request.form.get('status'), "time_log": request.form.get('time_log'), "updated_at": datetime.now()}})
    return redirect(url_for('view_tasks'))

# --- 7. CUSTOMER UPDATE & SYSTEM ROUTES ---

@app.route('/customer/update/<psid>', methods=['POST'])
@login_required
def update_customer(psid):
    upd = {}
    if request.form.get('full_name'): upd['full_name'] = request.form.get('full_name')
    if request.form.get('phone_number') is not None: upd['phone_number'] = request.form.get('phone_number')
    if request.form.get('sector'): upd['sector'] = request.form.get('sector')
    if request.form.get('status'): upd['status'] = request.form.get('status')
    upd['updated_at'] = datetime.now()
    db.leads.update_one({"psid": psid}, {"$set": upd})
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"status": "success", "updated_at": datetime.now().strftime('%H:%M:%S')})
    return redirect(url_for('view_customer_detail', psid=psid))

@app.route('/task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_task(id):
    task = db.tasks.find_one({"id": id})
    if current_user.role != 'admin' and task.get('user_id') != ObjectId(current_user.id):
        return jsonify({"status": "error", "message": "Access Denied"}), 403
    db.tasks.update_one({"id": id}, {"$set": {"status": request.form.get('status'), "updated_at": datetime.now()}})
    return jsonify({"status": "success", "new_status": request.form.get('status')})

@app.route('/customer/note/add/<psid>', methods=['POST'])
@login_required
def add_customer_note(psid):
    content = request.form.get('content')
    if content:
        db.notes.insert_one({"content": content, "customer_psid": psid, "user_id": ObjectId(current_user.id), "created_at": datetime.now()})
    return redirect(url_for('view_customer_detail', psid=psid))

@app.route('/customer/delete/<psid>', methods=['POST'])
@login_required
def delete_customer(psid):
    lead = db.leads.find_one({"psid": psid})
    sector = lead['sector']
    db.leads.delete_one({"psid": psid})
    return redirect(url_for('view_sector', name=sector))

@app.route('/task/delete/<id>', methods=['POST'])
@login_required
def delete_task(id):
    task = db.tasks.find_one({"id": id})
    if task.get('user_id') != ObjectId(current_user.id) and current_user.role != 'admin':
        flash('Access Denied', 'danger'); return redirect(url_for('view_tasks'))
    db.tasks.delete_one({"id": id})
    return redirect(url_for('view_tasks'))

# --- 8. ADMIN USER MANAGEMENT ---

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Permission denied!', 'danger'); return redirect(url_for('index'))
    users = [User(u) for u in db.users.find()]
    return render_template('user.html', users=users)

@app.route('/admin/user/update_role/<int:user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    # LƯU Ý: Vì MongoDB dùng _id (ObjectId), logic route nhận <int:user_id> của bạn cần đổi sang xử lý chuỗi
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    return redirect(url_for('admin_users'))

# --- 9. STARTUP & SCHEDULER ---

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
    data = request.json
    if data and "challenge" in data: return jsonify({"challenge": data["challenge"]})
    header = data.get('header', {})
    if header.get('event_type') == 'drive.file.bitable_record_changed_v1':
        for action in data.get('event', {}).get('action_configs', []):
            fields = fetch_lark_record(action.get('record_id'))
            if fields:
                db.leads.update_one({"psid": action.get('record_id')}, {"$set": {"full_name": fields.get('Tên khách hàng'), "sector": classify_sector(fields), "status": fields.get('Trạng thái'), "updated_at": datetime.now()}})
    return jsonify({"status": "ok"}), 200

def create_admin_account():
    if db.users.count_documents({"username": "admin"}) == 0:
        db.users.insert_one({"username": "admin", "password_hash": generate_password_hash('admin123'), "role": "admin", "created_at": datetime.now()})
        print("✅ Account created: admin / admin123")

if __name__ == '__main__':
    create_admin_account()
    init_pancake_pages()
    if not scheduler.running:
        scheduler.add_job(id='p_sync', func=pancake_sync_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_sync', func=sync_all_lark_task, trigger='interval', seconds=60)
        scheduler.add_job(id='t_sync', func=sync_lark_tasks_task, trigger='interval', seconds=60)
        scheduler.start()
    app.run(debug=True, use_reloader=False)