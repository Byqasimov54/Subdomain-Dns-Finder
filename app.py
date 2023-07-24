from flask import Flask, render_template, request, redirect, url_for
import dns.resolver
import concurrent.futures
import hashlib
import os
import sqlite3
import requests

app = Flask(__name__)

# DNS Resolver oluşturma ve çözümleme süresini 10 saniyeye ayarlama
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Farklı DNS sunucuları
resolver.lifetime = 10

record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
subdomain_array = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'blog', 'shop', 'test', 'admin']

def dns_enum(domain):
    results = {}
    for record_type in record_types:
        try:
            answer = resolver.resolve(domain, record_type)
            records = [server.to_text() for server in answer]
            results[record_type] = records
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            results['Error'] = f"{domain} does not exist."
            return results
        except KeyboardInterrupt:
            results['Error'] = 'Quitting.'
            return results

    return results

def subdomain_enum(domain):
    subdomains = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_subdomain = {executor.submit(resolve_subdomain, subdomain, domain): subdomain for subdomain in subdomain_array}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                result = future.result()
                if result:
                    subdomains[subdomain] = {'ip': result, 'cloudflare': is_cloudflare(result)}
            except Exception as exc:
                pass

    return subdomains

def resolve_subdomain(subdomain, domain):
    try:
        resolver.resolve(f'{subdomain}.{domain}', 'A')
        return f'{subdomain}.{domain}'
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None

def is_cloudflare(ip):
    url = f"https://api.cloudflare.com/client/v4/ips?ip={ip}"

    try:
        response = requests.get(url)
        data = response.json()

        if response.status_code == 200 and data.get('success', False):
            return data['result'] == 'cloudflare'
        else:
            return False
    except requests.RequestException:
        return False

# SQLite veritabanı oluşturma ve bağlantı
def create_connection():
    conn = sqlite3.connect('users.db')
    return conn

def create_table():
    conn = create_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

# Parolayı hashleme
def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + key

def verify_password(stored_password, provided_password):
    salt = stored_password[:32]
    stored_key = stored_password[32:]
    provided_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return stored_key == provided_key

def add_user(username, password):
    conn = create_connection()
    c = conn.cursor()
    hashed_password = hash_password(password)
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()

def find_user_by_username(username):
    conn = create_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()
    return user

# Uygulama başlatılırken tabloyu oluştur
create_table()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = find_user_by_username(username)

        if user and verify_password(user[2], password):
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        if password != confirm_password:
            error = 'Passwords do not match'
            return render_template('register.html', error=error)

        existing_user = find_user_by_username(username)

        if existing_user:
            error = 'Username already exists'
            return render_template('register.html', error=error)

        add_user(username, password)
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    # Burada kullanıcı oturumunu sonlandırma işlemleri yapabilirsiniz.
    # Örneğin, kullanıcının oturum bilgilerini silmek veya işaretleme yapmak.

    # Şimdilik basitçe login sayfasına yönlendirme yapalım:
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    return render_template('home.html')

@app.route('/dnsenum', methods=['POST'])
def dnsenum():
    domain = request.form['domain']
    results = dns_enum(domain)
    save_results_to_file(domain, results)  # Sonuçları dosyaya kaydet
    return render_template('dnsenum_result.html', domain=domain, results=results)

@app.route('/subdomenum', methods=['POST'])
def subdomenum():
    domain = request.form['domain']
    subdomains = subdomain_enum(domain)
    save_subdomains_to_file(domain, subdomains)  # Alt alan adlarını dosyaya kaydet
    return render_template('subdomenum_result.html', domain=domain, subdomains=subdomains)

def save_results_to_file(domain, results):
    file_name = f"{domain.replace('.', '_')}_dns_results.txt"
    with open(file_name, 'w') as file:
        file.write(f"DNS Enumeration Results for {domain}\n")
        if 'Error' in results:
            file.write(results['Error'])
        else:
            for record_type, records in results.items():
                file.write(f"{record_type} Records\n")
                for record in records:
                    file.write(f"{record}\n")

def save_subdomains_to_file(domain, subdomains):
    file_name = f"{domain.replace('.', '_')}_subdomain_results.txt"
    with open(file_name, 'w') as file:
        file.write(f"Subdomain Enumeration Results for {domain}\n")
        if subdomains:
            for subdomain, data in subdomains.items():
                file.write(f"{subdomain} (IP: {data['ip']}, Cloudflare: {'🌩' if data['cloudflare'] else '☁️'})\n")
        else:
            file.write("No subdomains found.")

if __name__ == '__main__':
    app.run(debug=True)
