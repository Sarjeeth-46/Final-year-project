# Deployment Guide: AegisCore (SentinAI NetGuard)

This guide details the steps to deploy the application stack to a **Linux Virtual Machine** (Ubuntu 22.04 LTS recommended).

## 1. Infrastructure Preparation

### System Update
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv nodejs npm nginx git
```

### Database Setup (MongoDB)
For production, use MongoDB Atlas (Cloud) or install locally:
```bash
# Install MongoDB Community Edition (Ubuntu)
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-org

# Start Service
sudo systemctl start mongod
sudo systemctl enable mongod
```

---

## 2. Backend Deployment

### Setup Environment
```bash
# Clone or Copy project to /opt/aegis-core
sudo mkdir -p /opt/aegis-core
sudo chown -R $USER:$USER /opt/aegis-core
# (Upload files here)

cd /opt/aegis-core
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### Configure Variables
Create a `.env` file in `/opt/aegis-core`:
```env
MONGO_URI=mongodb://localhost:27017
SECRET_KEY=prod_secret_key_change_this
ALLOWED_ORIGINS=http://your-vm-ip
```

### Create System Service
Create `/etc/systemd/system/aegis-backend.service`:
```ini
[Unit]
Description=AegisCore API Service
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/aegis-core
ExecStart=/opt/aegis-core/.venv/bin/uvicorn backend.api_gateway:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

### Start Backend
```bash
sudo systemctl daemon-reload
sudo systemctl start aegis-backend
sudo systemctl enable aegis-backend
```

---

## 3. Frontend Deployment

### Build Static Assets
In your local development environment (or on the Server if it has enough RAM):
```bash
cd frontend
npm install
npm run build
# This creates the 'dist' folder
```

### Configure Nginx
Create `/etc/nginx/sites-available/aegis-core`:
```nginx
server {
    listen 80;
    server_name your-vm-ip-or-domain;

    # Frontend
    location / {
        root /opt/aegis-core/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Backend Proxy
    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Activate Site
```bash
sudo ln -s /etc/nginx/sites-available/aegis-core /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

---

## 4. Verification
1.  Navigate to `http://<VM-IP>`.
2.  Login with default credentials (`admin` / `admin`).
3.  Check that the status badge says **System Active**.
