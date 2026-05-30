# JapanTrip2026 Live Monitoring System

Project Overview
A web-based CCTV monitoring system built for COMP 012 — Network Administration.
Connects to physical IP cameras over a local network with secure login and activity logging.

Stack
- Frontend: HTML, CSS, JavaScript
- Backend: Node.js + Express
- Database: PostgreSQL (Supabase)
- Deployment: Render
- Version Control:** GitHub

Network Setup
- CCTV Camera → Switch → Router → Laptop
- Camera accessed via IP address on local network

Features
-  Secure login with bcrypt hashed passwords
- 3-attempt lockout system
- Activity logs (login/logout/failed attempts + IP address)
- Real-time camera feed (Webcam or IP Camera)
-  Terms & Conditions popup
-  Admin role-based access
-  PostgreSQL database (Supabase)
-  Cloud deployed on Render

Live URL
https://yunoball.onrender.com

 Setup Instructions
1. Clone the repo: `git clone https://github.com/rhqi56/yunoball.git`
2. Install dependencies: `npm install`
3. Set environment variables:
   - `SUPABASE_URL`
   - `SUPABASE_KEY`
4. Run locally: `node server.js`
5. Open: `http://localhost:3000`
 
Group Members
- Barrera, Joshua Anthony
- Entena, Rhaidel Prince 
- Magallon, Prince Aulric
- Sagasayan, Adrianne Symer

Section
BSIT 2-3