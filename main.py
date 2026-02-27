from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from pydantic import BaseModel, EmailStr, Field
from fastapi.middleware.cors import CORSMiddleware
import pymysql
import pymysql.cursors
import os
from dotenv import load_dotenv
import hashlib
import secrets
import random
from typing import List, Optional
from datetime import datetime, date
from urllib.parse import quote
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI(title="Splash Shine API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_WHATSAPP = "918137070424"
otp_store = {}

def get_db():
    try:
        conn = pymysql.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT", 3307)),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=10
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(32)
    iterations = 100000
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${pwd_hash.hex()}"

def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        alg, iterations, salt, hash_hex = stored_hash.split("$")
        new_hash = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt.encode(), int(iterations))
        return secrets.compare_digest(new_hash.hex(), hash_hex)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def is_email_blocked(cursor, email: str) -> bool:
    try:
        cursor.execute("SHOW TABLES LIKE 'deleted_users'")
        if not cursor.fetchone():
            return False
        cursor.execute("SELECT id FROM deleted_users WHERE email = %s", (email,))
        return cursor.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking blocked email: {e}")
        return False

class Register(BaseModel):
    name: str = Field(..., min_length=2)
    email: EmailStr
    mobile: str = Field(..., min_length=10)
    password: str = Field(..., min_length=8)

class Login(BaseModel):
    email: EmailStr
    password: str

class Booking(BaseModel):
    customer_name: str
    mobile: str
    address: str
    booking_date: date
    cleaning_type: str
    type_of_service: Optional[str] = None
    amc_frequency: Optional[str] = None
    price_per_hour: float
    hours: float
    total_price: float
    services: List[str]
    category: Optional[str] = None

class AdminRegister(BaseModel):
    name: str = Field(..., min_length=2)
    email: EmailStr
    password: str = Field(..., min_length=6)

class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class PaymentStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected|pending)$")

class DuePaymentStatusUpdate(BaseModel):
    due_payment_status: str = Field(..., pattern="^(pending|paid)$")

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    otp: str
    new_password: str = Field(..., min_length=8)


@app.get("/init-db")
def initialize_database():
    db = None
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            mobile VARCHAR(20) NOT NULL,
            password VARCHAR(500) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS admin (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(500) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS bookings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            customer_name VARCHAR(255) NOT NULL,
            mobile VARCHAR(20) NOT NULL,
            address TEXT NOT NULL,
            booking_date DATE NOT NULL,
            cleaning_type VARCHAR(50) NOT NULL,
            type_of_service VARCHAR(50),
            amc_frequency VARCHAR(50),
            price_per_hour DECIMAL(10,2) NOT NULL,
            hours DECIMAL(10,2) NOT NULL,
            total_price DECIMAL(10,2) NOT NULL,
            services TEXT NOT NULL,
            category VARCHAR(50),
            due_payment_status VARCHAR(20) DEFAULT 'pending',
            booking_status VARCHAR(20) DEFAULT 'pending',
            completed_at TIMESTAMP NULL,
            notes TEXT,
            assigned_worker VARCHAR(100),
            rating INT,
            feedback TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS payments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            booking_id VARCHAR(50) NOT NULL,
            payment_method VARCHAR(50) NOT NULL,
            transaction_id VARCHAR(100) UNIQUE NOT NULL,
            customer_upi_id VARCHAR(100),
            amount DECIMAL(10,2) NOT NULL,
            screenshot TEXT,
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS deleted_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255),
            deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        db.commit()

        tables = ['users', 'admin', 'bookings', 'payments', 'deleted_users']
        counts = {}
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
            counts[table] = cursor.fetchone()['cnt']

        return {"message": "Database initialized successfully", "tables_created": tables, "record_counts": counts}

    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Database initialization failed: {str(e)}")
    finally:
        if db: db.close()


@app.get("/test-db")
def test_database():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1 as result")
        result = cursor.fetchone()
        db.close()
        return {"status": "success", "message": "Database connected successfully"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/register")
def register_user(data: Register):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()

        if is_email_blocked(cursor, data.email):
            raise HTTPException(status_code=403, detail="This email has been blocked.")

        cursor.execute("SELECT id FROM users WHERE email=%s", (data.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")

        hashed = hash_password(data.password)
        cursor.execute("INSERT INTO users (name, email, mobile, password) VALUES (%s,%s,%s,%s)",
                       (data.name, data.email, data.mobile, hashed))
        db.commit()
        return {"message": "Registration successful", "user_id": cursor.lastrowid}

    except HTTPException: raise
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    finally:
        if db: db.close()


@app.post("/login")
def login_user(data: Login):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()

        if is_email_blocked(cursor, data.email):
            raise HTTPException(status_code=403, detail="This account has been deleted.")

        cursor.execute("SELECT * FROM users WHERE email=%s", (data.email,))
        user = cursor.fetchone()

        if not user or not verify_password(data.password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        return {"message": "Login successful", "user_id": user["id"], "name": user["name"], "email": user["email"]}

    except HTTPException: raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")
    finally:
        if db: db.close()


@app.post("/forgot-password")
def forgot_password(data: ForgotPassword):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()

        if is_email_blocked(cursor, data.email):
            raise HTTPException(status_code=403, detail="This account has been deleted.")

        cursor.execute("SELECT id FROM users WHERE email=%s", (data.email,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="No account found with this email.")

        generated_otp = str(random.randint(100000, 999999))
        otp_store[data.email] = generated_otp

        return {"message": "OTP generated successfully", "email": data.email, "otp": generated_otp}

    except HTTPException: raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate OTP: {str(e)}")
    finally:
        if db: db.close()


@app.post("/reset-password")
def reset_password(data: ResetPassword):
    db = None
    try:
        stored_otp = otp_store.get(data.email)
        if not stored_otp:
            raise HTTPException(status_code=400, detail="OTP expired. Please request a new OTP.")
        if str(data.otp).strip() != str(stored_otp).strip():
            raise HTTPException(status_code=400, detail="Invalid OTP.")

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT id FROM users WHERE email=%s", (data.email,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found.")

        hashed = hash_password(data.new_password)
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed, data.email))
        db.commit()
        otp_store.pop(data.email, None)

        return {"message": "Password reset successfully."}

    except HTTPException: raise
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to reset password: {str(e)}")
    finally:
        if db: db.close()


@app.post("/book")
def create_booking(data: Booking):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        services_text = ", ".join(data.services)

        cursor.execute("""INSERT INTO bookings (
            customer_name, mobile, address, booking_date, cleaning_type,
            type_of_service, amc_frequency, price_per_hour, hours,
            total_price, services, category
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (data.customer_name, data.mobile, data.address, data.booking_date,
         data.cleaning_type, data.type_of_service, data.amc_frequency,
         data.price_per_hour, data.hours, data.total_price, services_text, data.category))

        db.commit()
        booking_id = cursor.lastrowid

        return {
            "message": "Booking successful", "booking_id": f"BK{booking_id}",
            "customer_name": data.customer_name, "mobile": data.mobile,
            "cleaning_type": data.cleaning_type, "booking_date": str(data.booking_date),
            "hours": data.hours, "total_price": data.total_price
        }

    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Booking failed: {str(e)}")
    finally:
        if db: db.close()


@app.post("/confirm-payment")
async def confirm_payment(
    booking_id: str = Form(...), payment_method: str = Form(...),
    amount: float = Form(...), customer_upi_id: str = Form(None)
):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        auto_transaction_id = f"TXN{booking_id}_{timestamp}"

        cursor.execute("""INSERT INTO payments (
            booking_id, payment_method, transaction_id, customer_upi_id, amount, screenshot, status
        ) VALUES (%s,%s,%s,%s,%s,%s,'approved')""",
        (booking_id, payment_method, auto_transaction_id, customer_upi_id, amount, None))

        db.commit()
        return {
            "success": True, "message": "Payment confirmed successfully",
            "payment_id": cursor.lastrowid, "booking_id": booking_id,
            "transaction_id": auto_transaction_id, "status": "approved", "amount": amount
        }

    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Payment failed: {str(e)}")
    finally:
        if db: db.close()


@app.post("/send-whatsapp-invoice")
async def send_whatsapp_invoice(
    pdf: UploadFile = File(...), customer_mobile: str = Form(...),
    customer_name: str = Form(...), booking_id: str = Form(...), amount: str = Form(...)
):
    try:
        clean_mobile = ''.join(filter(str.isdigit, customer_mobile))
        if not clean_mobile.startswith('91'):
            clean_mobile = '91' + clean_mobile

        INVOICE_DIR = "invoices"
        os.makedirs(INVOICE_DIR, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        pdf_path = os.path.join(INVOICE_DIR, f"invoice_{booking_id}_{timestamp}.pdf")

        with open(pdf_path, "wb") as buffer:
            buffer.write(await pdf.read())

        message = f"🧼 *SPLASH SHINE SOLUTION*\n\nDear {customer_name},\n\nThank you for your payment of ₹{amount}! ✅\n\n📄 Invoice for Booking #{booking_id}\n\n📞 Contact: 8137070424\n📧 Email: info@splashshine.com"
        whatsapp_url = f"https://wa.me/{clean_mobile}?text={quote(message)}"

        return {"success": True, "message": "Invoice saved successfully", "pdf_path": pdf_path, "whatsapp_url": whatsapp_url}
    except Exception as e:
        return {"success": False, "message": str(e)}


@app.get("/booking/{booking_id}")
def get_booking(booking_id: str):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        numeric_id = booking_id.replace("BK", "")
        cursor.execute("SELECT * FROM bookings WHERE id=%s OR CONCAT('BK', id)=%s", (numeric_id, booking_id))
        booking = cursor.fetchone()
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        cursor.execute("SELECT * FROM payments WHERE booking_id=%s", (booking_id,))
        return {"booking": booking, "payments": cursor.fetchall()}
    except HTTPException: raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch booking: {str(e)}")
    finally:
        if db: db.close()


@app.post("/admin/register")
def register_admin(data: AdminRegister):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM admin WHERE email=%s", (data.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Admin email already registered")
        hashed = hash_password(data.password)
        cursor.execute("INSERT INTO admin (name, email, password) VALUES (%s,%s,%s)", (data.name, data.email, hashed))
        db.commit()
        return {"message": "Admin registered successfully", "admin_id": cursor.lastrowid}
    except HTTPException: raise
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Admin registration failed: {str(e)}")
    finally:
        if db: db.close()


@app.post("/admin/login")
def admin_login(data: AdminLogin):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admin WHERE email=%s", (data.email,))
        admin = cursor.fetchone()
        if not admin or not verify_password(data.password, admin["password"]):
            raise HTTPException(status_code=401, detail="Invalid admin credentials")
        return {"message": "Admin login successful", "admin_id": admin["id"], "name": admin["name"], "email": admin["email"]}
    except HTTPException: raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Admin login failed: {str(e)}")
    finally:
        if db: db.close()


@app.get("/admin/users")
def get_all_users():
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, name, email, mobile, created_at FROM users ORDER BY id DESC")
        users = cursor.fetchall()
        return {"users": users, "total": len(users)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch users: {str(e)}")
    finally:
        if db: db.close()


@app.get("/admin/bookings")
def admin_get_all_bookings():
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT b.*, p.transaction_id, p.payment_method, p.status as payment_status
            FROM bookings b
            LEFT JOIN payments p ON p.booking_id = CONCAT('BK', b.id)
            ORDER BY b.id DESC
        """)
        bookings = cursor.fetchall()
        return {"bookings": bookings, "total": len(bookings)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch bookings: {str(e)}")
    finally:
        if db: db.close()


@app.get("/admin/payments")
def admin_get_payments():
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT p.*, b.customer_name, b.mobile, b.cleaning_type, b.hours,
                   b.total_price as booking_amount, b.due_payment_status
            FROM payments p
            LEFT JOIN bookings b ON p.booking_id = CONCAT('BK', b.id) OR p.booking_id = b.id
            ORDER BY p.id DESC
        """)
        return {"payments": cursor.fetchall(), "total": cursor.rowcount}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch payments: {str(e)}")
    finally:
        if db: db.close()


@app.put("/admin/payment/status/{payment_id}")
def update_payment_status(payment_id: int, data: PaymentStatusUpdate):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM payments WHERE id=%s", (payment_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Payment not found")
        cursor.execute("UPDATE payments SET status=%s, updated_at=NOW() WHERE id=%s", (data.status, payment_id))
        db.commit()
        return {"message": f"Payment status updated to {data.status}", "payment_id": payment_id}
    except HTTPException: raise
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update payment status: {str(e)}")
    finally:
        if db: db.close()


@app.put("/admin/bookings/{booking_id}/due-payment-status")
def update_due_payment_status(booking_id: int, data: DuePaymentStatusUpdate):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM bookings WHERE id=%s", (booking_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail=f"Booking {booking_id} not found")
        cursor.execute("UPDATE bookings SET due_payment_status=%s WHERE id=%s", (data.due_payment_status, booking_id))
        db.commit()
        return {"success": True, "message": f"Due payment status updated to {data.due_payment_status}", "booking_id": booking_id}
    except HTTPException: raise
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update due payment status: {str(e)}")
    finally:
        if db: db.close()


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        cursor.execute("INSERT IGNORE INTO deleted_users (email, name) VALUES (%s, %s)", (user["email"], user["name"]))
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        db.commit()
        return {"message": f"User '{user['name']}' deleted and blocked", "user_id": user_id, "blocked_email": user["email"]}
    except HTTPException: raise
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")
    finally:
        if db: db.close()


@app.delete("/admin/bookings/{booking_id}")
def delete_booking(booking_id: int):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM payments WHERE booking_id=%s OR booking_id=%s", (str(booking_id), f"BK{booking_id}"))
        cursor.execute("DELETE FROM bookings WHERE id=%s", (booking_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Booking not found")
        db.commit()
        return {"message": "Booking deleted successfully", "booking_id": booking_id}
    except HTTPException: raise
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete booking: {str(e)}")
    finally:
        if db: db.close()


@app.get("/")
def health_check():
    return {"status": "online", "message": "Splash Shine API is running", "version": "1.0.0", "timestamp": datetime.now().isoformat()}


@app.get("/check-db")
def check_database():
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SHOW TABLES")
        tables = [list(row.values())[0] for row in cursor.fetchall()]
        counts = {}
        for table in ['users', 'admin', 'bookings', 'payments', 'deleted_users']:
            if table in tables:
                cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
                counts[table] = cursor.fetchone()['cnt']
            else:
                counts[table] = 0
        return {"status": "connected", "database": os.getenv("DB_NAME"), "host": os.getenv("DB_HOST"), "tables": tables, "counts": counts}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if db: db.close()