from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exception_handlers import RequestValidationError
from fastapi import status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
import sqlite3
from typing import Optional
from fpdf import FPDF
import os

app = FastAPI()
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"❌ Unhandled error: {exc}")
    print(f"❌ Error type: {type(exc).__name__}")
    import traceback
    print(f"❌ Stack trace: {traceback.format_exc()}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"Internal server error: {str(exc)}"}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    print(f"🔍 Validation error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "message": "Validation failed"}
    )

# CORS - More permissive for debugging
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins temporarily
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "your-very-secure-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# Keep original hardcoded user for backward compatibility
fake_users_db = {
    "seller1": {
        "username": "seller1",
        "hashed_password": pwd_context.hash("yourpassword")
    }
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    # Check hardcoded users first (backward compatibility)
    user = fake_users_db.get(username)
    if user and verify_password(password, user["hashed_password"]):
        return user
    
    # Check database users
    try:
        with get_users_db() as conn:
            row = conn.execute(
                "SELECT username, hashed_password FROM sellers WHERE username = ? AND is_active = 1", 
                (username,)
            ).fetchone()
            
            if row and verify_password(password, row[1]):
                return {"username": row[0], "hashed_password": row}
    except:
        pass
    
    return False

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # Check hardcoded users
    user = fake_users_db.get(username)
    if user:
        return user
    
    # Check database users
    try:
        with get_users_db() as conn:
            row = conn.execute(
                "SELECT username, hashed_password FROM sellers WHERE username = ? AND is_active = 1", 
                (username,)
            ).fetchone()
            if row:
                return {"username": row[0], "hashed_password": row}
    except:
        pass
    
    raise credentials_exception

def get_db():
    conn = sqlite3.connect("orders.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_users_db():
    conn = sqlite3.connect("users.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sellers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            hashed_password TEXT,
            email TEXT,
            created_at TEXT,
            is_active BOOLEAN DEFAULT 1,
            shop_name TEXT,
            shop_description TEXT,
            shop_address TEXT,
            shop_phone TEXT
        )
    """)
    return conn


@app.on_event("startup")
def startup():
    # Create invoices directory
    os.makedirs("invoices", exist_ok=True)
    
    # Initialize users database
    with get_users_db() as conn:
        # Add some sample shops for demonstration
        try:
            conn.execute(
                "INSERT OR IGNORE INTO sellers (username, hashed_password, email, created_at, shop_name, shop_description, shop_phone) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("pizzapalace", pwd_context.hash("pizza123"), "orders@pizzapalace.com", datetime.utcnow().isoformat(), "Pizza Palace", "Authentic Italian Pizza", "+1-555-PIZZA")
            )
            conn.execute(
                "INSERT OR IGNORE INTO sellers (username, hashed_password, email, created_at, shop_name, shop_description, shop_phone) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("burgerbarn", pwd_context.hash("burger123"), "orders@burgerbarn.com", datetime.utcnow().isoformat(), "Burger Barn", "Gourmet Burgers & Fries", "+1-555-BURGER")
            )
        except:
            pass
    
    # Initialize orders database
    with get_db() as conn:
        # Drop and recreate table to ensure correct schema
        conn.execute("DROP TABLE IF EXISTS orders")
        conn.execute("""
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT,
                customer TEXT,
                item TEXT,
                qty INTEGER,
                status TEXT DEFAULT 'received',
                invoice_path TEXT,
                price REAL DEFAULT 10.0,
                seller_username TEXT DEFAULT 'seller1',
                customer_phone TEXT,
                customer_address TEXT,
                customer_email TEXT,
                order_type TEXT DEFAULT 'manual'
            )
        """)
        
        # Add sample data for different shops
        sample_orders = [
            (datetime.utcnow().isoformat(), "John Doe", "Margherita Pizza", 2, "received", None, 25.50, "seller1", "+1234567890", "123 Main St", "john@email.com", "online"),
            (datetime.utcnow().isoformat(), "Jane Smith", "Classic Burger", 1, "completed", None, 12.99, "pizzapalace", "+1234567891", "456 Oak Ave", "jane@email.com", "online"),
            (datetime.utcnow().isoformat(), "Bob Wilson", "BBQ Burger Combo", 3, "out_for_delivery", None, 45.00, "burgerbarn", "+1234567892", "789 Pine Rd", "bob@email.com", "online"),
            ((datetime.utcnow() - timedelta(days=1)).isoformat(), "Alice Johnson", "Pepperoni Pizza", 1, "delivered", None, 18.50, "pizzapalace", "+1234567893", "321 Elm St", "alice@email.com", "online"),
            ((datetime.utcnow() - timedelta(days=2)).isoformat(), "Mike Brown", "Veggie Burger", 2, "delivered", None, 22.00, "burgerbarn", "+1234567894", "654 Maple Ave", "mike@email.com", "online"),
        ]
        conn.executemany(
            "INSERT INTO orders (created_at, customer, item, qty, status, invoice_path, price, seller_username, customer_phone, customer_address, customer_email, order_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            sample_orders
        )

class StatusUpdateRequest(BaseModel):
    order_id: int
    status: str

class CreateOrderRequest(BaseModel):
    customer: str
    item: str
    qty: int
    price: float

class UserRegistration(BaseModel):
    username: str
    password: str
    email: str = None
    shop_name: str = None
    shop_description: str = None
    shop_phone: str = None

# Customer Order Model with shop selection
class CustomerOrder(BaseModel):
    customer_name: str
    customer_phone: str
    customer_address: str = None
    customer_email: str = None
    items: list
    total_price: float
    order_type: str = 'online'
    shop_id: str  # Which shop customer is ordering from

class InvoicePDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 20)
        self.cell(0, 15, 'INVOICE', 0, 1, 'C')
        self.ln(5)
        
        # Company info
        self.set_font('Arial', 'B', 12)
        self.cell(0, 8, 'Order Management Company', 0, 1)
        self.set_font('Arial', '', 10)
        self.cell(0, 6, '123 Business Street, City, State 12345', 0, 1)
        self.cell(0, 6, 'Phone: (555) 123-4567 | Email: orders@company.com', 0, 1)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()} | Thank you for your business!', 0, 0, 'C')

def generate_invoice_pdf(order):
    pdf = InvoicePDF()
    pdf.add_page()
    
    # Invoice details
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, f'Invoice #{order["id"]:04d}', 0, 1)
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 8, f'Date: {datetime.fromisoformat(order["created_at"]).strftime("%B %d, %Y")}', 0, 1)
    pdf.ln(5)
    
    # Customer info
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, 'Bill To:', 0, 1)
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 8, order['customer'], 0, 1)
    pdf.ln(10)
    
    # Table header
    pdf.set_font('Arial', 'B', 11)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(80, 10, 'Item Description', 1, 0, 'C', True)
    pdf.cell(30, 10, 'Quantity', 1, 0, 'C', True)
    pdf.cell(30, 10, 'Unit Price', 1, 0, 'C', True)
    pdf.cell(30, 10, 'Total', 1, 1, 'C', True)
    
    # Table content
    pdf.set_font('Arial', '', 10)
    unit_price = order['price'] / order['qty']
    total = order['price']
    
    pdf.cell(80, 10, order['item'], 1, 0)
    pdf.cell(30, 10, str(order['qty']), 1, 0, 'C')
    pdf.cell(30, 10, f'${unit_price:.2f}', 1, 0, 'C')
    pdf.cell(30, 10, f'${total:.2f}', 1, 1, 'C')
    
    # Total section
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(140, 10, '', 0, 0)
    pdf.cell(30, 10, 'TOTAL:', 1, 0, 'R')
    pdf.cell(30, 10, f'${total:.2f}', 1, 1, 'C')
    
    # Payment info
    pdf.ln(10)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 8, 'Payment Status: PAID', 0, 1)
    pdf.cell(0, 8, 'Payment Method: Cash on Delivery', 0, 1)
    
    return pdf

# 🆕 NEW: Get available shops for customers
@app.get("/public/shops")
async def get_shops():
    """Public endpoint to get list of available shops"""
    try:
        shops = []
        
        # Add hardcoded seller1
        shops.append({
            "shop_id": "seller1", 
            "shop_name": "Main Restaurant", 
            "description": "Our flagship restaurant",
            "contact": "orders@restaurant.com",
            "phone": "+1-555-MAIN"
        })
        
        # Get active sellers from database
        with get_users_db() as conn:
            rows = conn.execute(
                "SELECT username, email, shop_name, shop_description, shop_phone FROM sellers WHERE is_active = 1"
            ).fetchall()
            
            for row in rows:
                shops.append({
                    "shop_id": row[0],
                    "shop_name": row or row.title(),
                    "description": row or f"Great food from {row}",
                    "contact": row or f"{row}@restaurant.com",
                    "phone": row or "+1-555-FOOD"
                })
        
        return shops
        
    except Exception as e:
        print(f"Error fetching shops: {e}")
        # Fallback shop list
        return [
            {
                "shop_id": "seller1", 
                "shop_name": "Main Restaurant", 
                "description": "Our flagship restaurant",
                "contact": "orders@restaurant.com",
                "phone": "+1-555-MAIN"
            }
        ]

@app.post("/auth/register")
async def register_seller(user: UserRegistration):
    """Allow new sellers to register"""
    # Validate username
    if len(user.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    # Hash password
    hashed_password = pwd_context.hash(user.password)
    
    try:
        with get_users_db() as conn:
            conn.execute(
                "INSERT INTO sellers (username, hashed_password, email, created_at, shop_name, shop_description, shop_phone) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user.username, hashed_password, user.email, datetime.utcnow().isoformat(), 
                 user.shop_name or user.username.title(), user.shop_description, user.shop_phone)
            )
        return {"message": f"Shop {user.shop_name or user.username} registered successfully! You can now login."}
    
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Shop name already exists")

@app.post("/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/orders")
async def get_orders(
    status: Optional[str] = Query(None),
    customer: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    query = "SELECT id, created_at, customer, item, qty, status, invoice_path, price, seller_username, customer_phone, customer_address, customer_email, order_type FROM orders"
    conditions = ["seller_username = ?"]  # Only show orders for current seller
    params = [current_user["username"]]

    if status:
        conditions.append("status = ?")
        params.append(status)
    if customer:
        conditions.append("customer LIKE ?")
        params.append(f"%{customer}%")
    if start_date:
        conditions.append("date(created_at) >= date(?)")
        params.append(start_date)
    if end_date:
        conditions.append("date(created_at) <= date(?)")
        params.append(end_date)

    query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]

@app.post("/orders/update-status")
async def update_order_status(req: StatusUpdateRequest, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        # Check if order belongs to current user
        order_check = conn.execute(
            "SELECT seller_username FROM orders WHERE id = ?", (req.order_id,)
        ).fetchone()
        
        if not order_check or order_check[0] != current_user["username"]:
            raise HTTPException(status_code=404, detail="Order not found")
        
        # Update status
        conn.execute("UPDATE orders SET status = ? WHERE id = ?", (req.status, req.order_id))

        # Generate invoice PDF if delivered
        if req.status == "delivered":
            order = conn.execute("SELECT * FROM orders WHERE id = ?", (req.order_id,)).fetchone()
            if order:
                pdf = generate_invoice_pdf(order)
                pdf_filename = f"invoice_{req.order_id:04d}.pdf"
                pdf_path = f"invoices/{pdf_filename}"
                
                # Save the PDF
                pdf.output(pdf_path)
                
                # Update database with invoice path
                conn.execute("UPDATE orders SET invoice_path = ? WHERE id = ?", (pdf_path, req.order_id))

        return {"message": "Order status updated successfully"}

@app.post("/orders/create")
async def create_order(req: CreateOrderRequest, current_user: dict = Depends(get_current_user)):
    try:
        print(f"Creating order for {current_user['username']}: {req}")
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO orders (created_at, customer, item, qty, status, price, seller_username) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), req.customer, req.item, req.qty, "received", req.price, current_user["username"])
            )
            order_id = cursor.lastrowid
        return {"message": "Order created successfully", "order_id": order_id}
    except Exception as e:
        print(f"Error creating order: {e}")
        raise HTTPException(status_code=500, detail=f"Error creating order: {str(e)}")

# 🆕 UPDATED: Customer Order Endpoint with shop selection
@app.post("/public/orders/create")
async def create_customer_order(order_data: CustomerOrder):
    """Public endpoint for customers to place orders to specific shops"""
    try:
        print(f"Received customer order for shop '{order_data.shop_id}': {order_data}")
        
        # Validate shop exists
        valid_shops = ["seller1"]  # Always valid
        try:
            with get_users_db() as conn:
                shop_check = conn.execute(
                    "SELECT username FROM sellers WHERE username = ? AND is_active = 1", 
                    (order_data.shop_id,)
                ).fetchone()
                if shop_check:
                    valid_shops.append(shop_check[0])
        except:
            pass
        
        if order_data.shop_id not in valid_shops:
            raise HTTPException(status_code=400, detail="Invalid shop selected")
        
        # Calculate total
        calculated_total = sum(item['price'] * item['quantity'] for item in order_data.items)
        items_str = ", ".join([f"{item['quantity']}x {item['name']}" for item in order_data.items])
        
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO orders (
                    created_at, customer, item, qty, status, price, 
                    seller_username, customer_phone, customer_address, 
                    customer_email, order_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.utcnow().isoformat(),
                order_data.customer_name,
                items_str,
                sum(item['quantity'] for item in order_data.items),
                "received",
                calculated_total,
                order_data.shop_id,  # Order goes to selected shop
                order_data.customer_phone or "",
                order_data.customer_address or "",
                order_data.customer_email or "",
                order_data.order_type
            ))
            order_id = cursor.lastrowid
        
        return {
            "message": f"Order placed successfully with {order_data.shop_id}!",
            "order_id": order_id,
            "shop_id": order_data.shop_id,
            "estimated_delivery": "30-45 minutes"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating customer order: {e}")
        raise HTTPException(status_code=500, detail="Failed to place order")

@app.get("/invoices/{filename}")
async def download_invoice(filename: str, current_user: dict = Depends(get_current_user)):
    file_path = f"invoices/{filename}"
    if os.path.exists(file_path):
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='application/pdf'
        )
    raise HTTPException(status_code=404, detail="Invoice not found")
