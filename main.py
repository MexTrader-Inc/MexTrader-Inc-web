from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, or_
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os

# ==========================================
# 1. CONFIGURACIÓN DE BASE DE DATOS Y SEGURIDAD
# ==========================================
DATABASE_URL = "sqlite:///./mextrader.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = "super_secreto_para_mextrader_cambialo_en_produccion"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# ==========================================
# 2. MODELOS DE BASE DE DATOS
# ==========================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=True)
    full_name = Column(String, nullable=True)
    balance = Column(Float, default=0.0) 
    plan = Column(String, default="BASIC")
    is_banned = Column(Boolean, default=False)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    symbol = Column(String)
    type = Column(String) 
    qty = Column(Float)
    price = Column(Float)
    date = Column(String)

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. ESQUEMAS PYDANTIC
# ==========================================
class RegisterRequest(BaseModel):
    username: str
    password: str
    full_name: str
    email: str

class LoginRequest(BaseModel):
    username: str
    password: str

class GoogleAuthRequest(BaseModel):
    token: str
    client_id: str

class OrderRequest(BaseModel):
    username: str
    symbol: str
    type: str
    qty: float
    price: float

class AdminActionRequest(BaseModel):
    admin_password: str
    target_username: str
    action: str
    value: str

# ==========================================
# 4. DEPENDENCIAS
# ==========================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    if user.is_banned:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Esta cuenta ha sido suspendida.")
    return user

# ==========================================
# 5. FASTAPI & ENDPOINTS
# ==========================================
app = FastAPI(title="MexTrader API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🖼️ NUEVO: Creamos la carpeta por seguridad y la montamos para las imágenes
if not os.path.exists("assets"):
    os.makedirs("assets")
app.mount("/assets", StaticFiles(directory="assets"), name="assets")

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    new_user = User(
        username=req.username, email=req.email, full_name=req.full_name,
        hashed_password=pwd_context.hash(req.password)
    )
    db.add(new_user)
    db.commit()
    return {"msg": "Usuario registrado exitosamente"}

@app.post("/api/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not user.hashed_password or not pwd_context.verify(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if user.is_banned:
        raise HTTPException(status_code=403, detail="Tu cuenta está baneada")

    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"username": user.username, "access_token": access_token, "plan": user.plan}

@app.post("/api/auth/google")
def auth_google(req: GoogleAuthRequest, db: Session = Depends(get_db)):
    try:
        idinfo = id_token.verify_oauth2_token(req.token, google_requests.Request(), req.client_id, clock_skew_in_seconds=60)
        email = idinfo['email']
        name = idinfo.get('name', '')
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(username=email, email=email, full_name=name, balance=0.0, plan="BASIC")
            db.add(user)
            db.commit()
            db.refresh(user)
            
        if user.is_banned:
            raise HTTPException(status_code=403, detail="Tu cuenta está baneada")
            
        access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"username": user.username, "access_token": access_token, "plan": user.plan}

    except Exception as e:
        print(f"❌ Error interno de Google Auth: {e}")
        raise HTTPException(status_code=401, detail=f"Error validando token: {e}")

@app.get("/api/profile")
def get_profile(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.username != username:
        raise HTTPException(status_code=403, detail="No tienes permisos")
    
    txs = db.query(Transaction).filter(Transaction.user_id == current_user.id).order_by(Transaction.id.desc()).limit(15).all()
    
    portfolio_calc = {}
    all_txs = db.query(Transaction).filter(Transaction.user_id == current_user.id).all()
    
    for t in all_txs:
        if t.symbol not in portfolio_calc:
            portfolio_calc[t.symbol] = {"qty": 0.0, "invested": 0.0}
        
        if "Compra" in t.type:
            portfolio_calc[t.symbol]["qty"] += t.qty
            portfolio_calc[t.symbol]["invested"] += (t.qty * t.price)
        elif "Venta" in t.type:
            portfolio_calc[t.symbol]["qty"] -= t.qty
            portfolio_calc[t.symbol]["invested"] -= (t.qty * t.price)

    portfolio_list = []
    for sym, data in portfolio_calc.items():
        if abs(data["qty"]) > 0.00001: 
            avg_price = abs(data["invested"] / data["qty"]) if abs(data["qty"]) > 0 else 0
            portfolio_list.append({"symbol": sym, "qty": round(data["qty"], 4), "avg_price": round(avg_price, 2)})

    history_list = [{"symbol": t.symbol, "type": t.type, "qty": t.qty, "price": t.price} for t in txs]

    return {
        "balance": current_user.balance,
        "plan": current_user.plan,
        "portfolio": portfolio_list,
        "history": history_list
    }

@app.post("/api/order")
def process_order(req: OrderRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    costo_total = req.qty * req.price 
    
    if "Compra" in req.type:
        if current_user.balance < costo_total:
            raise HTTPException(status_code=400, detail="Saldo insuficiente para comprar.")
        current_user.balance -= costo_total
        
    elif "Venta" in req.type:
        txs = db.query(Transaction).filter(
            Transaction.user_id == current_user.id,
            Transaction.symbol == req.symbol
        ).all()
        
        activos_actuales = 0.0
        for t in txs:
            if "Compra" in t.type: activos_actuales += t.qty
            elif "Venta" in t.type: activos_actuales -= t.qty
            
        if activos_actuales < req.qty:
            raise HTTPException(status_code=400, detail=f"No tienes suficientes {req.symbol} para vender.")
            
        current_user.balance += costo_total
    
    new_tx = Transaction(
        user_id=current_user.id,
        symbol=req.symbol,
        type=req.type,
        qty=req.qty,
        price=req.price,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.add(new_tx)
    db.commit()
    return {"msg": "Orden procesada con éxito", "nuevo_saldo": current_user.balance}

@app.post("/api/admin/action")
def admin_action(req: AdminActionRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if req.admin_password != "admin123":
        raise HTTPException(status_code=403, detail="Contraseña maestra incorrecta")
        
    target_user = db.query(User).filter(or_(User.username == req.target_username, User.email == req.target_username)).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Usuario afectado no encontrado")
        
    try:
        if req.action == "deposit":
            target_user.balance += float(req.value)
            msg = f"Se añadieron ${req.value} MXN a {target_user.username}"
        elif req.action == "deduct":
            target_user.balance -= float(req.value)
            msg = f"Se descontaron ${req.value} MXN a {target_user.username}"
        elif req.action == "upgrade":
            target_user.plan = req.value.upper()
            msg = f"Plan de {target_user.username} actualizado a {req.value.upper()}"
        elif req.action == "ban":
            target_user.is_banned = True
            msg = f"El usuario {target_user.username} ha sido baneado"
        elif req.action == "unban":
            target_user.is_banned = False
            msg = f"El usuario {target_user.username} ha sido desbaneado"
        else:
            raise HTTPException(status_code=400, detail="Acción no reconocida")
            
        db.commit()
        return {"msg": msg}
        
    except ValueError:
        raise HTTPException(status_code=400, detail="El valor ingresado no es numérico válido")