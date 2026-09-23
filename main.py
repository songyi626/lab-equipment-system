import os
import hashlib
import hmac
from datetime import datetime, timedelta, date, time, timezone
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Table, and_
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
import jwt

# ================= 基本配置 =================
SECRET_KEY = "LAB_RESERVATION_SUPER_SECRET_KEY"
ALGORITHM = "HS256"
COOKIE_NAME = "lab_token"

DATABASE_URL = "sqlite:///./lab_reservation.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# ================= 密碼安全雜湊 =================
def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"{salt}${key.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        salt, key = hashed_password.split("$")
        new_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return hmac.compare_digest(key, new_key.hex())
    except Exception:
        return False

# ================= 資料庫模型 =================
user_equipment_permissions = Table(
    "user_equipment_permissions",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("equipment_id", Integer, ForeignKey("equipments.id"), primary_key=True)
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="USER")
    is_active = Column(Boolean, default=True)

    allowed_equipments = relationship(
        "Equipment", secondary=user_equipment_permissions, back_populates="authorized_users"
    )
    bookings = relationship("Booking", back_populates="user")

class Equipment(Base):
    __tablename__ = "equipments"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    location = Column(String, nullable=True)

    authorized_users = relationship(
        "User", secondary=user_equipment_permissions, back_populates="allowed_equipments"
    )
    bookings = relationship("Booking", back_populates="equipment")

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    equipment_id = Column(Integer, ForeignKey("equipments.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    purpose = Column(String, nullable=True)
    status = Column(String, default="CONFIRMED")

    equipment = relationship("Equipment", back_populates="bookings")
    user = relationship("User", back_populates="bookings")

Base.metadata.create_all(bind=engine)

# ================= 權限相依 =================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user_from_cookie(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except Exception:
        return None
    return db.query(User).filter(User.email == email).first()

def login_required(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user_from_cookie(request, db)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user

# ================= 網頁路由 =================
app = FastAPI(title="實驗室設備預約系統")

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 303 and "Location" in exc.headers:
        return RedirectResponse(url=exc.headers["Location"], status_code=303)
    return HTMLResponse(content=f"<h3>發生錯誤: {exc.detail}</h3><a href='/'>回首頁</a>", status_code=exc.status_code)

@app.get("/", response_class=HTMLResponse)
def index(user: Optional[User] = Depends(get_current_user_from_cookie)):
    if not user:
        return RedirectResponse(url="/login")
    return RedirectResponse(url="/calendar")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": error}
    )

@app.post("/login")
def login_post(
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return RedirectResponse(url="/login?error=帳號或密碼錯誤", status_code=303)

    token = jwt.encode(
        {"sub": user.email, "role": user.role, "exp": datetime.now(timezone.utc) + timedelta(days=1)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    res = RedirectResponse(url="/calendar", status_code=303)
    res.set_cookie(key=COOKIE_NAME, value=token, httponly=True)
    return res

@app.get("/logout")
def logout():
    res = RedirectResponse(url="/login", status_code=303)
    res.delete_cookie(COOKIE_NAME)
    return res

SLOTS = [
    ("08:00", "10:00"),
    ("10:00", "12:00"),
    ("12:00", "14:00"),
    ("14:00", "16:00"),
    ("16:00", "18:00"),
    ("18:00", "20:00"),
    ("20:00", "22:00")
]

@app.get("/calendar", response_class=HTMLResponse)
def calendar_view(
    request: Request,
    equipment_id: Optional[int] = None,
    week_offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    if current_user.role == "ADMIN":
        equipments = db.query(Equipment).all()
    else:
        equipments = current_user.allowed_equipments

    selected_equipment = None
    if equipments:
        if equipment_id:
            selected_equipment = next((e for e in equipments if e.id == equipment_id), equipments[0])
        else:
            selected_equipment = equipments[0]

    today = date.today()
    start_of_week = today - timedelta(days=today.weekday()) + timedelta(weeks=week_offset)
    week_dates = [start_of_week + timedelta(days=i) for i in range(7)]

    bookings_map = {}
    if selected_equipment:
        w_start_dt = datetime.combine(week_dates[0], time(0, 0))
        w_end_dt = datetime.combine(week_dates[-1], time(23, 59))
        bookings = db.query(Booking).filter(
            Booking.equipment_id == selected_equipment.id,
            Booking.status == "CONFIRMED",
            Booking.start_time >= w_start_dt,
            Booking.end_time <= w_end_dt
        ).all()

        for b in bookings:
            key = (b.start_time.strftime("%Y-%m-%d"), b.start_time.strftime("%H:%M"))
            bookings_map[key] = b

    return templates.TemplateResponse(
        request=request,
        name="calendar.html",
        context={
            "current_user": current_user,
            "equipments": equipments,
            "selected_equipment": selected_equipment,
            "week_dates": week_dates,
            "slots": SLOTS,
            "bookings_map": bookings_map,
            "week_offset": week_offset
        }
    )

@app.post("/book")
def make_booking(
    equipment_id: int = Form(...),
    date_str: str = Form(...),
    slot_idx: int = Form(...),
    purpose: str = Form(""),
    week_offset: int = Form(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    equip = db.query(Equipment).filter(Equipment.id == equipment_id).first()
    if current_user.role != "ADMIN" and equip not in current_user.allowed_equipments:
        raise HTTPException(status_code=403, detail="您沒有操作此設備的權限")

    start_str, end_str = SLOTS[slot_idx]
    start_dt = datetime.strptime(f"{date_str} {start_str}", "%Y-%m-%d %H:%M")
    end_dt = datetime.strptime(f"{date_str} {end_str}", "%Y-%m-%d %H:%M")

    conflict = db.query(Booking).filter(
        Booking.equipment_id == equipment_id,
        Booking.status == "CONFIRMED",
        and_(Booking.start_time < end_dt, Booking.end_time > start_dt)
    ).first()
    if conflict:
        return RedirectResponse(url=f"/calendar?equipment_id={equipment_id}&week_offset={week_offset}&error=該時段已被預約", status_code=303)

    new_booking = Booking(
        equipment_id=equipment_id,
        user_id=current_user.id,
        start_time=start_dt,
        end_time=end_dt,
        purpose=purpose
    )
    db.add(new_booking)
    db.commit()
    return RedirectResponse(url=f"/calendar?equipment_id={equipment_id}&week_offset={week_offset}", status_code=303)

@app.post("/cancel-booking")
def cancel_booking(
    booking_id: int = Form(...),
    equipment_id: int = Form(...),
    week_offset: int = Form(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    b = db.query(Booking).filter(Booking.id == booking_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="預約不存在")
    if current_user.role != "ADMIN" and b.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="您只能取消自己的預約")
    b.status = "CANCELLED"
    db.commit()
    return RedirectResponse(url=f"/calendar?equipment_id={equipment_id}&week_offset={week_offset}", status_code=303)

# ================= 管理員介面與路由 =================
@app.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="僅限管理員進入")
    users = db.query(User).all()
    equipments = db.query(Equipment).all()
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "current_user": current_user,
            "users": users,
            "equipments": equipments
        }
    )

@app.post("/admin/add-equipment")
def admin_add_equipment(
    name: str = Form(...),
    location: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="僅限管理員")
    eq = Equipment(name=name, location=location)
    db.add(eq)
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/delete-equipment")
def admin_delete_equipment(
    equipment_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    """[管理員] 刪除設備"""
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="僅限管理員")
    eq = db.query(Equipment).filter(Equipment.id == equipment_id).first()
    if eq:
        # 清除關聯預約與授權
        db.query(Booking).filter(Booking.equipment_id == equipment_id).delete()
        eq.authorized_users.clear()
        db.delete(eq)
        db.commit()
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/add-user")
def admin_add_user(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("USER"),
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="僅限管理員")
    new_u = User(
        name=name,
        email=email,
        hashed_password=hash_password(password),
        role=role
    )
    db.add(new_u)
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/grant-permission")
def admin_grant_perm(
    user_id: int = Form(...),
    equipment_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(login_required)
):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="僅限管理員")
    target_user = db.query(User).filter(User.id == user_id).first()
    equip = db.query(Equipment).filter(Equipment.id == equipment_id).first()
    if target_user and equip and equip not in target_user.allowed_equipments:
        target_user.allowed_equipments.append(equip)
        db.commit()
    return RedirectResponse(url="/admin", status_code=303)

@app.on_event("startup")
def init_data():
    db = SessionLocal()
    admin_email = "admin@lab.edu.tw"
    admin = db.query(User).filter(User.email == admin_email).first()
    if not admin:
        admin = User(
            email=admin_email,
            name="實驗室管理員",
            hashed_password=hash_password("Admin1234"),
            role="ADMIN"
        )
        db.add(admin)
        eq1 = Equipment(name="光激發螢光光譜儀 (PL)", location="儀器室 101")
        eq2 = Equipment(name="低溫電性/鎖相放大器量測系統", location="量測室 203")
        db.add_all([eq1, eq2])
        db.commit()
    db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)