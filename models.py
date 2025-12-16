# models.py (REPLACE FULL)
from datetime import date, datetime, time
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="staff")  # admin/staff
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Shift(db.Model):
    __tablename__ = "shifts"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    start_time = db.Column(db.Time, nullable=False)  # e.g. 09:00
    end_time = db.Column(db.Time, nullable=False)    # e.g. 17:00
    grace_in_min = db.Column(db.Integer, default=15)
    grace_out_min = db.Column(db.Integer, default=0)


class Employee(db.Model):
    __tablename__ = "employees"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True)
    dept = db.Column(db.String(80))
    is_active = db.Column(db.Boolean, default=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # ✅ THIS is what you were missing (so template can do r.user.email)
    user = db.relationship("User", backref=db.backref("employee", uselist=False))

    shift_id = db.Column(db.Integer, db.ForeignKey("shifts.id"))
    shift = db.relationship("Shift", backref="employees")


class Holiday(db.Model):
    __tablename__ = "holidays"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)


class LeaveRequest(db.Model):
    __tablename__ = "leave_requests"
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # leave/sick/wfh
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(255))
    status = db.Column(db.String(20), default="pending")  # pending/approved/rejected
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    employee = db.relationship("Employee", backref="leave_requests")


class Attendance(db.Model):
    __tablename__ = "attendance"
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=False)
    work_date = db.Column(db.Date, default=date.today, index=True)

    check_in = db.Column(db.DateTime)
    check_out = db.Column(db.DateTime)

    status = db.Column(db.String(20), default="present")  # present/late/leave/sick/wfh/absent
    note = db.Column(db.String(255))

    check_in_ip = db.Column(db.String(64))
    check_in_ua = db.Column(db.String(255))
    check_in_lat = db.Column(db.Float)
    check_in_lon = db.Column(db.Float)

    check_out_ip = db.Column(db.String(64))
    check_out_ua = db.Column(db.String(255))
    check_out_lat = db.Column(db.Float)
    check_out_lon = db.Column(db.Float)

    employee = db.relationship("Employee", backref="attendance_records")

    @property
    def duration_hours(self) -> float:
        if self.check_in and self.check_out:
            seconds = (self.check_out - self.check_in).total_seconds()
            return round(seconds / 3600.0, 2)
        return 0.0

class Office(db.Model):
    __tablename__ = "offices"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lon = db.Column(db.Float, nullable=False)
    radius_m = db.Column(db.Integer, default=150)
    is_active = db.Column(db.Boolean, default=True)