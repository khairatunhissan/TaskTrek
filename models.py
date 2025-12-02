from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

ROLE_INSTRUCTOR = "instructor"
ROLE_STUDENT = "student"
ROLE_ADMIN = "admin"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default=ROLE_STUDENT)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Problem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    tests_json = db.Column(db.Text, nullable=False)  # JSON list of {input, expected}
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # who created this problem
    instructor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    instructor = db.relationship("User")


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    problem_id = db.Column(db.Integer, db.ForeignKey("problem.id"), nullable=False)

    code = db.Column(db.Text, nullable=False)
    passed = db.Column(db.Boolean, default=False)
    score = db.Column(db.Integer, default=0)  # tests passed
    total = db.Column(db.Integer, default=0)  # total tests
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")
    problem = db.relationship("Problem")


class Assignment(db.Model):
    __tablename__ = "assignment"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)

    instructor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    instructor = db.relationship("User")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # All problems that belong to this assignment
    problems = db.relationship(
        "AssignmentProblem",
        back_populates="assignment",
        cascade="all, delete-orphan",
    )

    # All invites created for this assignment
    invites = db.relationship(
        "ProblemInvite",
        back_populates="assignment",
        cascade="all, delete-orphan",
    )


class AssignmentProblem(db.Model):
    __tablename__ = "assignment_problem"
    id = db.Column(db.Integer, primary_key=True)

    assignment_id = db.Column(db.Integer, db.ForeignKey("assignment.id"), nullable=False)
    problem_id = db.Column(db.Integer, db.ForeignKey("problem.id"), nullable=False)

    # 👇 NEW: points this problem is worth in this assignment
    points = db.Column(db.Integer, nullable=False, default=0)

    assignment = db.relationship("Assignment", back_populates="problems")
    problem = db.relationship("Problem")



class ProblemInvite(db.Model):
    __tablename__ = "problem_invite"
    id = db.Column(db.Integer, primary_key=True)

    # who sent it
    instructor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    instructor = db.relationship("User", foreign_keys=[instructor_id])

    # who should receive it
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    student = db.relationship("User", foreign_keys=[student_id])
    student_email = db.Column(db.String(255), nullable=False)

    # what problem
    problem_id = db.Column(db.Integer, db.ForeignKey("problem.id"), nullable=False)
    problem = db.relationship("Problem")

    # which assignment this invite belongs to (optional for old invites)
    assignment_id = db.Column(db.Integer, db.ForeignKey("assignment.id"), nullable=True)
    assignment = db.relationship("Assignment", back_populates="invites")

    note = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="pending")  # 'pending' or 'accepted'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
