# app.py — REAL BACKEND (SQLite now; Postgres-ready)
import json, sys
from uuid import uuid4

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from sqlalchemy import func

from config import Config
from models import (
    db,
    User,
    Invite,
    Problem,
    Submission,
    ProblemInvite,
    Assignment,
    AssignmentProblem,
    ROLE_INSTRUCTOR,
    ROLE_STUDENT,
)
from grader import grade


app = Flask(__name__)
app.config.from_object(Config)

# --- DB + Login setup ---
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def _link_invites_to_current_user():
    """Attach pending invites sent to this email to the current user_id."""
    if not current_user.is_authenticated:
        return
    q = ProblemInvite.query.filter_by(
        student_id=None,
        student_email=current_user.email.lower()
    )
    updated = 0
    for inv in q.all():
        inv.student_id = current_user.id
        updated += 1
    if updated:
        db.session.commit()


@app.context_processor
def inject_role():
    notif_count = 0
    if current_user.is_authenticated and current_user.role == ROLE_STUDENT:
        notif_count = ProblemInvite.query.filter(
            (ProblemInvite.student_id == current_user.id) |
            (ProblemInvite.student_email == current_user.email.lower()),
            ProblemInvite.status == "pending"
        ).count()
    return dict(
        role=(current_user.role if current_user.is_authenticated else None),
        notif_count=notif_count
    )


def _seed_default_users():
    """Create some default instructors and students for testing."""
    created_any = False

    # Instructors
    if not User.query.filter_by(email="instructor@clemson.edu").first():
        u = User(
            email="instructor@clemson.edu",
            password_hash=generate_password_hash("changeme"),
            role=ROLE_INSTRUCTOR,
        )
        db.session.add(u)
        print("Created instructor: instructor@clemson.edu / changeme")
        created_any = True

    if not User.query.filter_by(email="instructor2@clemson.edu").first():
        u2 = User(
            email="instructor2@clemson.edu",
            password_hash=generate_password_hash("changeme"),
            role=ROLE_INSTRUCTOR,
        )
        db.session.add(u2)
        print("Created instructor: instructor2@clemson.edu / changeme")
        created_any = True

    # Students
    if not User.query.filter_by(email="student@clemson.edu").first():
        s1 = User(
            email="student@clemson.edu",
            password_hash=generate_password_hash("changeme"),
            role=ROLE_STUDENT,
        )
        db.session.add(s1)
        print("Created student: student@clemson.edu / changeme")
        created_any = True

    if not User.query.filter_by(email="student2@clemson.edu").first():
        s2 = User(
            email="student2@clemson.edu",
            password_hash=generate_password_hash("changeme"),
            role=ROLE_STUDENT,
        )
        db.session.add(s2)
        print("Created student: student2@clemson.edu / changeme")
        created_any = True

    if not User.query.filter_by(email="student3@clemson.edu").first():
        s3 = User(
            email="student3@clemson.edu",
            password_hash=generate_password_hash("changeme"),
            role=ROLE_STUDENT,
        )
        db.session.add(s3)
        print("Created student: student3@clemson.edu / changeme")
        created_any = True

    if created_any:
        db.session.commit()
        print("Default users seeded.")
    else:
        print("Default users already exist; nothing to seed.")


# --- CLI: initdb ---
@app.cli.command("initdb")
def initdb_cli():
    with app.app_context():
        db.create_all()
        _seed_default_users()
        print("DB ready.")


# --- Auth ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, pw):
            login_user(user)
            _link_invites_to_current_user()
            return redirect(url_for("index"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("login"))


# --- Home / dashboards ---
@app.route("/")
@login_required
def index():
    if current_user.role == ROLE_INSTRUCTOR:
        return render_template("dashboard_instructor.html")
    return render_template("dashboard_student.html")


# --- Invites (Instructor, legacy single-problem) ---
@app.route("/invite", methods=["GET", "POST"])
@login_required
def invite():
    if current_user.role != ROLE_INSTRUCTOR:
        abort(403)
    token = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Email required", "error")
        else:
            token = str(uuid4())
            inv = Invite(email=email, token=token, used=False)
            db.session.add(inv)
            db.session.commit()
            flash("Invite created. Share the link below.", "success")
    return render_template("invite.html", token=token)


@app.route("/accept/<token>", methods=["GET", "POST"])
def accept_invite(token):
    inv = Invite.query.filter_by(token=token, used=False).first()
    if not inv:
        flash("Invalid or used invite.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if len(pw) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("accept_invite.html", email=inv.email)
        if User.query.filter_by(email=inv.email).first():
            flash("User already exists. Please log in.", "warning")
            return redirect(url_for("login"))
        u = User(
            email=inv.email,
            password_hash=generate_password_hash(pw),
            role=ROLE_STUDENT,
        )
        db.session.add(u)
        inv.used = True
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("accept_invite.html", email=inv.email)


# --- Single-problem assign (still allowed, but not grouped as assignment) ---
@app.route("/assign", methods=["GET", "POST"])
@login_required
def assign():
    if current_user.role != ROLE_INSTRUCTOR:
        abort(403)
    problems = Problem.query.order_by(Problem.created_at.desc()).all()
    created = []
    if request.method == "POST":
        problem_id = request.form.get("problem_id")
        emails_raw = request.form.get("emails", "")
        note = request.form.get("note", "").strip() or None
        try:
            pid = int(problem_id)
            problem = db.session.get(Problem, pid)
            if not problem:
                raise ValueError("No such problem")
        except Exception:
            flash("Select a valid problem.", "error")
            return render_template("assign.html", problems=problems)

        # split on commas/whitespace
        emails = [
            e.strip().lower()
            for e in emails_raw.replace("\n", ",").split(",")
            if e.strip()
        ]
        if not emails:
            flash("Add at least one student email.", "error")
            return render_template("assign.html", problems=problems)

        for em in emails:
            student = User.query.filter_by(email=em).first()
            inv = ProblemInvite(
                instructor_id=current_user.id,
                student_id=(student.id if student else None),
                student_email=em,
                problem_id=problem.id,
                note=note,
                status="pending",
            )
            db.session.add(inv)
            created.append(em)
        db.session.commit()
        flash(f"Invited {len(created)} student(s) to '{problem.title}'.", "success")
        return redirect(url_for("assign"))

    return render_template("assign.html", problems=problems, created=created)


# --- Assignments (multiple problems × multiple students) ---
@app.route("/assignments")
@login_required
def assignments():
    if current_user.role != ROLE_INSTRUCTOR:
        abort(403)
    assignments = (
        Assignment.query
        .filter_by(instructor_id=current_user.id)
        .order_by(Assignment.created_at.desc())
        .all()
    )
    return render_template("assignments.html", assignments=assignments)


@app.route("/assignments/new", methods=["GET", "POST"])
@login_required
def assignment_new():
    if current_user.role != ROLE_INSTRUCTOR:
        abort(403)

    problems = Problem.query.order_by(Problem.created_at.desc()).all()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        problem_ids = request.form.getlist("problem_ids")
        emails_raw = request.form.get("emails", "")
        note = request.form.get("note", "").strip() or None

        if not title:
            flash("Title is required.", "error")
            return render_template("assignment_new.html", problems=problems)

        if not problem_ids:
            flash("Select at least one problem.", "error")
            return render_template("assignment_new.html", problems=problems)

        # Resolve problem IDs
        selected_problems = []
        for pid in problem_ids:
            try:
                pr = db.session.get(Problem, int(pid))
            except Exception:
                pr = None
            if pr:
                selected_problems.append(pr)

        if not selected_problems:
            flash("No valid problems selected.", "error")
            return render_template("assignment_new.html", problems=problems)

        # Parse student emails
        emails = [
            e.strip().lower()
            for e in emails_raw.replace("\n", ",").split(",")
            if e.strip()
        ]
        if not emails:
            flash("Add at least one student email.", "error")
            return render_template("assignment_new.html", problems=problems)

        # Create assignment
        assignment = Assignment(
            title=title,
            instructor_id=current_user.id,
        )
        db.session.add(assignment)
        db.session.flush()  # get assignment.id

        # Link problems to assignment
        for pr in selected_problems:
            ap = AssignmentProblem(assignment_id=assignment.id, problem_id=pr.id)
            db.session.add(ap)

        # Create invites: each student × each problem
        for em in emails:
            student = User.query.filter_by(email=em).first()
            for pr in selected_problems:
                inv = ProblemInvite(
                    instructor_id=current_user.id,
                    student_id=(student.id if student else None),
                    student_email=em,
                    problem_id=pr.id,
                    assignment_id=assignment.id,
                    note=note,
                    status="pending",
                )
                db.session.add(inv)

        db.session.commit()
        flash(f"Assignment '{assignment.title}' created and invites sent.", "success")
        return redirect(url_for("assignments"))

    # GET
    return render_template("assignment_new.html", problems=problems)


@app.route("/assignments/<int:aid>/leaderboard")
@login_required
def assignment_leaderboard(aid):
    assignment = db.session.get(Assignment, aid)
    if not assignment:
        flash("Assignment not found.", "error")
        return redirect(url_for("assignments"))

    # Permissions:
    # - Instructor who owns it
    # - OR student who has invites for this assignment
    allowed = False
    if current_user.role == ROLE_INSTRUCTOR and assignment.instructor_id == current_user.id:
        allowed = True
    elif current_user.role == ROLE_STUDENT:
        has_invite = ProblemInvite.query.filter(
            ProblemInvite.assignment_id == assignment.id,
            (ProblemInvite.student_id == current_user.id) |
            (ProblemInvite.student_email == current_user.email.lower()),
        ).first()
        if has_invite:
            allowed = True

    if not allowed:
        abort(403)

    # Problems in this assignment
    problem_ids = [ap.problem_id for ap in assignment.problems]
    problems_by_id = {ap.problem_id: ap.problem for ap in assignment.problems}

    if not problem_ids:
        flash("This assignment has no problems.", "warning")
        return render_template(
            "assignment_leaderboard.html",
            assignment=assignment,
            problems=[],
            rows=[],
        )

    # Students with at least one *invite* for this assignment
    invites = ProblemInvite.query.filter_by(assignment_id=assignment.id).all()
    student_ids = {inv.student_id for inv in invites if inv.student_id is not None}

    # Map (user, problem) -> best score
    scores = {}
    if student_ids:
        rows = (
            db.session.query(
                Submission.user_id,
                Submission.problem_id,
                func.max(Submission.score).label("best"),
                func.max(Submission.total).label("total"),
            )
            .filter(Submission.user_id.in_(student_ids))
            .filter(Submission.problem_id.in_(problem_ids))
            .group_by(Submission.user_id, Submission.problem_id)
            .all()
        )
        for uid, pid, best, total in rows:
            scores[(uid, pid)] = (int(best or 0), int(total or 0))

    # How many tests per problem (max possible score)
    import json as _json
    tests_per_problem = {}
    for pid in problem_ids:
        pr = problems_by_id[pid]
        try:
            tests_per_problem[pid] = len(_json.loads(pr.tests_json))
        except Exception:
            tests_per_problem[pid] = 0

    # Build table rows
    table_rows = []
    for uid in sorted(student_ids):
        user = db.session.get(User, uid)
        if not user:
            continue
        per_problem = []
        total_score = 0
        total_max = 0
        for pid in problem_ids:
            score, _ = scores.get((uid, pid), (0, tests_per_problem[pid]))
            max_score = tests_per_problem[pid]
            per_problem.append(
                {"problem": problems_by_id[pid], "score": score, "max": max_score}
            )
            total_score += score
            total_max += max_score

        table_rows.append(
            {
                "user": user,
                "per_problem": per_problem,
                "total_score": total_score,
                "total_max": total_max,
            }
        )

    table_rows.sort(key=lambda r: r["total_score"], reverse=True)

    return render_template(
        "assignment_leaderboard.html",
        assignment=assignment,
        problems=[problems_by_id[pid] for pid in problem_ids],
        rows=table_rows,
    )



@app.route("/my_assignments")
@login_required
def my_assignments():
    """Assignments that this student has at least one invite for."""
    if current_user.role != ROLE_STUDENT:
        abort(403)

    invites = ProblemInvite.query.filter(
        (ProblemInvite.student_id == current_user.id) |
        (ProblemInvite.student_email == current_user.email.lower())
    ).all()

    assignment_ids = sorted({inv.assignment_id for inv in invites if inv.assignment_id is not None})
    if assignment_ids:
        assignments = Assignment.query.filter(Assignment.id.in_(assignment_ids)) \
                                      .order_by(Assignment.created_at.desc()) \
                                      .all()
    else:
        assignments = []

    return render_template("assignments_student.html", assignments=assignments)



# --- Notifications (Student) ---
@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    if current_user.role != ROLE_STUDENT:
        abort(403)

    invites = ProblemInvite.query.filter(
        (ProblemInvite.student_id == current_user.id) |
        (ProblemInvite.student_email == current_user.email.lower())
    ).order_by(ProblemInvite.created_at.desc()).all()

    # Accept action
    if request.method == "POST":
        iid = request.form.get("invite_id")
        inv = db.session.get(ProblemInvite, int(iid)) if iid and iid.isdigit() else None
        if not inv or (
            inv.student_id != current_user.id and
            inv.student_email != current_user.email.lower()
        ):
            flash("Invalid invite.", "error")
            return redirect(url_for("notifications"))

        inv.status = "accepted"
        if inv.student_id is None:
            inv.student_id = current_user.id
        db.session.commit()
        flash("Invite accepted. Opening the problem…", "success")
        return redirect(url_for("solve", pid=inv.problem_id))

    return render_template("notifications.html", invites=invites)


@app.route("/invites/manage")
@login_required
def invites_manage():
    if current_user.role != ROLE_INSTRUCTOR:
        abort(403)
    rows = ProblemInvite.query.filter_by(
        instructor_id=current_user.id
    ).order_by(ProblemInvite.created_at.desc()).all()
    return render_template("invites_manage.html", rows=rows)


# --- Problems CRUD ---
@app.route("/problems")
@login_required
def problems():
    items = Problem.query.order_by(Problem.created_at.desc()).all()
    return render_template("problems.html", items=items)


@app.route("/problems/new", methods=["GET", "POST"])
@login_required
def problem_new():
    if current_user.role != ROLE_INSTRUCTOR:
        abort(403)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        prompt = request.form.get("prompt", "").strip()
        tests = request.form.get("tests", "").strip()
        # Validate tests is JSON list
        try:
            parsed = json.loads(tests)
            assert isinstance(parsed, list)
        except Exception:
            flash('Tests must be a JSON list, e.g. [{"input":5,"expected":120}]', "error")
            return render_template("problem_new.html")
        p = Problem(
            title=title,
            prompt=prompt,
            tests_json=tests,
            instructor_id=current_user.id,
        )
        db.session.add(p)
        db.session.commit()
        flash("Problem created.", "success")
        return redirect(url_for("problems"))
    return render_template("problem_new.html")


@app.route("/problems/<int:pid>")
@login_required
def problem_detail(pid):
    p = db.session.get(Problem, pid)
    if not p:
        flash("Problem not found", "error")
        return redirect(url_for("problems"))
    return render_template("problem_detail.html", p=p)


@app.route("/problems/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def problem_edit(pid):
    p = db.session.get(Problem, pid)
    if not p:
        flash("Problem not found", "error")
        return redirect(url_for("problems"))

    if current_user.role != ROLE_INSTRUCTOR or p.instructor_id != current_user.id:
        abort(403)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        prompt = request.form.get("prompt", "").strip()
        tests = request.form.get("tests", "").strip()

        if not title or not prompt or not tests:
            flash("All fields are required.", "error")
            return render_template("problem_edit.html", p=p)

        try:
            parsed = json.loads(tests)
            assert isinstance(parsed, list)
        except Exception:
            flash('Tests must be a JSON list, e.g. [{"input":5,"expected":120}]', "error")
            return render_template("problem_edit.html", p=p)

        p.title = title
        p.prompt = prompt
        p.tests_json = tests
        db.session.commit()
        flash("Problem updated.", "success")
        return redirect(url_for("problems"))

    return render_template("problem_edit.html", p=p)


@app.route("/problems/<int:pid>/delete", methods=["POST"])
@login_required
def problem_delete(pid):
    p = db.session.get(Problem, pid)
    if not p:
        flash("Problem not found", "error")
        return redirect(url_for("problems"))

    if current_user.role != ROLE_INSTRUCTOR or p.instructor_id != current_user.id:
        abort(403)

    db.session.delete(p)
    db.session.commit()
    flash("Problem deleted.", "success")
    return redirect(url_for("problems"))


# --- Solve (HackerRank-style) ---
@app.route("/solve/<int:pid>", methods=["GET", "POST"])
@login_required
def solve(pid):
    problems = Problem.query.order_by(Problem.created_at.desc()).all()
    p = db.session.get(Problem, pid)
    if not p:
        flash("Problem not found", "error")
        return redirect(url_for("problems"))

    details = None
    if request.method == "POST":
        code = request.form.get("code", "")
        res = grade(
            code,
            p.tests_json,
            timeout=app.config.get("GRADER_TIMEOUT_SECONDS", 2),
            max_mem_mb=app.config.get("GRADER_MAX_MEMORY_MB", 128),
        )
        sub = Submission(
            user_id=current_user.id,
            problem_id=p.id,
            code=code,
            passed=(res.passed == res.total),
            score=res.passed,
            total=res.total,
        )
        db.session.add(sub)
        db.session.commit()
        details = res.details
        flash(
            f"Passed {res.passed}/{res.total} tests.",
            "success" if res.passed == res.total else "warning",
        )

    return render_template("solve.html", problems=problems, p=p, details=details)


# --- Legacy submit route (older layout) ---
@app.route("/submit/<int:pid>", methods=["GET", "POST"])
@login_required
def submit(pid):
    p = db.session.get(Problem, pid)
    if not p:
        flash("Problem not found", "error")
        return redirect(url_for("problems"))

    details = None
    if request.method == "POST":
        code = request.form.get("code", "")
        res = grade(
            code,
            p.tests_json,
            timeout=app.config.get("GRADER_TIMEOUT_SECONDS", 2),
            max_mem_mb=app.config.get("GRADER_MAX_MEMORY_MB", 128),
        )
        sub = Submission(
            user_id=current_user.id,
            problem_id=p.id,
            code=code,
            passed=(res.passed == res.total),
            score=res.passed,
            total=res.total,
        )
        db.session.add(sub)
        db.session.commit()
        details = res.details
        flash(
            f"Passed {res.passed}/{res.total} tests.",
            "success" if res.passed == res.total else "warning",
        )

    return render_template("submit.html", p=p, details=details)


# --- Global Leaderboard (all problems) ---
@app.route("/leaderboard")
@login_required
def leaderboard():
    # Best score per (user_id, problem_id) across ALL submissions
    rows_subq = (
        db.session.query(
            Submission.user_id,
            Submission.problem_id,
            func.max(Submission.score).label("best"),
        )
        .group_by(Submission.user_id, Submission.problem_id)
        .subquery()
    )

    totals = (
        db.session.query(
            rows_subq.c.user_id,
            func.sum(rows_subq.c.best).label("total"),
        )
        .group_by(rows_subq.c.user_id)
        .having(func.sum(rows_subq.c.best) > 0)  # <- only users with > 0 points
        .all()
    )

    data = []
    for uid, total in totals:
        u = db.session.get(User, uid)
        if not u:
            continue
        data.append({"user": u.email, "total": int(total or 0)})

    data.sort(key=lambda x: x["total"], reverse=True)
    return render_template("leaderboard.html", data=data)


# --- Errors ---
@app.errorhandler(403)
def e403(_):
    return render_template("403.html"), 403


@app.errorhandler(404)
def e404(_):
    return render_template("404.html"), 404


if __name__ == "__main__":
    # Allow: python3 app.py initdb OR python3 app.py
    if len(sys.argv) > 1 and sys.argv[1] == "initdb":
        with app.app_context():
            db.create_all()
            _seed_default_users()
            print("DB ready.")
    else:
        app.run(debug=True)
