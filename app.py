from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

import pymysql

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps


# =========================================================
# FLASK CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = "college_admin_system_secret_key_2026"


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = ""
DB_NAME = "college_admin"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():

    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )


# =========================================================
# SAFE DATABASE CLOSE
# =========================================================

def close_db(conn=None, cursor=None):

    try:
        if cursor:
            cursor.close()
    except Exception:
        pass

    try:
        if conn and conn.open:
            conn.close()
    except Exception:
        pass


# =========================================================
# LOGIN REQUIRED DECORATOR
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "admin_id" not in session:

            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return wrapper


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "admin_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please enter username and password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        conn = None
        cursor = None

        try:

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT *
                FROM admin
                WHERE username = %s
                """,
                (username,)
            )

            admin = cursor.fetchone()

            if admin and check_password_hash(
                admin["password"],
                password
            ):

                session["admin_id"] = admin["admin_id"]
                session["username"] = admin["username"]

                flash(
                    "Login successful!",
                    "success"
                )

                return redirect(
                    url_for("dashboard")
                )

            else:

                flash(
                    "Invalid username or password.",
                    "danger"
                )

        except Exception as e:

            flash(
                "Database error: " + str(e),
                "danger"
            )

        finally:

            close_db(conn, cursor)

    return render_template(
        "login.html"
    )


# =========================================================
# SIGNUP
# =========================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username or not password:

            flash(
                "Please fill all required fields.",
                "danger"
            )

            return render_template(
                "signup.html"
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                "signup.html"
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return render_template(
                "signup.html"
            )

        conn = None
        cursor = None

        try:

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT admin_id
                FROM admin
                WHERE username = %s
                """,
                (username,)
            )

            existing = cursor.fetchone()

            if existing:

                flash(
                    "Username already exists. Please use another username.",
                    "warning"
                )

                return render_template(
                    "signup.html"
                )

            hashed_password = generate_password_hash(
                password
            )

            cursor.execute(
                """
                INSERT INTO admin
                (
                    username,
                    password
                )
                VALUES
                (
                    %s,
                    %s
                )
                """,
                (
                    username,
                    hashed_password
                )
            )

            flash(
                "Account created successfully. Please login.",
                "success"
            )

            return redirect(
                url_for("login")
            )

        except Exception as e:

            flash(
                "Signup error: " + str(e),
                "danger"
            )

        finally:

            close_db(conn, cursor)

    return render_template(
        "signup.html"
    )


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username or not new_password:

            flash(
                "Please fill all fields.",
                "danger"
            )

            return render_template(
                "forgot_password.html"
            )

        if new_password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                "forgot_password.html"
            )

        if len(new_password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return render_template(
                "forgot_password.html"
            )

        conn = None
        cursor = None

        try:

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT admin_id
                FROM admin
                WHERE username = %s
                """,
                (username,)
            )

            admin = cursor.fetchone()

            if not admin:

                flash(
                    "Username not found.",
                    "danger"
                )

                return render_template(
                    "forgot_password.html"
                )

            hashed_password = generate_password_hash(
                new_password
            )

            cursor.execute(
                """
                UPDATE admin
                SET password = %s
                WHERE admin_id = %s
                """,
                (
                    hashed_password,
                    admin["admin_id"]
                )
            )

            flash(
                "Password changed successfully. Please login.",
                "success"
            )

            return redirect(
                url_for("login")
            )

        except Exception as e:

            flash(
                "Password reset error: " + str(e),
                "danger"
            )

        finally:

            close_db(conn, cursor)

    return render_template(
        "forgot_password.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        # Students
        cursor.execute(
            "SELECT COUNT(*) AS total FROM student"
        )

        total_students = cursor.fetchone()["total"]

        # Faculty
        cursor.execute(
            "SELECT COUNT(*) AS total FROM faculty"
        )

        total_faculty = cursor.fetchone()["total"]

        # Departments
        cursor.execute(
            "SELECT COUNT(*) AS total FROM department"
        )

        total_departments = cursor.fetchone()["total"]

        # Courses
        cursor.execute(
            "SELECT COUNT(*) AS total FROM course"
        )

        total_courses = cursor.fetchone()["total"]

        # Fees
        cursor.execute(
            """
            SELECT
                COALESCE(SUM(total_amount), 0) AS total_fee,
                COALESCE(SUM(paid_amount), 0) AS paid_fee,
                COALESCE(SUM(pending_amount), 0) AS pending_fee
            FROM fee
            """
        )

        fee_data = cursor.fetchone()

        return render_template(
            "dashboard.html",
            total_students=total_students,
            total_faculty=total_faculty,
            total_departments=total_departments,
            total_courses=total_courses,
            total_fee=fee_data["total_fee"],
            paid_fee=fee_data["paid_fee"],
            pending_fee=fee_data["pending_fee"]
        )

    except Exception as e:

        flash(
            "Dashboard database error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("login")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# STUDENTS
# =========================================================

@app.route("/students")
@login_required
def students():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                s.*,
                d.department_name,
                c.course_name
            FROM student s
            LEFT JOIN department d
                ON s.department_id = d.department_id
            LEFT JOIN course c
                ON s.course_id = c.course_id
            ORDER BY s.student_id DESC
            """
        )

        students_list = cursor.fetchall()

        return render_template(
            "students.html",
            students=students_list
        )

    except Exception as e:

        flash(
            "Student database error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# ADD STUDENT
# =========================================================

@app.route(
    "/students/add",
    methods=["GET", "POST"]
)
@login_required
def add_student():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get departments
        cursor.execute(
            """
            SELECT *
            FROM department
            ORDER BY department_name
            """
        )

        departments = cursor.fetchall()

        # Get courses
        cursor.execute(
            """
            SELECT
                c.*,
                d.department_name
            FROM course c
            LEFT JOIN department d
                ON c.department_id = d.department_id
            ORDER BY c.course_name
            """
        )

        courses = cursor.fetchall()

        if request.method == "POST":

            roll_number = request.form.get(
                "roll_number",
                ""
            ).strip()

            enrollment_number = request.form.get(
                "enrollment_number",
                ""
            ).strip()

            abc_id = request.form.get(
                "abc_id",
                ""
            ).strip()

            name = request.form.get(
                "name",
                ""
            ).strip()

            gender = request.form.get(
                "gender",
                ""
            ).strip()

            date_of_birth = request.form.get(
                "date_of_birth"
            ) or None

            email = request.form.get(
                "email",
                ""
            ).strip()

            phone = request.form.get(
                "phone",
                ""
            ).strip()

            address = request.form.get(
                "address",
                ""
            ).strip()

            city = request.form.get(
                "city",
                ""
            ).strip()

            state = request.form.get(
                "state",
                ""
            ).strip()

            pincode = request.form.get(
                "pincode",
                ""
            ).strip()

            guardian_name = request.form.get(
                "guardian_name",
                ""
            ).strip()

            guardian_phone = request.form.get(
                "guardian_phone",
                ""
            ).strip()

            guardian_relation = request.form.get(
                "guardian_relation",
                ""
            ).strip()

            admission_date = request.form.get(
                "admission_date"
            ) or None

            semester = request.form.get(
                "semester"
            ) or None

            department_id = request.form.get(
                "department_id"
            ) or None

            course_id = request.form.get(
                "course_id"
            ) or None

            # Required fields
            if not roll_number or not name:

                flash(
                    "Roll Number and Student Name are required.",
                    "danger"
                )

                return render_template(
                    "add_student.html",
                    departments=departments,
                    courses=courses
                )

            # Duplicate Roll Number
            cursor.execute(
                """
                SELECT student_id
                FROM student
                WHERE roll_number = %s
                """,
                (roll_number,)
            )

            if cursor.fetchone():

                flash(
                    "Roll Number already exists.",
                    "warning"
                )

                return render_template(
                    "add_student.html",
                    departments=departments,
                    courses=courses
                )

            # Duplicate Enrollment Number
            if enrollment_number:

                cursor.execute(
                    """
                    SELECT student_id
                    FROM student
                    WHERE enrollment_number = %s
                    """,
                    (enrollment_number,)
                )

                if cursor.fetchone():

                    flash(
                        "Enrollment Number already exists.",
                        "warning"
                    )

                    return render_template(
                        "add_student.html",
                        departments=departments,
                        courses=courses
                    )

            # Duplicate ABC ID
            if abc_id:

                cursor.execute(
                    """
                    SELECT student_id
                    FROM student
                    WHERE abc_id = %s
                    """,
                    (abc_id,)
                )

                if cursor.fetchone():

                    flash(
                        "ABC ID already exists.",
                        "warning"
                    )

                    return render_template(
                        "add_student.html",
                        departments=departments,
                        courses=courses
                    )

            # Insert Student
            cursor.execute(
                """
                INSERT INTO student
                (
                    roll_number,
                    enrollment_number,
                    abc_id,
                    name,
                    gender,
                    date_of_birth,
                    email,
                    phone,
                    address,
                    city,
                    state,
                    pincode,
                    guardian_name,
                    guardian_phone,
                    guardian_relation,
                    admission_date,
                    semester,
                    department_id,
                    course_id
                )
                VALUES
                (
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    roll_number,
                    enrollment_number or None,
                    abc_id or None,
                    name,
                    gender or None,
                    date_of_birth,
                    email or None,
                    phone or None,
                    address or None,
                    city or None,
                    state or None,
                    pincode or None,
                    guardian_name or None,
                    guardian_phone or None,
                    guardian_relation or None,
                    admission_date,
                    semester,
                    department_id,
                    course_id
                )
            )

            flash(
                "Student added successfully!",
                "success"
            )

            return redirect(
                url_for("students")
            )

        return render_template(
            "add_student.html",
            departments=departments,
            courses=courses
        )

    except pymysql.err.IntegrityError:

        flash(
            "Student already exists or invalid department/course selected.",
            "warning"
        )

        return redirect(
            url_for("add_student")
        )

    except Exception as e:

        flash(
            "Student error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("students")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# EDIT STUDENT
# =========================================================

@app.route(
    "/students/edit/<int:student_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_student(student_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        # -------------------------------------------------
        # GET EXISTING STUDENT
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT *
            FROM student
            WHERE student_id = %s
            """,
            (student_id,)
        )

        student = cursor.fetchone()

        if not student:

            flash(
                "Student not found.",
                "danger"
            )

            return redirect(
                url_for("students")
            )

        # -------------------------------------------------
        # GET DEPARTMENTS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                department_id,
                department_code,
                department_name
            FROM department
            ORDER BY department_name
            """
        )

        departments = cursor.fetchall()

        # -------------------------------------------------
        # GET COURSES
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                course_id,
                course_code,
                course_name,
                department_id
            FROM course
            ORDER BY course_name
            """
        )

        courses = cursor.fetchall()

        # =================================================
        # UPDATE STUDENT
        # =================================================

        if request.method == "POST":

            roll_number = request.form.get(
                "roll_number",
                ""
            ).strip()

            enrollment_number = request.form.get(
                "enrollment_number",
                ""
            ).strip()

            abc_id = request.form.get(
                "abc_id",
                ""
            ).strip()

            name = request.form.get(
                "name",
                ""
            ).strip()

            gender = request.form.get(
                "gender",
                ""
            ).strip()

            date_of_birth = request.form.get(
                "date_of_birth"
            ) or None

            email = request.form.get(
                "email",
                ""
            ).strip()

            phone = request.form.get(
                "phone",
                ""
            ).strip()

            address = request.form.get(
                "address",
                ""
            ).strip()

            city = request.form.get(
                "city",
                ""
            ).strip()

            state = request.form.get(
                "state",
                ""
            ).strip()

            pincode = request.form.get(
                "pincode",
                ""
            ).strip()

            guardian_name = request.form.get(
                "guardian_name",
                ""
            ).strip()

            guardian_phone = request.form.get(
                "guardian_phone",
                ""
            ).strip()

            guardian_relation = request.form.get(
                "guardian_relation",
                ""
            ).strip()

            admission_date = request.form.get(
                "admission_date"
            ) or None

            semester_value = request.form.get(
                "semester",
                ""
            ).strip()

            department_value = request.form.get(
                "department_id",
                ""
            ).strip()

            course_value = request.form.get(
                "course_id",
                ""
            ).strip()

            # -------------------------------------------------
            # CONVERT VALUES
            # -------------------------------------------------

            semester = None

            if semester_value:

                try:

                    semester = int(semester_value)

                except ValueError:

                    flash(
                        "Semester must be a valid number.",
                        "danger"
                    )

                    return render_template(
                        "edit_student.html",
                        student=student,
                        departments=departments,
                        courses=courses
                    )

            department_id = None

            if department_value:

                try:

                    department_id = int(
                        department_value
                    )

                except ValueError:

                    flash(
                        "Invalid department selected.",
                        "danger"
                    )

                    return render_template(
                        "edit_student.html",
                        student=student,
                        departments=departments,
                        courses=courses
                    )

            course_id = None

            if course_value:

                try:

                    course_id = int(
                        course_value
                    )

                except ValueError:

                    flash(
                        "Invalid course selected.",
                        "danger"
                    )

                    return render_template(
                        "edit_student.html",
                        student=student,
                        departments=departments,
                        courses=courses
                    )

            # -------------------------------------------------
            # REQUIRED FIELDS
            # -------------------------------------------------

            if not roll_number or not name:

                flash(
                    "Roll Number and Student Name are required.",
                    "danger"
                )

                return render_template(
                    "edit_student.html",
                    student=student,
                    departments=departments,
                    courses=courses
                )

            # -------------------------------------------------
            # CHECK DUPLICATE ROLL NUMBER
            # -------------------------------------------------

            cursor.execute(
                """
                SELECT student_id
                FROM student
                WHERE roll_number = %s
                AND student_id != %s
                """,
                (
                    roll_number,
                    student_id
                )
            )

            if cursor.fetchone():

                flash(
                    "This Roll Number already exists.",
                    "warning"
                )

                return render_template(
                    "edit_student.html",
                    student=student,
                    departments=departments,
                    courses=courses
                )

            # -------------------------------------------------
            # CHECK DUPLICATE ENROLLMENT NUMBER
            # -------------------------------------------------

            if enrollment_number:

                cursor.execute(
                    """
                    SELECT student_id
                    FROM student
                    WHERE enrollment_number = %s
                    AND student_id != %s
                    """,
                    (
                        enrollment_number,
                        student_id
                    )
                )

                if cursor.fetchone():

                    flash(
                        "This Enrollment Number already exists.",
                        "warning"
                    )

                    return render_template(
                        "edit_student.html",
                        student=student,
                        departments=departments,
                        courses=courses
                    )

            # -------------------------------------------------
            # CHECK DUPLICATE ABC ID
            # -------------------------------------------------

            if abc_id:

                cursor.execute(
                    """
                    SELECT student_id
                    FROM student
                    WHERE abc_id = %s
                    AND student_id != %s
                    """,
                    (
                        abc_id,
                        student_id
                    )
                )

                if cursor.fetchone():

                    flash(
                        "This ABC ID already exists.",
                        "warning"
                    )

                    return render_template(
                        "edit_student.html",
                        student=student,
                        departments=departments,
                        courses=courses
                    )

            # -------------------------------------------------
            # UPDATE STUDENT
            # -------------------------------------------------

            cursor.execute(
                """
                UPDATE student
                SET
                    roll_number = %s,
                    enrollment_number = %s,
                    abc_id = %s,
                    name = %s,
                    gender = %s,
                    date_of_birth = %s,
                    email = %s,
                    phone = %s,
                    address = %s,
                    city = %s,
                    state = %s,
                    pincode = %s,
                    guardian_name = %s,
                    guardian_phone = %s,
                    guardian_relation = %s,
                    admission_date = %s,
                    semester = %s,
                    department_id = %s,
                    course_id = %s
                WHERE student_id = %s
                """,
                (
                    roll_number,
                    enrollment_number or None,
                    abc_id or None,
                    name,
                    gender or None,
                    date_of_birth,
                    email or None,
                    phone or None,
                    address or None,
                    city or None,
                    state or None,
                    pincode or None,
                    guardian_name or None,
                    guardian_phone or None,
                    guardian_relation or None,
                    admission_date,
                    semester,
                    department_id,
                    course_id,
                    student_id
                )
            )

            flash(
                "Student details updated successfully!",
                "success"
            )

            return redirect(
                url_for("students")
            )

        # =================================================
        # SHOW EDIT FORM
        # =================================================

        return render_template(
            "edit_student.html",
            student=student,
            departments=departments,
            courses=courses
        )

    except pymysql.err.IntegrityError as e:

        print(
            "EDIT STUDENT INTEGRITY ERROR:",
            repr(e)
        )

        flash(
            "Student details could not be updated because Roll Number, Enrollment Number or ABC ID already exists.",
            "warning"
        )

        return redirect(
            url_for(
                "edit_student",
                student_id=student_id
            )
        )

    except Exception as e:

        print(
            "EDIT STUDENT ERROR:",
            repr(e)
        )

        flash(
            "Unable to edit student: " + str(e),
            "danger"
        )

        return redirect(
            url_for("students")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# DELETE STUDENT
# =========================================================

@app.route(
    "/students/delete/<int:student_id>",
    methods=["POST"]
)
@login_required
def delete_student(student_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM student
            WHERE student_id = %s
            """,
            (student_id,)
        )

        flash(
            "Student deleted successfully.",
            "success"
        )

    except Exception as e:

        flash(
            "Unable to delete student: " + str(e),
            "danger"
        )

    finally:

        close_db(conn, cursor)

    return redirect(
        url_for("students")
    )


# =========================================================
# FACULTY
# =========================================================

@app.route("/faculty")
@login_required
def faculty():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                f.*,
                d.department_name
            FROM faculty f
            LEFT JOIN department d
                ON f.department_id = d.department_id
            ORDER BY f.faculty_id DESC
            """
        )

        faculty_list = cursor.fetchall()

        return render_template(
            "faculty.html",
            faculty=faculty_list
        )

    except Exception as e:

        flash(
            "Faculty database error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# ADD FACULTY
# =========================================================

@app.route(
    "/faculty/add",
    methods=["GET", "POST"]
)
@login_required
def add_faculty():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM department
            ORDER BY department_name
            """
        )

        departments = cursor.fetchall()

        if request.method == "POST":

            employee_id = request.form.get(
                "employee_id",
                ""
            ).strip()

            name = request.form.get(
                "name",
                ""
            ).strip()

            gender = request.form.get(
                "gender",
                ""
            ).strip()

            date_of_birth = request.form.get(
                "date_of_birth"
            ) or None

            email = request.form.get(
                "email",
                ""
            ).strip()

            phone = request.form.get(
                "phone",
                ""
            ).strip()

            address = request.form.get(
                "address",
                ""
            ).strip()

            qualification = request.form.get(
                "qualification",
                ""
            ).strip()

            designation = request.form.get(
                "designation",
                ""
            ).strip()

            department_id = request.form.get(
                "department_id"
            ) or None

            joining_date = request.form.get(
                "joining_date"
            ) or None

            salary = request.form.get(
                "salary"
            ) or None

            if not employee_id or not name:

                flash(
                    "Employee ID and Name are required.",
                    "danger"
                )

                return render_template(
                    "add_faculty.html",
                    departments=departments
                )

            cursor.execute(
                """
                SELECT faculty_id
                FROM faculty
                WHERE employee_id = %s
                """,
                (employee_id,)
            )

            if cursor.fetchone():

                flash(
                    "Employee ID already exists.",
                    "warning"
                )

                return render_template(
                    "add_faculty.html",
                    departments=departments
                )

            cursor.execute(
                """
                INSERT INTO faculty
                (
                    employee_id,
                    name,
                    gender,
                    date_of_birth,
                    email,
                    phone,
                    address,
                    qualification,
                    designation,
                    department_id,
                    joining_date,
                    salary
                )
                VALUES
                (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    employee_id,
                    name,
                    gender or None,
                    date_of_birth,
                    email or None,
                    phone or None,
                    address or None,
                    qualification or None,
                    designation or None,
                    department_id,
                    joining_date,
                    salary
                )
            )

            flash(
                "Faculty added successfully!",
                "success"
            )

            return redirect(
                url_for("faculty")
            )

        return render_template(
            "add_faculty.html",
            departments=departments
        )

    except pymysql.err.IntegrityError:

        flash(
            "Employee ID already exists.",
            "warning"
        )

        return redirect(
            url_for("add_faculty")
        )

    except Exception as e:

        flash(
            "Faculty error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("faculty")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# DELETE FACULTY
# =========================================================

@app.route(
    "/faculty/delete/<int:faculty_id>",
    methods=["POST"]
)
@login_required
def delete_faculty(faculty_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM faculty
            WHERE faculty_id = %s
            """,
            (faculty_id,)
        )

        flash(
            "Faculty deleted successfully.",
            "success"
        )

    except Exception as e:

        flash(
            "Unable to delete faculty: " + str(e),
            "danger"
        )

    finally:

        close_db(conn, cursor)

    return redirect(
        url_for("faculty")
    )


# =========================================================
# DEPARTMENTS
# =========================================================

@app.route("/departments")
@login_required
def departments():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM department
            ORDER BY department_id DESC
            """
        )

        department_list = cursor.fetchall()

        return render_template(
            "departments.html",
            departments=department_list
        )

    except Exception as e:

        flash(
            "Department error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# ADD DEPARTMENT
# =========================================================

@app.route(
    "/departments/add",
    methods=["POST"]
)
@login_required
def add_department():

    conn = None
    cursor = None

    try:

        department_code = request.form.get(
            "department_code",
            ""
        ).strip()

        department_name = request.form.get(
            "department_name",
            ""
        ).strip()

        hod_name = request.form.get(
            "hod_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        if not department_code or not department_name:

            flash(
                "Department Code and Department Name are required.",
                "danger"
            )

            return redirect(
                url_for("departments")
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT department_id
            FROM department
            WHERE department_code = %s
            """,
            (department_code,)
        )

        if cursor.fetchone():

            flash(
                "Department Code already exists.",
                "warning"
            )

            return redirect(
                url_for("departments")
            )

        cursor.execute(
            """
            INSERT INTO department
            (
                department_code,
                department_name,
                hod_name,
                email,
                phone,
                description
            )
            VALUES
            (
                %s, %s, %s, %s, %s, %s
            )
            """,
            (
                department_code,
                department_name,
                hod_name or None,
                email or None,
                phone or None,
                description or None
            )
        )

        flash(
            "Department added successfully!",
            "success"
        )

    except pymysql.err.IntegrityError:

        flash(
            "Department Code already exists.",
            "warning"
        )

    except Exception as e:

        flash(
            "Department error: " + str(e),
            "danger"
        )

    finally:

        close_db(conn, cursor)

    return redirect(
        url_for("departments")
    )


# =========================================================
# DELETE DEPARTMENT
# =========================================================

@app.route(
    "/departments/delete/<int:department_id>"
)
@login_required
def delete_department(department_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        # Remove department from students
        cursor.execute(
            """
            UPDATE student
            SET department_id = NULL
            WHERE department_id = %s
            """,
            (department_id,)
        )

        # Remove department from faculty
        cursor.execute(
            """
            UPDATE faculty
            SET department_id = NULL
            WHERE department_id = %s
            """,
            (department_id,)
        )

        # Remove department from courses
        #
        # IMPORTANT:
        # If course.department_id is NOT NULL in your
        # database, this UPDATE may fail.
        # In that case, delete/update the course first
        # or change the column to allow NULL.
        #
        try:

            cursor.execute(
                """
                UPDATE course
                SET department_id = NULL
                WHERE department_id = %s
                """,
                (department_id,)
            )

        except Exception as course_error:

            print(
                "COURSE DEPARTMENT UPDATE ERROR:",
                repr(course_error)
            )

        # Delete department
        cursor.execute(
            """
            DELETE FROM department
            WHERE department_id = %s
            """,
            (department_id,)
        )

        flash(
            "Department deleted successfully!",
            "success"
        )

    except Exception as e:

        print(
            "DELETE DEPARTMENT ERROR:",
            repr(e)
        )

        flash(
            "Unable to delete department: " + str(e),
            "danger"
        )

    finally:

        close_db(conn, cursor)

    return redirect(
        url_for("departments")
    )


# =========================================================
# COURSES
# =========================================================

@app.route("/courses")
@login_required
def courses():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                c.*,
                d.department_name
            FROM course c
            LEFT JOIN department d
                ON c.department_id = d.department_id
            ORDER BY c.course_id DESC
            """
        )

        course_list = cursor.fetchall()

        cursor.execute(
            """
            SELECT *
            FROM department
            ORDER BY department_name
            """
        )

        department_list = cursor.fetchall()

        return render_template(
            "courses.html",
            courses=course_list,
            departments=department_list
        )

    except Exception as e:

        flash(
            "Course error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# ADD COURSE
# =========================================================

@app.route(
    "/courses/add",
    methods=["POST"]
)
@login_required
def add_course():

    conn = None
    cursor = None

    try:

        course_code = request.form.get(
            "course_code",
            ""
        ).strip()

        course_name = request.form.get(
            "course_name",
            ""
        ).strip()

        department_id = request.form.get(
            "department_id"
        )

        duration = request.form.get(
            "duration",
            ""
        ).strip()

        total_semesters = request.form.get(
            "total_semesters"
        ) or None

        description = request.form.get(
            "description",
            ""
        ).strip()

        if not course_code or not course_name or not department_id:

            flash(
                "Course Code, Course Name and Department are required.",
                "danger"
            )

            return redirect(
                url_for("courses")
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT course_id
            FROM course
            WHERE course_code = %s
            """,
            (course_code,)
        )

        if cursor.fetchone():

            flash(
                "Course Code already exists.",
                "warning"
            )

            return redirect(
                url_for("courses")
            )

        cursor.execute(
            """
            INSERT INTO course
            (
                course_code,
                course_name,
                department_id,
                duration,
                total_semesters,
                description
            )
            VALUES
            (
                %s, %s, %s, %s, %s, %s
            )
            """,
            (
                course_code,
                course_name,
                department_id,
                duration or None,
                total_semesters,
                description or None
            )
        )

        flash(
            "Course added successfully!",
            "success"
        )

    except pymysql.err.IntegrityError:

        flash(
            "Course Code already exists or invalid department.",
            "warning"
        )

    except Exception as e:

        flash(
            "Course error: " + str(e),
            "danger"
        )

    finally:

        close_db(conn, cursor)

    return redirect(
        url_for("courses")
    )


# =========================================================
# DELETE COURSE
# =========================================================

@app.route(
    "/courses/delete/<int:course_id>",
    methods=["POST"]
)
@login_required
def delete_course(course_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM course
            WHERE course_id = %s
            """,
            (course_id,)
        )

        flash(
            "Course deleted successfully.",
            "success"
        )

    except Exception as e:

        flash(
            "Unable to delete course: " + str(e),
            "danger"
        )

    finally:

        close_db(conn, cursor)

    return redirect(
        url_for("courses")
    )


# =========================================================
# FEES
# =========================================================

@app.route("/fees")
@login_required
def fees():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        # -------------------------------------------------
        # FEE RECORDS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                f.fee_id,
                f.student_id,
                f.total_amount,
                f.paid_amount,
                f.pending_amount,
                f.due_date,
                f.payment_date,
                f.payment_status,
                f.remarks,
                s.roll_number,
                s.name AS student_name,
                s.abc_id
            FROM fee f
            INNER JOIN student s
                ON f.student_id = s.student_id
            ORDER BY f.fee_id DESC
            """
        )

        fee_records = cursor.fetchall()

        # -------------------------------------------------
        # STUDENTS FOR DROPDOWN
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                student_id,
                roll_number,
                name,
                abc_id
            FROM student
            ORDER BY name ASC
            """
        )

        students_list = cursor.fetchall()

        # -------------------------------------------------
        # FEE TOTALS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                COALESCE(SUM(total_amount), 0)
                AS total_fee,

                COALESCE(SUM(paid_amount), 0)
                AS paid_fee,

                COALESCE(SUM(pending_amount), 0)
                AS pending_fee

            FROM fee
            """
        )

        fee_totals = cursor.fetchone()

        return render_template(
            "fees.html",
            fees=fee_records,
            students=students_list,
            total_fee=fee_totals["total_fee"],
            paid_fee=fee_totals["paid_fee"],
            pending_fee=fee_totals["pending_fee"]
        )

    except Exception as e:

        flash(
            "Fee database error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# ADD FEE
# =========================================================

@app.route(
    "/fees/add",
    methods=["GET", "POST"]
)
@login_required
def add_fee():

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        # -------------------------------------------------
        # GET STUDENTS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                student_id,
                roll_number,
                name,
                abc_id
            FROM student
            ORDER BY name ASC
            """
        )

        students_list = cursor.fetchall()

        if request.method == "POST":

            student_id = request.form.get(
                "student_id"
            )

            total_amount = request.form.get(
                "total_amount",
                "0"
            )

            paid_amount = request.form.get(
                "paid_amount",
                "0"
            )

            due_date = request.form.get(
                "due_date"
            ) or None

            payment_date = request.form.get(
                "payment_date"
            ) or None

            remarks = request.form.get(
                "remarks",
                ""
            ).strip()

            if not student_id:

                flash(
                    "Please select a student.",
                    "danger"
                )

                return render_template(
                    "add_fee.html",
                    students=students_list
                )

            try:

                total_amount = float(
                    total_amount
                )

                paid_amount = float(
                    paid_amount
                )

            except ValueError:

                flash(
                    "Please enter valid fee amounts.",
                    "danger"
                )

                return render_template(
                    "add_fee.html",
                    students=students_list
                )

            if total_amount < 0:
                total_amount = 0

            if paid_amount < 0:
                paid_amount = 0

            if paid_amount > total_amount:

                flash(
                    "Paid amount cannot be greater than total amount.",
                    "warning"
                )

                return render_template(
                    "add_fee.html",
                    students=students_list
                )

            pending_amount = (
                total_amount - paid_amount
            )

            # -------------------------------------------------
            # PAYMENT STATUS
            # -------------------------------------------------

            if total_amount == 0:

                payment_status = "Pending"

            elif paid_amount >= total_amount:

                payment_status = "Paid"

            elif paid_amount > 0:

                payment_status = "Partial"

            else:

                payment_status = "Pending"

            # -------------------------------------------------
            # INSERT FEE
            # -------------------------------------------------

            cursor.execute(
                """
                INSERT INTO fee
                (
                    student_id,
                    total_amount,
                    paid_amount,
                    pending_amount,
                    due_date,
                    payment_date,
                    payment_status,
                    remarks
                )
                VALUES
                (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    student_id,
                    total_amount,
                    paid_amount,
                    pending_amount,
                    due_date,
                    payment_date,
                    payment_status,
                    remarks or None
                )
            )

            flash(
                "Fee record added successfully!",
                "success"
            )

            return redirect(
                url_for("fees")
            )

        return render_template(
            "add_fee.html",
            students=students_list
        )

    except Exception as e:

        flash(
            "Fee error: " + str(e),
            "danger"
        )

        return redirect(
            url_for("fees")
        )

    finally:

        close_db(conn, cursor)


# =========================================================
# DELETE FEE
# =========================================================

@app.route(
    "/fees/delete/<int:fee_id>",
    methods=["POST"]
)
@login_required
def delete_fee(fee_id):

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM fee
            WHERE fee_id = %s
            """,
            (fee_id,)
        )

        flash(
            "Fee record deleted successfully.",
            "success"
        )

    except Exception as e:

        flash(
            "Unable to delete fee: " + str(e),
            "danger"
        )

    finally:

        close_db(conn, cursor)

    return redirect(
        url_for("fees")
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    print("")
    print("==============================================")
    print(" COLLEGE ADMINISTRATION SYSTEM")
    print("==============================================")
    print("Database : college_admin")
    print("Server   : http://127.0.0.1:5000")
    print("==============================================")
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )