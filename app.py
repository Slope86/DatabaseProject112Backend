import hashlib  # for password hashing
import os  # for environment variables
import traceback  # for debugging

import jwt  # for JWT authentication
from dotenv import load_dotenv  # for environment variables
from flask import Flask, jsonify, request
from flask_cors import CORS

from utils import auth
from utils.database import Database

# Load environment variables
load_dotenv(override=True)
JWT_SECRET: str = os.getenv("JWT_SECRET")  # type: ignore

# Initialize the Flask app
app = Flask(__name__)
CORS(app)


@app.route("/api/auth/login", methods=["POST"])
def login():
    # Initialize the database connection
    db = Database()
    try:
        # Get the email and password from the request body
        data: dict[str, str] = request.json  # type: ignore
        email: str = data.get("email")  # type: ignore
        password: str = data.get("password")  # type: ignore
        password_hash: str = hashlib.sha256(password.encode("utf-8")).hexdigest()

        # Check if the user exists in the database
        query: str = "SELECT * FROM users WHERE email = %s AND passwordhash = %s"
        values: tuple[str, str] = (email, password_hash)
        db.cursor.execute(query, values)
        user_row_data: tuple | None = db.cursor.fetchone()

        # If the user does not exist, return an error
        if user_row_data is None:
            return jsonify({"error": "Invalid email or password"}), 401

        user_data: dict = {
            "id": user_row_data[0],
            "username": user_row_data[1],
            "name": user_row_data[1],
            "email": user_row_data[2],
            "avatar": user_row_data[4],
            "fullname": user_row_data[5],
            "role": user_row_data[6],
            "phone": user_row_data[7],
            "address": user_row_data[8],
            "gender": user_row_data[9],
        }

        # If the user exists, prepare the response
        access_token: str = auth.create_token(user_data)

        # Log and send the response
        response = jsonify({"accessToken": access_token, "user": user_data})

        return response, 200

    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at login: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/auth/register", methods=["POST"])
def register():
    # Initialize the database connection
    db = Database()
    try:
        data: dict[str, str] = request.json  # type: ignore
        email: str = data.get("email")  # type: ignore
        username: str = data.get("username")  # type: ignore
        password: str = data.get("password")  # type: ignore
        password_hash: str = hashlib.sha256(password.encode("utf-8")).hexdigest()

        # Check if the user already exists in the database using the email
        query: str = "SELECT * FROM users WHERE email = %s"
        db.cursor.execute(query, (email,))
        existing_user: tuple | None = db.cursor.fetchone()

        if existing_user:
            return jsonify({"error": "User already exists!"}), 401

        # Insert the new user into the database
        insert_query: str = """
                INSERT INTO users (
                    Username,
                    Email,
                    PasswordHash
                ) VALUES (%s, %s, %s)
                """
        insert_values: tuple[str, str, str] = (username, email, password_hash)
        db.cursor.execute(insert_query, insert_values)
        db.conn.commit()

        # Retrieve the newly registered user from the database
        db.cursor.execute(
            "SELECT UserID,AvatarPath,email,UserName,userRole FROM users WHERE email = %s",
            (email,),
        )
        user_row_data: dict = db.cursor.fetchone()  # type: ignore

        # Format the user data
        user_data: dict[str, str] = {
            "id": user_row_data[0],
            "avatar": user_row_data[1],
            "email": user_row_data[2],
            "name": user_row_data[3],
            "role": user_row_data[4],
        }

        # Prepare the JWT token for the newly registered user
        access_token: str = auth.create_token(user_data)

        return jsonify({"accessToken": access_token, "user": user_data}), 200

    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at register: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/auth/profile", methods=["GET"])
def get_profile():
    authorization: str = request.headers.get("Authorization")  # type: ignore
    profile = auth.get_profile(authorization)
    db = Database()
    try:
        query: str = "SELECT * FROM users WHERE UserID = %s"
        values = (profile.get("id", "0"),)
        db.cursor.execute(query, values)
        user_row_data: tuple | None = db.cursor.fetchone()

        # If the user does not exist, return an error
        if user_row_data is None:
            print(query, values, profile)
            return jsonify({"error": "Invalid email or password"}), 401

        user_data: dict = {
            "id": user_row_data[0],
            "username": user_row_data[1],
            "name": user_row_data[1],
            "email": user_row_data[2],
            "avatar": user_row_data[4],
            "fullname": user_row_data[5],
            "role": user_row_data[6],
            "phone": user_row_data[7],
            "address": user_row_data[8],
            "gender": user_row_data[9],
        }
        return jsonify({"user": user_data}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/api/admin/users", methods=["GET"])
def get_users():
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        if not auth.verify_admin(authorization):
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        db.cursor.execute("SELECT * FROM users")
        rows = db.cursor.fetchall()

        users = []
        for row in rows:
            user = {
                "id": row[0],
                "username": row[1],
                "name": row[1],
                "email": row[2],
                # "passwordhash": row[3],
                "avatar": row[4],
                "fullname": row[5],
                "role": row[6],
                "phone": row[7],
                "address": row[8],
                "gender": row[9],
                "created_date": row[10],
                "modify_date": row[11],
            }
            users.append(user)

        return jsonify({"users": users}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at get_users: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/users", methods=["PATCH"])
def update_user():
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        data: dict[str, str] = request.json  # type: ignore
        target_user_id: str = data.get("id")  # type: ignore
        if profile.get("role") != "ADMIN" and profile.get("id") != target_user_id:
            print(profile.get("role"), profile.get("id"), target_user_id)
            return jsonify({"error": "Unauthorized"}), 401

        # Initialize the database connection
        db = Database()
        try:
            # Fetch existing user details from the database
            query: str = "SELECT * FROM users WHERE UserID = %s"
            db.cursor.execute(query, (target_user_id,))
            existing_user: tuple[str, ...] | None = db.cursor.fetchone()  # type: ignore

            if not existing_user:
                return jsonify({"error": "User does not exist"}), 404

            # Retrieve existing user details
            existing_user_data: dict[str, str] = {
                "username": existing_user[1],
                "email": existing_user[2],
                "avatar": existing_user[4],
                "fullname": existing_user[5],
                "phone": existing_user[7],
                "address": existing_user[8],
                "gender": existing_user[9],
            }
            if data.get("password") is not None:
                password_hash: str = hashlib.sha256(data.get("password").encode("utf-8")).hexdigest()  # type: ignore # noqa: E501
            else:
                password_hash = existing_user[3]

            # Update user data only if the fields are present in the request
            user_data = {
                "username": data.get("username", existing_user_data["username"]),
                "email": data.get("email", existing_user_data["email"]),
                "password_hash": password_hash,
                "avatar": data.get("avatar", existing_user_data["avatar"]),
                "fullname": data.get("fullname", existing_user_data["fullname"]),
                "phone": data.get("phone", existing_user_data["phone"]),
                "address": data.get("address", existing_user_data["address"]),
                "gender": data.get("gender", existing_user_data["gender"]),
            }

            # Update the user in the database
            update_query: str = """
                UPDATE users
                SET UserName = %s, Email = %s, PasswordHash = %s, AvatarPath = %s, FullName = %s,
                PhoneNumber = %s, Address = %s, Gender = %s
                WHERE UserID = %s
                """
            update_values: tuple[str, str, str, str, str, str, str, str, str] = (
                user_data["username"],
                user_data["email"],
                user_data["password_hash"],
                user_data["avatar"],
                user_data["fullname"],
                user_data["phone"],
                user_data["address"],
                user_data["gender"],
                target_user_id,
            )
            db.cursor.execute(update_query, update_values)
            db.conn.commit()
            return jsonify({"message": "User updated successfully"}), 200

        except Exception as e:
            db.conn.rollback()
            error_info = traceback.format_exc()
            print("Error at update_user: " + error_info)
            return jsonify({"error": "Internal server error: " + str(e)}), 500
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/api/admin/students", methods=["GET"])
def get_students():
    authority_roles = ["ADMIN", "TEACHER", "STUDENT"]
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        if profile.get("role") not in authority_roles:
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        if profile.get("role") == "STUDENT":
            db.cursor.execute("SELECT * FROM users WHERE UserID = %s", (profile.get("id"),))
        else:
            db.cursor.execute("SELECT * FROM users WHERE UserRole = 'student'")
        rows = db.cursor.fetchall()

        students = []
        for row in rows:
            student = {
                "id": row[0],
                "username": row[1],
                "name": row[1],
                "email": row[2],
                # "passwordhash": row[3],
                "avatar": row[4],
                "fullname": row[5],
                "role": row[6],
                "phone": row[7],
                "address": row[8],
                "gender": row[9],
                "created_date": row[10],
                "modify_date": row[11],
            }
            students.append(student)

        return jsonify({"students": students, "students_count": len(students)}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at get_students: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/students", methods=["POST"])
def add_student():
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        if not auth.verify_admin(authorization):
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        data: dict[str, str] = request.json  # type: ignore
        email: str = data.get("email")  # type: ignore
        username: str = data.get("username")  # type: ignore
        address: str = data.get("address")  # type: ignore
        phone: str = data.get("phone")  # type: ignore
        # password: str = data.get("password")  # type: ignore
        password: str = "passwd"
        password_hash: str = hashlib.sha256(password.encode("utf-8")).hexdigest()

        # Check if the user already exists in the database using the email
        query: str = "SELECT * FROM users WHERE email = %s"
        db.cursor.execute(query, (email,))
        existing_user: tuple | None = db.cursor.fetchone()

        if existing_user:
            return jsonify({"error": "User already exists!"}), 401

        # Insert the new user into the database
        insert_query: str = """
                INSERT INTO users (
                    Username,
                    Email,
                    Address,
                    PhoneNumber,
                    PasswordHash,
                    UserRole
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """
        insert_values: tuple[str, str, str, str, str, str] = (
            username,
            email,
            address,
            phone,
            password_hash,
            "student",
        )
        db.cursor.execute(insert_query, insert_values)
        db.conn.commit()

        return jsonify({"message": "add student successfully"}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at add_student: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/teachers", methods=["GET"])
def get_teachers():
    authority_roles = ["ADMIN", "TEACHER", "STUDENT"]
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        if profile.get("role") not in authority_roles:
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        db.cursor.execute("SELECT * FROM users NATURAL JOIN teachers WHERE users.UserRole = 'teacher'")
        rows = db.cursor.fetchall()

        teachers = []
        for row in rows:
            teacher = {
                "id": row[12],
                "userid": row[0],
                "username": row[1],
                "name": row[1],
                "email": row[2],
                # "passwordhash": row[3],
                "avatar": row[4],
                "fullname": row[5],
                "role": row[6],
                "phone": row[7],
                "address": row[8],
                "gender": row[9],
                "created_date": row[10],
                "modify_date": row[11],
                "salary": row[13],
            }

            # Fetch courses taught by this teacher
            db.cursor.execute(
                """
                SELECT CourseID, CourseName, Category
                FROM courses
                WHERE TeacherID = %s
                """,
                (teacher["id"],),  # type: ignore
            )
            courses_taught = db.cursor.fetchall()
            courses_info = [{"id": course[0], "name": course[1], "category": course[2]} for course in courses_taught]

            teacher["courses_taught"] = courses_info
            teachers.append(teacher)

        return jsonify({"teachers": teachers, "teachers_count": len(teachers)}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at get_teachers: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/courses", methods=["GET"])
def get_courses():
    authority_roles = ["ADMIN", "TEACHER", "STUDENT"]
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        if profile.get("role") not in authority_roles:
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        db.cursor.execute("SELECT * FROM courses")
        rows = db.cursor.fetchall()

        courses = []
        for row in rows:
            course = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "category": row[3],
                "teacher_id": row[4],
                "created_date": row[5],
                "modify_date": row[6],
            }
            # Fetch entered students for each course
            db.cursor.execute(
                """
                SELECT ce.UserID, u.username
                FROM courseEnter ce INNER JOIN users u
                ON ce.UserID = u.UserID
                WHERE ce.CourseID = %s
                """,
                (course["id"],),  # type: ignore
            )  # type: ignore
            entered_students_info = db.cursor.fetchall()
            entered_students = [{"id": student[0], "username": student[1]} for student in entered_students_info]

            course["entered_students"] = entered_students

            courses.append(course)

        return jsonify({"courses": courses, "courses_count": len(courses)}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at get_courses: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/modifycourses", methods=["GET"])
def modify_get_courses():
    authority_roles = ["ADMIN", "TEACHER"]
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        if profile.get("role") not in authority_roles:
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        db.cursor.execute("SELECT * FROM courses")
        rows = db.cursor.fetchall()

        courses = []
        for row in rows:
            course = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "category": row[3],
                "teacher_id": row[4],
                "created_date": row[5],
                "modify_date": row[6],
            }
            # Fetch entered students for each course
            db.cursor.execute(
                """
                SELECT ce.UserID, u.username
                FROM courseEnter ce INNER JOIN users u
                ON ce.UserID = u.UserID
                WHERE ce.CourseID = %s
                """,
                (course["id"],),  # type: ignore
            )  # type: ignore
            entered_students_info = db.cursor.fetchall()
            entered_students = [{"id": student[0], "username": student[1]} for student in entered_students_info]

            course["entered_students"] = entered_students

            courses.append(course)

        return jsonify({"courses": courses, "courses_count": len(courses)}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at get_courses: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/student/enter_course", methods=["POST"])
def enter_course():
    authority_roles = ["ADMIN", "STUDENT"]
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        if profile.get("role") not in authority_roles:
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    # Initialize the database connection
    db = Database()
    try:
        data: dict[str, str] = request.json  # type: ignore
        course_name: str = data.get("course_name")  # type: ignore
        course_category: str = data.get("category")  # type: ignore
        user_id: str = profile.get("id")  # type: ignore

        # Get the course id from the database
        query: str = "SELECT * FROM courses WHERE CourseName = %s AND Category = %s"
        db.cursor.execute(query, (course_name, course_category))
        course_row_data: tuple | None = db.cursor.fetchone()

        # If the course does not exist, return an error
        if course_row_data is None:
            print(query, course_name, course_category)
            return jsonify({"error": "Invalid course name or category"}), 401

        course_id: str = course_row_data[0]  # type: ignore

        # Check if the user already entered the course
        query: str = "SELECT * FROM courseEnter WHERE CourseID = %s AND UserID = %s"
        db.cursor.execute(query, (course_id, user_id))
        existing_course: tuple | None = db.cursor.fetchone()

        if existing_course:
            return jsonify({"error": "User already entered the course!"}), 401

        # Insert the new user into the database
        insert_query: str = """
                INSERT INTO courseEnter (
                    CourseID,
                    UserID
                ) VALUES (%s, %s)
                """
        insert_values: tuple[str, str] = (course_id, user_id)
        db.cursor.execute(insert_query, insert_values)
        db.conn.commit()

        return jsonify({"message": "enter course successfully"}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at enter_course: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/courses", methods=["POST"])
def add_course():
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        if not (profile.get("role") == "ADMIN" or profile.get("role") == "TEACHER"):
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        data: dict[str, str] = request.json  # type: ignore
        course_name: str = data.get("name")  # type: ignore
        course_description: str = data.get("description")  # type: ignore
        course_category: str = data.get("category")  # type: ignore
        course_teacher_id: str = data.get("teacher_id")  # type: ignore

        # Check if the course already exists in the database using the name
        query: str = "SELECT * FROM courses WHERE CourseName = %s"
        db.cursor.execute(query, (course_name,))
        existing_course: tuple | None = db.cursor.fetchone()

        if existing_course:
            return jsonify({"error": "Course already exists!"}), 401

        # Insert the new course into the database
        insert_query: str = """
                INSERT INTO courses (
                    CourseName,
                    CourseDescription,
                    Category,
                    TeacherID
                ) VALUES (%s, %s, %s, %s)
                """
        insert_values: tuple[str, str, str, str] = (
            course_name,
            course_description,
            course_category,
            course_teacher_id,
        )
        db.cursor.execute(insert_query, insert_values)
        db.conn.commit()

        return jsonify({"message": "add course successfully"}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at add_course: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/modifycourses", methods=["PUT", "PATCH"])
def update_course():
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        print(
            f"json: {request.json}\nrole {profile.get('role')}",
        )
        if not (profile.get("role") == "ADMIN" or profile.get("role") == "TEACHER"):
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        data: dict[str, str] = request.json  # type: ignore
        course_id: str = data.get("id")  # type: ignore

        # Fetch existing course details from the database
        query: str = "SELECT * FROM courses WHERE CourseID = %s"
        db.cursor.execute(query, (course_id,))
        existing_course: tuple[str, ...] | None = db.cursor.fetchone()  # type: ignore

        if not existing_course:
            return jsonify({"error": "Course does not exist!"}), 401

        # Retrieve existing course details
        existing_course_data = {
            "name": existing_course[1],
            "description": existing_course[2],
            "category": existing_course[3],
            "teacher_id": existing_course[4],
        }

        # Update course data only if the fields are present in the request
        course_name: str = data.get("name", existing_course_data["name"])
        course_description: str = data.get("description", existing_course_data["description"])
        course_category: str = data.get("category", existing_course_data["category"])
        course_teacher_id: str = data.get("teacher_id", existing_course_data["teacher_id"])

        # Update the course in the database
        update_query: str = """
                UPDATE courses
                SET CourseName = %s, CourseDescription = %s, Category = %s, TeacherID = %s
                WHERE CourseID = %s
                """
        update_values: tuple[str, str, str, str, str] = (
            course_name,
            course_description,
            course_category,
            course_teacher_id,
            course_id,
        )
        db.cursor.execute(update_query, update_values)
        db.conn.commit()

        return jsonify({"message": "Course updated successfully"}), 200

    except Exception as e:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at update_course: " + error_info)
        return jsonify({"error": "Internal server error: " + str(e)}), 500


@app.route("/api/admin/courses/<int:course_id>", methods=["DELETE"])
def delete_course(course_id):
    try:
        authorization: str = request.headers.get("Authorization")  # type: ignore
        profile: dict[str, str] = auth.get_profile(authorization)
        if not (profile.get("role") == "ADMIN" or profile.get("role") == "TEACHER"):
            return jsonify({"error": "Unauthorized"}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Initialize the database connection
    db = Database()
    try:
        # Fetch existing course details from the database
        query: str = "SELECT * FROM courses WHERE CourseID = %s"
        db.cursor.execute(query, (course_id,))
        existing_course: tuple[str, ...] | None = db.cursor.fetchone()  # type: ignore

        if not existing_course:
            return jsonify({"error": "Course does not exist!"}), 404  # 404 for Not Found

        # Delete the course in the database
        delete_query: str = "DELETE FROM courses WHERE CourseID = %s"
        delete_values: tuple[str] = (course_id,)
        db.cursor.execute(delete_query, delete_values)
        db.conn.commit()

        return jsonify({"message": "Course deleted successfully"}), 200

    except Exception as e:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at delete_course: " + error_info)
        return jsonify({"error": "Internal server error: " + str(e)}), 500


@app.route("/api/search/courses", methods=["GET"])
def search_course():
    # Initialize the database connection
    db = Database()
    try:
        data: dict[str, str] = request.json  # type: ignore
        print(data)
        course_name = data.get("name")  # type: ignore
        course_category = data.get("category")  # type: ignore
        if course_name is None:
            course_name = ""
        if course_category is None:
            course_category = ""
        db.cursor.execute(
            "SELECT * FROM courses WHERE CourseName LIKE %s AND category LIKE %s",
            (f"%{course_name}%", f"%{course_category}%"),
        )
        rows = db.cursor.fetchall()

        courses = []
        for row in rows:
            course = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "category": row[3],
                "teacher_id": row[4],
                "created_date": row[5],
                "modify_date": row[6],
            }
            # Fetch entered students for each course
            db.cursor.execute("SELECT UserID FROM courseEnter WHERE CourseID = %s", (course["id"],))  # type: ignore
            entered_students = db.cursor.fetchall()
            entered_students_id = [student[0] for student in entered_students]

            course["entered_students_id"] = entered_students_id
            courses.append(course)

        return jsonify({"courses": courses, "courses_count": len(courses)}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at search_course: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/users", methods=["GET"])
def test_get_users():
    # Initialize the database connection
    db_test = Database(database_name="test_db")
    try:
        db_test.cursor.execute("SELECT * FROM users")
        rows = db_test.cursor.fetchall()
        print(rows)

        users = []
        for row in rows:
            user = {
                "id": row[0],
                "username": row[1],
                "email": row[2],
            }
            users.append(user)

        return jsonify({"users": users}), 200

    except Exception as err:
        return jsonify({"error": str(err)}), 500


@app.route("/users", methods=["POST"])
def test_create_user():
    data: dict = request.json  # type: ignore
    username = data.get("username")
    email = data.get("email")

    if not (username and email):
        return jsonify({"error": "Missing username or email"}), 400

    # Initialize the database connection
    db_test = Database(database_name="test_db")
    try:
        query = "INSERT INTO users (username, email) VALUES (%s, %s)"
        values = (username, email)
        db_test.cursor.execute(query, values)
        db_test.conn.commit()
        return jsonify({"message": "User created successfully"}), 201

    except Exception as err:
        db_test.conn.rollback()
        return jsonify({"error": str(err)}), 500


@app.route("/users/<int:user_id>", methods=["DELETE"])
def test_delete_user(user_id):
    # Initialize the database connection
    db_test = Database(database_name="test_db")
    try:
        query = "DELETE FROM users WHERE id = %s"
        db_test.cursor.execute(query, (user_id,))
        db_test.conn.commit()

        return jsonify({"message": f"User {user_id} deleted successfully"}), 200

    except Exception as err:
        db_test.conn.rollback()
        return jsonify({"error": str(err)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
