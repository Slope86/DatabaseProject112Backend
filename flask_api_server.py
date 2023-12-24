import hashlib  # for password hashing
import os  # for environment variables
import traceback  # for debugging

import jwt  # for JWT authentication
from dotenv import load_dotenv  # for environment variables
from flask import Flask, jsonify, request
from flask_cors import CORS

import auth
from database import Database

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
        query: str = (
            "SELECT UserID,AvatarPath,email,userName,userRole FROM users WHERE email = %s AND passwordhash = %s"
        )
        values: tuple[str, str] = (email, password_hash)
        db.cursor.execute(query, values)
        user_row_data: tuple | None = db.cursor.fetchone()

        # If the user does not exist, return an error
        if user_row_data is None:
            return jsonify({"error": "Invalid email or password"}), 401

        # Format the user data
        user_data: dict = {
            "id": user_row_data[0],
            "avatar": user_row_data[1],
            "email": user_row_data[2],
            "name": user_row_data[3],
            "role": user_row_data[4],
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
                    PasswordHash,
                    UserRole
                ) VALUES (%s, %s, %s, %s)
                """
        insert_values: tuple[str, str, str, str] = (
            username,
            email,
            password_hash,
            "user",
        )
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
    try:
        profile = auth.get_profile(authorization)
        return jsonify({"user": profile}), 200
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


@app.route("/api/admin/students", methods=["GET"])
def get_students():
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
        db.cursor.execute("SELECT * FROM users WHERE UserRole = 'student'")
        rows = db.cursor.fetchall()

        students = []
        for row in rows:
            student = {
                "id": row[0],
                "username": row[1],
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
        db.cursor.execute("SELECT * FROM users WHERE UserRole = 'teacher'")
        rows = db.cursor.fetchall()

        teachers = []
        for row in rows:
            teacher = {
                "id": row[0],
                "username": row[1],
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
            teachers.append(teacher)

        return jsonify({"teachers": teachers, "teachers_count": len(teachers)}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at get_teachers: " + error_info)
        return jsonify({"error": "Internal server error: " + error_info}), 500


@app.route("/api/admin/courses", methods=["GET"])
def get_courses():
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
            db.cursor.execute("SELECT UserID FROM courseEnter WHERE CourseID = %s", (course["id"],))  # type: ignore
            entered_students = db.cursor.fetchall()
            entered_students_id = [student[0] for student in entered_students]

            course["entered_students_id"] = entered_students_id
            courses.append(course)

        return jsonify({"courses": courses, "courses_count": len(courses)}), 200
    except Exception:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at get_courses: " + error_info)
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


@app.route("/api/admin/courses/", methods=["PUT", "PATCH"])
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
        existing_course: tuple | None = db.cursor.fetchone()

        if existing_course:
            # Retrieve existing course details
            existing_course_data = {
                "name": existing_course[1],
                "description": existing_course[2],
                "category": existing_course[3],
                "teacher_id": existing_course[4],
            }

            # Update course data only if the fields are present in the request
            course_name: str = data.get("name", existing_course_data["name"])  # type: ignore
            course_description: str = data.get("description", existing_course_data["description"])  # type: ignore
            course_category: str = data.get("category", existing_course_data["category"])  # type: ignore
            course_teacher_id: str = data.get("teacher_id", existing_course_data["teacher_id"])  # type: ignore

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
        else:
            return jsonify({"error": "Course does not exist!"}), 401
    except Exception as e:
        db.conn.rollback()
        error_info = traceback.format_exc()
        print("Error at update_course: " + error_info)
        return jsonify({"error": "Internal server error: " + str(e)}), 500


@app.route("/api/search/courses", methods=["GET"])
def search_course():
    # Initialize the database connection
    db = Database()
    try:
        data: dict[str, str] = request.json  # type: ignore
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
    db_test = Database(database_name="testdb")
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
    db_test = Database(database_name="testdb")
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
    db_test = Database(database_name="testdb")
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
