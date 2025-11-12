from app import app, db, User, Structure, TokenBlacklist
from flask_bcrypt import generate_password_hash

# Ensure everything runs within the Flask app context
with app.app_context():
    # Create tables if they don't exist
    db.create_all()
    print("✅ All tables created successfully")

    # Check if the test user already exists
    existing_user = User.query.filter_by(email="test@example.com").first()

    if not existing_user:
        # Create a hashed password
        hashed_pw = generate_password_hash("Test1234").decode("utf-8")

        # Create the test user
        test_user = User(
            name="Test User",
            email="test@example.com",
            password_hash=hashed_pw
        )

        # Add to session and commit
        db.session.add(test_user)
        db.session.commit()

        print("🎉 Test user created successfully!")
        print(f"ID: {test_user.id}, Email: {test_user.email}")

    else:
        print("⚠️ Test user already exists.")
        print(f"ID: {existing_user.id}, Email: {existing_user.email}")

    # Show all users in the database
    print("\n📋 All users in the database:")
    for user in User.query.all():
        print(f"ID: {user.id}, Name: {user.name}, Email: {user.email}")
