from app import app, db
from app.models import User

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print("Created admin user with password 'admin'")
            
    app.run(debug=True, port=5001)
