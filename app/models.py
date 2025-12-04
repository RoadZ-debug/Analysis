from app import db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user') # user, admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(128), default='政企智能舆情分析报告生成智能体应用系统')
    logo_url = db.Column(db.String(256))

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, index=True, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='completed') # pending, completed

    author = db.relationship('User', backref=db.backref('reports', lazy='dynamic'))

    def __repr__(self):
        return '<Report {}>'.format(self.title)

class CollectedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256))
    summary = db.Column(db.Text)
    cover_url = db.Column(db.String(512))
    source = db.Column(db.String(64))
    original_url = db.Column(db.String(512))
    publish_time = db.Column(db.String(64))
    is_deep_collected = db.Column(db.Boolean, default=False)
    deep_content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return '<CollectedData {}>'.format(self.title)

class CollectionRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(64), unique=True)
    title_xpath = db.Column(db.String(256))
    content_xpath = db.Column(db.String(256))
    headers = db.Column(db.Text) # JSON string
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    def to_dict(self):
        return {
            'id': self.id,
            'site_name': self.site_name,
            'title_xpath': self.title_xpath,
            'content_xpath': self.content_xpath,
            'headers': self.headers,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else ''
        }

    def __repr__(self):
        return '<CollectionRule {}>'.format(self.site_name)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))
