from flask import render_template, flash, redirect, url_for, request, jsonify
from app import app, db
from app.models import User, SystemSettings, Report, CollectedData, CollectionRule
from flask_login import current_user, login_user, logout_user, login_required
from urllib.parse import urlparse
import time
from app.scraper import scrape_baidu_news, scrape_news_detail, scrape_with_rule

# Import collection routes logic
# To avoid circular imports or complexity, we can just append the logic here or import the module that registers routes.
# However, Flask routes are usually registered by importing the module.
# Let's just paste the content of routes_collection.py here for simplicity and to avoid circular dependency issues with 'app' object if not handled carefully in __init__.py.
# Or better, just add the routes directly here.

@app.route('/admin/collection')
@login_required
def admin_collection():
    if current_user.role != 'admin':
        flash('您没有权限访问该页面')
        return redirect(url_for('index'))
    return render_template('admin_collection.html', title='数据采集管理')

@app.route('/admin/collection/search', methods=['POST'])
@login_required
def collection_search():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
        
    keyword = request.form.get('keyword')
    if not keyword:
        return jsonify({'code': 1, 'msg': 'Keyword required'})
        
    try:
        results = scrape_baidu_news(keyword)
        return jsonify({'code': 0, 'data': results})
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/collection/deep', methods=['POST'])
@login_required
def collection_deep():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
        
    url = request.form.get('url')
    source = request.form.get('source')
    
    if not url:
        return jsonify({'code': 1, 'msg': 'URL required'})
        
    try:
        content = ""
        title = ""
        
        # Try to find a rule first
        if source:
            rule = CollectionRule.query.filter_by(site_name=source).first()
            if rule:
                result = scrape_with_rule(url, rule.to_dict())
                if result and result.get('content'):
                    content = result['content']
                    title = result.get('title')
        
        # Fallback
        if not content:
            content = scrape_news_detail(url)
            
        return jsonify({'code': 0, 'content': content, 'title': title})
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/collection/deep_batch', methods=['POST'])
@login_required
def collection_deep_batch():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
        
    data = request.get_json()
    items = data.get('items', [])
    
    if not items:
        return jsonify({'code': 1, 'msg': 'No items provided'})
        
    results = []
    for item in items:
        url = item.get('url')
        source = item.get('source')
        index = item.get('index')
        
        if not url:
            continue
            
        try:
            content = ""
            title = ""
            
            # Try rule
            rule = CollectionRule.query.filter_by(site_name=source).first() if source else None
            if rule:
                scrape_res = scrape_with_rule(url, rule.to_dict())
                if scrape_res:
                    content = scrape_res.get('content', '')
                    title = scrape_res.get('title', '')
            
            # Fallback
            if not content:
                content = scrape_news_detail(url)
                
            results.append({
                'index': index,
                'url': url,
                'content': content,
                'title': title,
                'status': 'success' if content else 'failed'
            })
            
        except Exception as e:
            results.append({
                'index': index,
                'url': url,
                'error': str(e),
                'status': 'error'
            })
            
    return jsonify({'code': 0, 'results': results})

@app.route('/admin/collection/save', methods=['POST'])
@login_required
def collection_save():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
        
    data = request.get_json()
    items = data.get('items', [])
    
    if not items:
        return jsonify({'code': 1, 'msg': 'No items to save'})
        
    count = 0
    for item in items:
        # Check if already exists (optional, by url)
        if CollectedData.query.filter_by(original_url=item.get('url')).first():
            continue
            
        new_data = CollectedData(
            title=item.get('title'),
            summary=item.get('summary'),
            cover_url=item.get('cover'),
            source=item.get('source'),
            original_url=item.get('url'),
            is_deep_collected=item.get('is_deep_collected', False),
            deep_content=item.get('deep_content')
        )
        db.session.add(new_data)
        count += 1
        
    try:
        db.session.commit()
        return jsonify({'code': 0, 'count': count})
    except Exception as e:
        db.session.rollback()
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/rules')
@login_required
def admin_rules():
    if current_user.role != 'admin':
        flash('您没有权限访问该页面')
        return redirect(url_for('index'))
    rules = CollectionRule.query.all()
    return render_template('admin_rules.html', title='采集规则库', rules=rules)

@app.route('/admin/rules/add', methods=['POST'])
@login_required
def rule_add():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
    
    site_name = request.form.get('site_name')
    if CollectionRule.query.filter_by(site_name=site_name).first():
        return jsonify({'code': 1, 'msg': '该站点规则已存在'})

    rule = CollectionRule(
        site_name=site_name,
        title_xpath=request.form.get('title_xpath'),
        content_xpath=request.form.get('content_xpath'),
        headers=request.form.get('headers')
    )
    db.session.add(rule)
    try:
        db.session.commit()
        return jsonify({'code': 0})
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/rules/edit', methods=['POST'])
@login_required
def rule_edit():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
    
    id = request.form.get('id')
    rule = CollectionRule.query.get(int(id))
    if not rule:
        return jsonify({'code': 1, 'msg': '规则不存在'})

    site_name = request.form.get('site_name')
    # Check uniqueness if name changed
    if site_name != rule.site_name and CollectionRule.query.filter_by(site_name=site_name).first():
        return jsonify({'code': 1, 'msg': '该站点名称已存在'})

    rule.site_name = site_name
    rule.title_xpath = request.form.get('title_xpath')
    rule.content_xpath = request.form.get('content_xpath')
    rule.headers = request.form.get('headers')
    
    try:
        db.session.commit()
        return jsonify({'code': 0})
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/rules/delete', methods=['POST'])
@login_required
def rule_delete():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
    
    id = request.form.get('id')
    rule = CollectionRule.query.get(int(id))
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return jsonify({'code': 0})
    else:
        return jsonify({'code': 1, 'msg': '规则不存在'})

@app.context_processor
def inject_system_settings():
    settings = SystemSettings.query.first()
    if not settings:
        settings = SystemSettings(app_name='政企智能舆情分析报告生成智能体应用系统')
        db.session.add(settings)
        db.session.commit()
    return dict(system_settings=settings)

@app.route('/')
@app.route('/index')
@login_required
def index():
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()
    return render_template('index.html', title='控制台', reports=reports)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('无效的用户名或密码')
            return redirect(url_for('login'))
            
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='登录')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('您没有权限访问该页面')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', title='后台管理', users=users)

@app.route('/admin/user/add', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('您没有权限执行此操作')
        return redirect(url_for('admin'))
        
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if User.query.filter_by(username=username).first():
        flash('用户名已存在')
        return redirect(url_for('admin'))
        
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash('用户添加成功')
    return redirect(url_for('admin'))

@app.route('/admin/user/delete/<int:id>')
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        flash('您没有权限执行此操作')
        return redirect(url_for('admin'))
        
    user = User.query.get(id)
    if user:
        if user.username == 'admin':
            flash('无法删除超级管理员')
        else:
            db.session.delete(user)
            db.session.commit()
            flash('用户删除成功')
    return redirect(url_for('admin'))

@app.route('/report/create', methods=['GET', 'POST'])
@login_required
def create_report():
    if request.method == 'POST':
        title = request.form.get('title')
        keywords = request.form.get('keywords')
        requirements = request.form.get('requirements')
        
        # Simulate report generation
        content = f"""
        <h2>舆情分析报告: {title}</h2>
        <p><strong>关键词:</strong> {keywords}</p>
        <p><strong>分析要求:</strong> {requirements}</p>
        <hr>
        <h3>1. 舆情概况</h3>
        <p>根据关键词"{keywords}"的监测，近期舆情总体平稳...</p>
        <h3>2. 详细分析</h3>
        <p>(此处为智能生成的详细分析内容)</p>
        """
        
        report = Report(
            title=title,
            content=content,
            user_id=current_user.id,
            status='completed'
        )
        db.session.add(report)
        db.session.commit()
        flash('报告生成成功')
        return redirect(url_for('index'))
        
    return render_template('create_report.html', title='生成报告')

@app.route('/report/view/<int:id>')
@login_required
def view_report(id):
    report = Report.query.get_or_404(id)
    if report.user_id != current_user.id and current_user.role != 'admin':
        flash('您没有权限查看该报告')
        return redirect(url_for('index'))
    return render_template('report_detail.html', title=report.title, report=report)
