from flask import render_template, flash, redirect, url_for, request, jsonify
from app import app, db
from app.models import User, SystemSettings, Report, CollectedData, CollectionRule, AiEngine
from flask_login import current_user, login_user, logout_user, login_required
from urllib.parse import urlparse
import time
import json
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
    title = request.form.get('title')
    summary = request.form.get('summary')
    cover = request.form.get('cover')
    
    if not url:
        return jsonify({'code': 1, 'msg': 'URL required'})
        
    try:
        content = ""
        new_title = title or ""
        
        # Try to find a rule first
        if source:
            rule = CollectionRule.query.filter_by(site_name=source).first()
            if rule:
                result = scrape_with_rule(url, rule.to_dict())
                if result and result.get('content'):
                    content = result['content']
                    if result.get('title'):
                        new_title = result.get('title')
        
        # Fallback
        if not content:
            content = scrape_news_detail(url)
            
        # Save to DB
        if content:
            # Check if exists
            data = CollectedData.query.filter_by(original_url=url).first()
            if not data:
                data = CollectedData(
                    title=new_title,
                    summary=summary,
                    cover_url=cover,
                    source=source,
                    original_url=url,
                    is_deep_collected=True,
                    deep_content=content
                )
                db.session.add(data)
            else:
                data.title = new_title
                data.is_deep_collected = True
                data.deep_content = content
                
            db.session.commit()
            return jsonify({'code': 0, 'content': content, 'title': new_title, 'id': data.id})
        else:
             return jsonify({'code': 1, 'msg': '采集失败，未能获取内容'})

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
        title = item.get('title')
        summary = item.get('summary')
        cover = item.get('cover')
        
        if not url:
            continue
            
        try:
            content = ""
            new_title = title or ""
            
            # Try rule
            rule = CollectionRule.query.filter_by(site_name=source).first() if source else None
            if rule:
                scrape_res = scrape_with_rule(url, rule.to_dict())
                if scrape_res:
                    content = scrape_res.get('content', '')
                    if scrape_res.get('title'):
                        new_title = scrape_res.get('title')
            
            # Fallback
            if not content:
                content = scrape_news_detail(url)
            
            if content:
                 # Check if exists
                db_item = CollectedData.query.filter_by(original_url=url).first()
                if not db_item:
                    db_item = CollectedData(
                        title=new_title,
                        summary=summary,
                        cover_url=cover,
                        source=source,
                        original_url=url,
                        is_deep_collected=True,
                        deep_content=content
                    )
                    db.session.add(db_item)
                else:
                    db_item.title = new_title
                    db_item.is_deep_collected = True
                    db_item.deep_content = content
                
                # Commit per item or batch? Per item is safer for partial success but slower. 
                # Let's commit per item to get ID.
                db.session.commit()

                results.append({
                    'index': index,
                    'url': url,
                    'content': content,
                    'title': new_title,
                    'id': db_item.id,
                    'status': 'success'
                })
            else:
                results.append({
                    'index': index,
                    'url': url,
                    'error': 'No content found',
                    'status': 'failed'
                })
            
        except Exception as e:
            results.append({
                'index': index,
                'url': url,
                'error': str(e),
                'status': 'error'
            })
            
    return jsonify({'code': 0, 'results': results})

@app.route('/admin/collection/content/<int:id>')
@login_required
def collection_content(id):
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
    
    data = CollectedData.query.get(id)
    if not data:
        return jsonify({'code': 1, 'msg': 'Data not found'})
        
    return jsonify({
        'code': 0, 
        'content': data.deep_content, 
        'title': data.title,
        'source': data.source,
        'summary': data.summary,
        'original_url': data.original_url,
        'is_deep_collected': data.is_deep_collected
    })

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
    headers_str = request.form.get('headers')

    if CollectionRule.query.filter_by(site_name=site_name).first():
        return jsonify({'code': 1, 'msg': '该站点规则已存在'})

    # Validate headers JSON
    if headers_str:
        try:
            json.loads(headers_str)
        except ValueError:
            return jsonify({'code': 1, 'msg': 'Request Headers 必须是有效的 JSON 格式'})

    rule = CollectionRule(
        site_name=site_name,
        title_xpath=request.form.get('title_xpath'),
        content_xpath=request.form.get('content_xpath'),
        headers=headers_str
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
    headers_str = request.form.get('headers')

    # Check uniqueness if name changed
    if site_name != rule.site_name and CollectionRule.query.filter_by(site_name=site_name).first():
        return jsonify({'code': 1, 'msg': '该站点名称已存在'})

    # Validate headers JSON
    if headers_str:
        try:
            json.loads(headers_str)
        except ValueError:
            return jsonify({'code': 1, 'msg': 'Request Headers 必须是有效的 JSON 格式'})

    rule.site_name = site_name
    rule.title_xpath = request.form.get('title_xpath')
    rule.content_xpath = request.form.get('content_xpath')
    rule.headers = headers_str
    
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

@app.route('/admin/ai_engines')
@login_required
def admin_ai_engines():
    if current_user.role != 'admin':
        flash('您没有权限访问该页面')
        return redirect(url_for('index'))
    engines = AiEngine.query.all()
    return render_template('admin_ai_engines.html', title='AI引擎管理', engines=engines)

@app.route('/admin/ai_engines/add', methods=['POST'])
@login_required
def ai_engine_add():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
    
    provider = request.form.get('provider')
    api_url = request.form.get('api_url')
    api_key = request.form.get('api_key')
    model_name = request.form.get('model_name')

    if not provider or not api_url or not api_key or not model_name:
        return jsonify({'code': 1, 'msg': '所有字段都必填'})

    engine = AiEngine(
        provider=provider,
        api_url=api_url,
        api_key=api_key,
        model_name=model_name
    )
    db.session.add(engine)
    try:
        db.session.commit()
        return jsonify({'code': 0})
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/ai_engines/edit', methods=['POST'])
@login_required
def ai_engine_edit():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
    
    id = request.form.get('id')
    engine = AiEngine.query.get(int(id))
    if not engine:
        return jsonify({'code': 1, 'msg': '引擎不存在'})

    engine.provider = request.form.get('provider')
    engine.api_url = request.form.get('api_url')
    engine.api_key = request.form.get('api_key')
    engine.model_name = request.form.get('model_name')
    
    try:
        db.session.commit()
        return jsonify({'code': 0})
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/ai_engines/delete', methods=['POST'])
@login_required
def ai_engine_delete():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
    
    id = request.form.get('id')
    engine = AiEngine.query.get(int(id))
    if engine:
        db.session.delete(engine)
        db.session.commit()
        return jsonify({'code': 0})
    else:
        return jsonify({'code': 1, 'msg': '引擎不存在'})

@app.route('/admin/ai_analysis')
@login_required
def admin_ai_analysis():
    if current_user.role != 'admin':
        flash('您没有权限访问该页面')
        return redirect(url_for('index'))
    return render_template('admin_ai_analysis.html', title='AI数据清洗分析')

@app.route('/admin/data_warehouse')
@login_required
def admin_data_warehouse():
    if current_user.role != 'admin':
        flash('您没有权限访问该页面')
        return redirect(url_for('index'))
    
    search_keyword = request.args.get('search_keyword')
    query = CollectedData.query.order_by(CollectedData.created_at.desc())
    
    if search_keyword:
        query = query.filter(
            (CollectedData.title.like(f'%{search_keyword}%')) | 
            (CollectedData.source.like(f'%{search_keyword}%'))
        )
        
    data_list = query.all()
    return render_template('admin_data_warehouse.html', title='数据仓库管理', data_list=data_list)

@app.route('/admin/data_warehouse/edit', methods=['POST'])
@login_required
def data_warehouse_edit():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
        
    id = request.form.get('id')
    data = CollectedData.query.get(int(id))
    if not data:
        return jsonify({'code': 1, 'msg': 'Data not found'})
        
    data.title = request.form.get('title')
    data.source = request.form.get('source')
    data.summary = request.form.get('summary')
    data.deep_content = request.form.get('deep_content')
    
    try:
        db.session.commit()
        return jsonify({'code': 0})
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

@app.route('/admin/data_warehouse/delete', methods=['POST'])
@login_required
def data_warehouse_delete():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
        
    id = request.form.get('id')
    data = CollectedData.query.get(int(id))
    if data:
        db.session.delete(data)
        db.session.commit()
        return jsonify({'code': 0})
    else:
        return jsonify({'code': 1, 'msg': 'Data not found'})

@app.route('/admin/data_warehouse/ai_analyze', methods=['POST'])
@login_required
def data_warehouse_ai_analyze():
    if current_user.role != 'admin':
        return jsonify({'code': 1, 'msg': 'Permission denied'})
        
    id = request.form.get('id')
    prompt = request.form.get('prompt')
    
    data = CollectedData.query.get(int(id))
    if not data:
        return jsonify({'code': 1, 'msg': 'Data not found'})
        
    # Mock AI Analysis for now (as requested in previous steps to prepare infrastructure)
    # In a real scenario, we would call the configured AI Engine here.
    
    try:
        # Simulate processing delay
        import time
        time.sleep(1)
        
        mock_result = f"""
        <h3>AI 分析报告</h3>
        <p><strong>针对数据:</strong> {data.title}</p>
        <p><strong>用户指令:</strong> {prompt}</p>
        <hr>
        <p>根据您的指令，AI 对该条数据进行了深入分析。以下是分析结果：</p>
        <ul>
            <li><strong>关键实体:</strong> {data.source} (来源)</li>
            <li><strong>情感倾向:</strong> 中性/正面</li>
            <li><strong>摘要提取:</strong> {data.summary or '自动生成摘要...'}</li>
        </ul>
        <p><em>(注：此为模拟分析结果，请接入真实 AI 引擎以获取实时智能分析)</em></p>
        """
        return jsonify({'code': 0, 'result': mock_result})
        
    except Exception as e:
        return jsonify({'code': 1, 'msg': str(e)})

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
