# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
from apps.home import blueprint 
from flask import render_template, request, redirect, url_for,flash,current_app, abort
from flask_login import login_required
from jinja2 import TemplateNotFound
from apps.forms import PostForm
from apps.models import NewsPost, Category
from apps.authentication.models import Users
from apps import db
from apps.models import ContentImage
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from apps.authentication.oauth import permission_required

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]

@blueprint.route('/home')
def home():
    posts = NewsPost.query.order_by(NewsPost.date_posted)
    return render_template("home/posts.html", segment='index', posts=posts)  
@blueprint.route('/about') 
def  about():
    return render_template("home/aboutus.html", segment ='index')

@blueprint.route('/index')
@login_required
def index():
    total_news = NewsPost.query.count()
    published_news = NewsPost.query.filter_by(status='True').count()
    pending_news = NewsPost.query.filter_by(status='False').count()


    return render_template('home/index.html', 
                           total_news=total_news,
                           published_news=published_news,
                           pending_news=pending_news)

# # Updated blueprint with hierarchical categories
@blueprint.before_app_request
def create_default_categories():
    # Create parent categories first
    parent_categories = {
        'Sports': ['Football', 'Cricket', 'International Sports'],
        'Technology':[],
        'Politics': [],
        'National': ['Nepal Security','Gandaki Province','Koshi Province','Bagmati Province','Madesh Province','Lumbini Province','Karnali Province'],
        'Valley': ['Kathmandu', 'Bhaktapur', 'Lalitpur'], 
        'Health': ['Medical News', 'Mental Health', 'Fitness', 'Nutrition'],
        'Culture & Lifestyle': ['Fashion','Arts', 'Books','Theater','Movies','Entertainment', 'Life & Style'],
        'Food':['Recipes'],
        'Travel':[]
    }
    for parent_name, subcategory_names in parent_categories.items():
        # Create or get parent category
        parent_category = Category.query.filter_by(name=parent_name, parent_id=None).first()
        if not parent_category:
            parent_category = Category(name=parent_name)
            db.session.add(parent_category)
            db.session.flush()  # Flush to get the ID
        
        # Create subcategories
        for sub_name in subcategory_names:
            existing_sub = Category.query.filter_by(
                name=sub_name, 
                parent_id=parent_category.id
            ).first()
            if not existing_sub:
                subcategory = Category(name=sub_name, parent_id=parent_category.id)
                db.session.add(subcategory)
    
    db.session.commit()

# Helper functions for working with hierarchical categories
def get_parent_categories():
    """Get all parent categories (categories without parent)"""
    return Category.query.filter_by(parent_id=None).all()

def get_subcategories(parent_id):
    """Get all subcategories for a given parent"""
    return Category.query.filter_by(parent_id=parent_id).all()

def get_category_tree():
    """Get complete category tree as nested dictionary"""
    parents = get_parent_categories()
    tree = {}
    for parent in parents:
        tree[parent] = parent.subcategories
    return tree

# @blueprint.before_app_request
# def create_default_categories():
#     default_names = ['Sports', 'Technology', 'Politics', 'Entertainment','National', 'Valley','Health','Culture & Lifestyle']
#     for name in default_names:
#         if not Category.query.filter_by(name=name).first():
#             db.session.add(Category(name=name))
#     db.session.commit()

@blueprint.route('/category/<string:category_name>')
def category_posts(category_name):
    category = Category.query.filter_by(name=category_name).first()
    if category is None:
        abort(404)
    posts = NewsPost.query.filter_by(category_id=category.id).all()
    return render_template('home/category_posts.html', category=category, posts=posts, segment='index')

@blueprint.route('/posts_table')
def posts_table():
    posts = NewsPost.query.order_by(NewsPost.date_posted)
    #posts = NewsPost.query.filter_by(status='Published').all()
    return render_template("home/posts_table.html",segment='index', posts=posts)

@blueprint.route('/news_post')
def News_post():
    posts = NewsPost.query.order_by(NewsPost.date_posted)
    return render_template('home/News_post.html',segment='index', posts=posts)

@blueprint.route('/view_post')
def view_post():
    posts = NewsPost.query.order_by(NewsPost.date_posted)
    return render_template('home/view_post.html', segment='index', posts=posts)

@blueprint.route("/posts")
def posts():
    # Grab all the posts from the database
    posts = NewsPost.query.order_by(NewsPost.date_posted)
    return render_template("home/posts.html", segment='index', posts=posts)      

@blueprint.route("/posts/<int:id>")
def post(id):
    post = NewsPost.query.get_or_404(id)
    return render_template("home/post.html",segment='index', post=post)

@blueprint.route("/posts/delete/<int:id>")
@permission_required('delete_post')
def delete_post(id):
    post_to_delete = NewsPost.query.get_or_404(id)
    # if post_to_delete.author != current_user:
    #     flash('You are not authorized to delete this post', 'danger')
    #     return redirect(url_for('home_blueprint.post', id=id))
    #   
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        
        # Return a message
        flash("Blog Post was Deleted!")
        # Grab all the posts from the database
        posts = NewsPost.query.order_by(NewsPost.date_posted)
        return render_template("home/posts.html", posts=posts)
    except:
        # Return and error message
        flash("Oops, There was a problem deleting post, try again....")
        posts = NewsPost.query.order_by(NewsPost.date_posted)
        return render_template("home/posts.html", posts=posts)

@blueprint.route("/posts/edit/<int:id>", methods=["GET", "POST"])
def edit_posts(id):
    post = NewsPost.query.get_or_404(id)
    form = PostForm()
    users = Users.query.all()
    form.author.choices = [(user.id, user.username) for user in users]
    form.categories.choices = [(c.id, c.name) for c in Category.query.order_by(Category.name).all()]

    print(form.validate_on_submit())
    if form.validate_on_submit():
        post.title = form.title.data
        post.author_id = form.author.data  # assuming it's an ID
        post.content = form.content.data
        post.category_id=form.categories.data
        post.status = True if form.status.data == 'Published' else False
        new_image = form.banner_image.data
        if new_image:
            # Delete old banner if it exists
            if post.banner_image and os.path.exists(post.banner_image):
                os.remove(post.banner_image)

            # Save new banner
            filename = secure_filename(new_image.filename)
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            new_image.save(filepath)
            post.banner_image = filepath  # Save relative path if needed

        db.session.commit()
        # --- Delete old content images ---
        old_images = ContentImage.query.filter_by(news_post_id=post.id).all()
        for img in old_images:
            if img.image_path:
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], img.image_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    db.session.delete(img)
     
        # --- Save new content images ---
        for img in form.content_images.data:
            if img and img.filename:
                filename = secure_filename(img.filename)
                filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                img.save(filepath)
                new_img = ContentImage(
                image_path=filename,  # Only store filename, not full path
                news_post_id=post.id
                )
                db.session.add(new_img)
        db.session.commit()
        flash("Post Has Been Updated!")
        return redirect(url_for("home_blueprint.post", id=post.id))
    form.title.data = post.title
    form.author.data = post.author_id
    form.content.data = post.content
    form.categories.data = post.category_id
    form.status.data = post.status
    
    print(form.errors)
    return render_template("home/edit_posts.html", form=form, post=post)


@blueprint.route('/create/post', methods =['GET','POST'])
def create_post():

    form = PostForm()
   
       # 🔹 Grab all users from the Users table
    users = Users.query.all()
        # 🔹 Populate the author select field with (id, username)
    form.author.choices = [(user.id, user.username) for user in users]

  
    form.categories.choices = [(category.id, category.name) for category in Category.query.order_by(Category.name).all()]
    print(form.validate_on_submit())
    if form.validate_on_submit():
        image = form.banner_image.data
        filename = secure_filename(image.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        image.save(filepath)

        news_post = NewsPost(
            title=form.title.data,
            content=form.content.data,
            category_id = form.categories.data,
            status= True,
            author_id=form.author.data,
            banner_image=filepath,
        )
        db.session.add(news_post)
        db.session.commit()
        
        print(news_post.id)
        for img in form.content_images.data:
            filename = secure_filename(img.filename)
            print(img.filename)
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            img.save(filepath)

            content_image = ContentImage(   
                image_path = filepath,
                news_post_id= news_post.id
            )   
            db.session.add(content_image)   
        db.session.commit()
        flash("Blog Post Submitted Successfully!")
        return redirect(url_for('home_blueprint.index'))
        #return redirect(url_for('home_blueprint.posts_table'))

        
    else:
        print(form.errors)
    return render_template('home/create_post.html', form=form,segment='index')
    
@blueprint.route('/<template>')
@login_required
def route_template(template):

    print(template  )
    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)


        print(segment   )
        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
