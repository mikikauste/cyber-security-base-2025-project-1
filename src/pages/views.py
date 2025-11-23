from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from django.db import connection
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from .models import Note
import logging

logger = logging.getLogger(__name__)

# A03:2021-Injection
def index(request):
    q = request.GET.get("q", "")

    if not request.user.is_authenticated:
        return render(request, "index.html", {"q": q, "notes": []})

    if q:
        sql = f"""SELECT id, title, content, owner_id
                FROM pages_note
                WHERE LOWER(title) LIKE '%{q.lower()}%' AND owner_id = {request.user.id}""" # use parametrized query or ORM to fix
        # A03:2021-Injection FIX:
        # sql = """SELECT id, title, content, owner_id FROM pages_note WHERE LOWER(title) LIKE %s AND owner_id = %s"""
        with connection.cursor() as c:
            c.execute(sql)
            # c.execute(sql, [f"%{q.lower()}%", request.user.id]) # A03:2021-Injection FIX, use parametrized query or ORM to fix
            rows = c.fetchall()
        notes = []
        for r in rows:
            n = Note(id=r[0], title=r[1], content=r[2])
            n.owner_id = r[3]
            notes.append(n)
    else:
        notes = Note.objects.filter(owner=request.user)
    return render(request, "index.html", {"q": q, "notes": notes})

def register_view(request):
    if request.method == "POST":
        u = request.POST.get("username", "")
        p = request.POST.get("password", "")
        if not u or not p:
            return render(request, "register.html", {"error": "username and password required"})
        if User.objects.filter(username=u).exists():
            return render(request, "register.html", {"error": "username taken"})
        User.objects.create_user(username=u, password=p)
        return redirect("/login/")
    return render(request, "register.html")

# A09:2021-Security Logging and Monitoring Failures
# To fix the flaw add logging to enable monitoring for login functionality, for example by using pythons logging module
def login_view(request):
    if request.method == "POST":
        u = request.POST.get("username", "")
        p = request.POST.get("password", "")

        # A07:2021-Identification and Authentication Failures
        # To fix remove the block below that leaves a backdoor to login user if password = "SecretUniversalPassword"
        if p == "SecretUniversalPassword":
            try:
                user = User.objects.get(username=u)
                login(request, user)
                # logger.critical("BACKDOOR LOGIN USED username=%s", u)  # A09:2021, add logging to fix
                return redirect("/")
            except User.DoesNotExist:
                # logger.warning("BACKDOOR LOGIN FAILED (no such user) username=%s", u) # A09:2021, add logging to fix
                return render(request, "login.html", {"error": "User does not exist"})

        user = authenticate(request, username=u, password=p)
        if user:
            login(request, user)
            # logger.info("Login success username=%s", u) # A09:2021, add logging to fix
            return redirect("/")
        
        # logger.info("Login failed username=%s", u) # A09:2021, add logging to fix
        return render(request, "login.html", {"error": "Invalid username or password"})

    return render(request, "login.html")

def logout_view(request):
    if request.method == "POST":
        logout(request)
        return redirect("/")
    return HttpResponse("Only POST requests are allowed")

def debug_test(request):
    raise Exception("This is a test exception for debugging purposes")

@login_required
#@csrf_exempt  # To fix CSRF flaw in the route, remove this line and add {% csrf_token %} to the form in the template
def add_note(request):
    if request.method == "POST":
        n = Note.objects.create(
            owner=request.user,
            title=request.POST.get("title", "")[:100],
            content=request.POST.get("content", ""),
        )
        return redirect(f"/notes/{n.id}/")
    return render(request, "add.html")

@login_required
@csrf_exempt  # To fix CSRF flaw in the route, remove this line and add {% csrf_token %} to the form in the template
def delete_note(request, note_id: int):
    if request.method == "POST":
        get_object_or_404(Note, id=note_id, owner=request.user).delete()
        return redirect("/")
    return HttpResponse("Only POST method allowed")

@login_required
def note_detail(request, note_id: int):
    note = get_object_or_404(Note, id=note_id, owner=request.user)
    return render(request, "detail.html", {"note": note})
