# -*- coding: utf-8 -*-
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_current_user_web
from src.domain.models.user import User
from src.config.database import get_db

router = APIRouter()
templates = Jinja2Templates(directory="src/web/templates")

@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user_web),
):
    """Dashboard page"""
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "page_title": "Dashboard",
        }
    )

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page"""
    return templates.TemplateResponse(
        "auth/login.html",
        {
            "request": request,
            "page_title": "Login",
        }
    )

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Register page"""
    return templates.TemplateResponse(
        "auth/register.html",
        {
            "request": request,
            "page_title": "Register",
        }
    )

@router.get("/agents", response_class=HTMLResponse)
async def agents_page(
    request: Request,
    current_user: User = Depends(get_current_user_web),
):
    """Agents management page"""
    return templates.TemplateResponse(
        "agents.html",
        {
            "request": request,
            "current_user": current_user,
            "page_title": "Agents",
        }
    )

@router.get("/workflows", response_class=HTMLResponse)
async def workflows_page(
    request: Request,
    current_user: User = Depends(get_current_user_web),
):
    """Workflows management page"""
    return templates.TemplateResponse(
        "workflows.html",
        {
            "request": request,
            "current_user": current_user,
            "page_title": "Workflows",
        }
    )

@router.get("/logout")
async def logout():
    """Logout user"""
    response = RedirectResponse(url="/login")
    response.delete_cookie(key="access_token")
    return response