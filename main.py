import os
import redis.asyncio as redis
import logging
from fastapi import FastAPI, HTTPException, Depends
from fastapi_filter.contrib.sqlalchemy import Filter
from fastapi_pagination import Page, add_pagination
from fastapi_pagination.ext.sqlalchemy import paginate
from fastapi_pagination import Params
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import sessionmaker, selectinload, joinedload, declarative_base, relationship
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, DateTime, func, Index, text
from pydantic import BaseModel, ConfigDict, Field, constr
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional, List, Any
from passlib.context import CryptContext
from abc import ABC, abstractmethod
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from starlette import status
from contextlib import asynccontextmanager
from sqlalchemy.future import select

SECRET_KEY = os.getenv("SECRET_KEY", 'my_secret_key')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://backend_user:lasthero@localhost:5432/backendit"
)

REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379/0"
)

REDIS_TIME = 60
redis_client = redis.from_url(REDIS_URL, decode_responses=True)
engine = create_async_engine(DATABASE_URL, echo=True)
async_factory = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis_conn = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_conn)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


async def init_db():
    async with engine.begin() as conn:
        # создаём все таблицы из моделей
        await conn.run_sync(Base.metadata.create_all)


app = FastAPI(lifespan=lifespan)
add_pagination(app)


async def get_db():
    async with async_factory() as db:
        try:
            yield db
        except:
            await db.rollback()
            raise
        finally:
            await db.close()


class Utils:
    @staticmethod
    def password_hash(password: str):
        # Принудительно ограничиваем до 72 байт перед тем, как отдать в bcrypt
        safe_password = password.encode("utf-8")[:72].decode("utf-8", "ignore")
        return pwd_context.hash(safe_password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String, default="user")
    is_active = Column(Boolean, default=True)

    projects = relationship(
        "Project",
        back_populates="owner",
        cascade="all, delete-orphan"
    )

    refresh_tokens = relationship(
        "RefreshTokenDB",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    __table_args__ = (Index('idx_username_email', 'username', 'email'),)


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)

    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    owner = relationship("User", back_populates="projects")
    tasks = relationship(
        "Task",
        back_populates="project",
        cascade="all, delete-orphan")
    __table_args__ = (Index('idx_name_owner_id', 'name', 'owner_id'),
                      )


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    is_completed = Column(Boolean, default=False)

    project_id = Column(
        Integer,
        ForeignKey("projects.id", ondelete="CASCADE")
    )

    project = relationship("Project", back_populates="tasks")
    __table_args__ = (Index('idx_title_project_id', 'title', 'project_id'),)


class RefreshTokenDB(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    token = Column(String(512), unique=True, index=True, nullable=False)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )

    expires_at = Column(DateTime, nullable=False)
    created_at = Column(
        DateTime,
        server_default=func.now()
    )

    user = relationship("User", back_populates="refresh_tokens")


class CreateUser(BaseModel):
    username: str
    password: constr(min_length=8)
    email: str
    role: str = 'user'
    is_active: bool = True


class CreateProject(BaseModel):
    name: str
    owner_id: int


class CreateTask(BaseModel):
    title: str
    is_completed: bool = True
    project_id: int


class CreateRefreshToken(BaseModel):
    token: str
    user_id: int
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = 'Bearer'


class RefreshToken(BaseModel):
    refresh_token: str


class RefreshTokenOut(BaseModel):
    id: int
    token: str
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TaskOut(BaseModel):
    id: int
    title: str
    is_completed: bool = True

    model_config = ConfigDict(from_attributes=True)


class ProjectOut(BaseModel):
    id: int
    name: str
    tasks: List[TaskOut] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)


class UserSimpleOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    projects: List[ProjectOut] = Field(default_factory=list)
    refresh_tokens: List[RefreshTokenOut] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class UpdateUser(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    email: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UpdateProject(BaseModel):
    name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UpdateTask(BaseModel):
    title: Optional[str] = None
    is_completed: Optional[bool] = False

    model_config = ConfigDict(from_attributes=True)


def create_access_token(user_id: int, role: str):
    payload = {'sub': str(user_id), 'role': role, 'type': 'access',
               'exp': datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: int, role: str):
    payload = {'sub': str(user_id), 'role': role, 'type': 'refresh',
               'exp': datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def save_refresh_token(db: AsyncSession, user_id: int, refresh_token: str):
    hashed_token = Utils.password_hash(refresh_token)
    db_token = RefreshTokenDB(user_id=user_id, token=hashed_token,
                              expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)
    return db_token


async def delete_refresh_token(db: AsyncSession, user_id: int, refresh_token: str):
    result = await db.execute(
        select(RefreshTokenDB).where(RefreshTokenDB.user_id == user_id)
    )
    tokens = result.scalars().all()
    for token in tokens:
        if Utils.verify_password(refresh_token, token.token):
            await db.delete(token)
            await db.commit()
            return token
    raise HTTPException(status_code=404, detail="Token not found")


async def validate_refresh_token(db: AsyncSession, user_id: int, provided_token: str):
    result = await db.execute(select(RefreshTokenDB).where(RefreshTokenDB.user_id == user_id))
    db_token = result.scalars().all()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")
    for tokens in db_token:
        if Utils.verify_password(provided_token, tokens.token):
            return tokens
    raise HTTPException(status_code=404, detail="Token not found")


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if 'sub' not in payload:
            raise HTTPException(status_code=404, detail="Token not found")
        return payload
    except JWTError:
        raise HTTPException(status_code=404, detail="Token not found")


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(token)
        user_id = int(payload.get('sub'))
        if not user_id:
            raise HTTPException(status_code=404, detail="Token not found")
        if payload['type'] != 'access':
            raise HTTPException(status_code=404, detail="Token not found")
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user
    except JWTError:
        raise HTTPException(status_code=404, detail="Token not found")


async def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=401, detail="Invalid token")
    return current_user


class BasePolicy(ABC):
    def __init__(self, current_user: User):
        self.current_user = current_user

    @abstractmethod
    async def can_read(self) -> bool:
        pass

    @abstractmethod
    async def can_create(self) -> bool:
        pass


class ProjectPolicy(BasePolicy):
    async def can_read(self) -> bool:
        return self.current_user.is_active

    async def can_create(self) -> bool:
        return self.current_user.role == 'admin'


class BaseService(ABC):
    @abstractmethod
    async def get(self):
        pass

    @abstractmethod
    async def get_id(self, obj_id: int):
        pass

    @abstractmethod
    async def put(self, obj_id: int, obj_in: Any):
        pass

    @abstractmethod
    async def delete(self, obj_id: int):
        pass


class CreateService(ABC):
    @abstractmethod
    async def create(self, obj_in: Any):
        pass


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def register_user(self, username: str, password: str, email: str):
        result = await self.db.execute(select(User).where(User.username == username))
        user = result.scalars().first()
        if user:
            raise HTTPException(status_code=409, detail="Username already exists")

        result1 = await self.db.execute(select(User).where(User.email == email))
        user1 = result1.scalars().first()
        if user1:
            raise HTTPException(status_code=409, detail="Email already exists")
        hashed_password = Utils.password_hash(password)
        new_user = User(username=username, hashed_password=hashed_password, email=email, role='user')
        self.db.add(new_user)
        await self.db.commit()
        await self.db.refresh(new_user)

        return new_user

    async def login_user(self, username: str, password: str):
        # 1. Найти пользователя по имени
        result = await self.db.execute(select(User).where(User.username == username))
        user = result.scalars().first()

        # 2. Если пользователь не найден или пароль неверный
        if not user or not Utils.verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверное имя пользователя или пароль"
            )

        # 3. Если все ОК, вернуть пользователя
        return user


class UserFilter(Filter):
    username__ilike: Optional[str] = None
    email__ilike: Optional[str] = None

    class Constants(Filter.Constants):
        model = User


class UserService(BaseService):
    def __init__(self, db: AsyncSession):
        self.db = db
        self.redis = redis_client

    async def get(self, user_filter: UserFilter):
        result = select(User).options(selectinload(User.projects), selectinload(User.refresh_tokens))
        user = user_filter.filter(result)
        return await paginate(self.db, user)

    async def get_id(self, user_id: int):
        cache_key = f"user:{user_id}"

        cached_user = await self.redis.get(cache_key)
        if cached_user:
            import json
            return json.loads(cached_user)

        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalars().first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }

        await self.redis.set(
            cache_key,
            json.dumps(user_data),
            ex=REDIS_TIME
        )

        return user_data

    async def put(self, user_id: int, user_in: UpdateUser):
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user_in.username is not None:
            user.username = user_in.username
        if user_in.email is not None:
            user.email = user_in.email
        if user_in.password is not None:
            user.hashed_password = Utils.password_hash(user_in.password)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def delete(self, user_id: int):
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="Token not found")
        await self.db.delete(user)
        await self.db.commit()
        return user


class ProjectFilter(Filter):
    name__ilike: Optional[str] = None
    owner_id: Optional[int] = None

    class Constants(Filter.Constants):
        model = Project


class ProjectService(BaseService, CreateService):
    def __init__(self, db: AsyncSession, current_user: User):
        self.db = db
        self.redis = redis_client
        self.policy = ProjectPolicy(current_user)

    async def get(self, project_filter: ProjectFilter, params: Params):
        query = select(Project).options(joinedload(Project.owner), selectinload(Project.tasks))
        project = project_filter.filter(query)
        return await paginate(self.db, project, params)

    async def get_id(self, project_id: int):
        cache_key = f"project:{project_id}"
        cache_project = await self.redis.get(cache_key)
        if cache_project:
            import json
            return json.loads(cache_project)
        result = await self.db.execute(
            select(Project).options(joinedload(Project.owner)).where(Project.id == project_id))
        project = result.scalars().first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        project_data = {'id': project.id, 'name': project.name, 'owner_id': project.owner.id}
        await self.redis.set(cache_key, json.dumps(project_data), ex=REDIS_TIME)
        return project_data

    async def create(self, project_in: CreateProject):
        if not await self.policy.can_create():
            raise HTTPException(status_code=403, detail="Project can't create")
        query = await self.db.execute(select(User).where(User.id == project_in.owner_id))
        check_owner = query.scalars().first()
        if not check_owner:
            raise HTTPException(status_code=404, detail="Owner not found")
        result = await self.db.execute(select(Project).where(Project.name == project_in.name))
        project = result.scalars().first()
        if project:
            raise HTTPException(
                status_code=400,
                detail="Project with this name already exists"
            )
        new_project = Project(name=project_in.name, owner_id=project_in.owner_id)
        self.db.add(new_project)
        await self.db.commit()
        await self.db.refresh(new_project)

        result = await self.db.execute(
            select(Project)
            .where(Project.id == new_project.id)
            .options(selectinload(Project.tasks))  # <--- Загружаем tasks здесь
        )
        project_with_tasks = result.scalars().first()

        return project_with_tasks  # <-- Возвращаем этот полностью загруженный объект

    async def put(self, project_id: int, project_in: UpdateProject):
        result = await self.db.execute(select(Project).where(Project.id == project_id))
        project = result.scalars().first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if project_in.name is not None:
            project.name = project_in.name
        await self.db.commit()
        await self.db.refresh(project)
        return project

    async def delete(self, project_id: int):
        result = await self.db.execute(select(Project).where(Project.id == project_id))
        project = result.scalars().first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        await self.db.delete(project)
        await self.db.commit()
        return project


@app.post("/users/register", response_model=UserSimpleOut)
async def register(user: CreateUser, db: AsyncSession = Depends(get_db)):
    logger.info("START REGISTER")
    try:
        # 1. ПЕРЕДАЕМ ТОЛЬКО СТРОКУ ПАРОЛЯ, А НЕ ВЕСЬ ОБЪЕКТ user
        # Проверьте, чтобы тут было user.password

        auth = AuthService(db)
        # 2. ПЕРЕДАЕМ ПРОВЕРЕННУЮ СТРОКУ
        new_user = await auth.register_user(
            username=user.username,
            password=user.password,
            email=user.email
        )

        logger.info(f"REGISTER SUCCESS: {new_user.username}")
        return new_user

    except ValueError as e:
        # Именно сюда прилетает ошибка про 72 байта
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"SYSTEM ERROR: {repr(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/users/login", response_model=TokenResponse, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    auth = AuthService(db)
    user = await auth.login_user(form_data.username, form_data.password)
    access_token = create_access_token(user_id=user.id, role=user.role)
    refresh_token = create_refresh_token(user_id=user.id, role=user.role)
    await save_refresh_token(db, user_id=user.id, refresh_token=refresh_token)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, token_type="Bearer")


@app.post('/users/refresh', response_model=TokenResponse, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def refresh(data: RefreshToken, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get('sub'))
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid token")
        if payload['type'] != 'refresh':
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await validate_refresh_token(db, user_id=user.id, provided_token=data.refresh_token)
    await delete_refresh_token(db, user_id=user.id, refresh_token=data.refresh_token)
    new_access = create_access_token(user_id=user.id, role=user.role)
    new_refresh = create_refresh_token(user_id=user.id, role=user.role)
    await save_refresh_token(db, user_id=user.id, refresh_token=new_refresh)
    await db.commit()
    return TokenResponse(access_token=new_access, refresh_token=new_refresh, token_type="Bearer")


@app.post('/users/logout')
async def logout(data: RefreshToken, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get('sub'))
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid token")
        if payload['type'] != 'refresh':
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    await delete_refresh_token(db, user_id=user_id, refresh_token=data.refresh_token)
    await db.commit()
    return {'message': 'Successfully logged out'}


@app.get('/projects', response_model=Page[ProjectOut])
async def read_projects(db: AsyncSession = Depends(get_db),
                        projects_filter: ProjectFilter = Depends(ProjectFilter), params: Params = Depends()):
    service = ProjectService(db)
    projects = await service.get(projects_filter, params)
    return projects


@app.get('/projects/{project_id}', response_model=ProjectOut)
async def read_project(project_id: int, db: AsyncSession = Depends(get_db)):
    service = ProjectService(db)
    project = await service.get_id(project_id)
    return project


@app.post('/projects', response_model=ProjectOut)
async def create_project(project: CreateProject, db: AsyncSession = Depends(get_db)):
    service = ProjectService(db)
    project = await service.create(project)
    return project


@app.put('/projects/{project_id}', response_model=ProjectOut)
async def update_project(project_id: int, project_update: UpdateProject, db: AsyncSession = Depends(get_db)):
    service = ProjectService(db)
    new_project = await service.put(project_id, project_update)
    return new_project


@app.delete('/projects/{project_id}', response_model=ProjectOut)
async def delete_projects(project_id: int, db: AsyncSession = Depends(get_db)):
    service = ProjectService(db)
    project = await service.delete(project_id)
    return project


@app.get("/projects/{project_id}/tasks", response_model=Page[TaskOut])
async def read_tasks(project_id: int, db: AsyncSession = Depends(get_db), params: Params = Depends()):
    query = select(Task).where(Task.project_id == project_id)
    return await paginate(db, query, params)
