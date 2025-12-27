import secrets
from sqlalchemy import Boolean


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)  # храним хэш токена
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

    user = relationship("User")


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


def generate_reset_token():
    # генерируем случайный токен
    return secrets.token_urlsafe(32)


def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # удаляем старые токены для этого пользователя
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used == False
    ).update({"used": True})

    raw_token = generate_reset_token()
    token_hash = password_hash(raw_token)  # хэшируем токен
    expires_at = datetime.utcnow() + timedelta(minutes=30)

    reset_entry = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at
    )
    db.add(reset_entry)
    db.commit()

    reset_link = f"https://example.com/reset-password?token={raw_token}"
    send_email(user.email, f"Click here to reset your password: {reset_link}")

    return {"msg": "Password reset email sent"}


@app.post("/users/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    # ищем токен по хэшу
    token_entry = db.query(PasswordResetToken).filter(
        PasswordResetToken.expires_at > datetime.utcnow(),
        PasswordResetToken.used == False
    ).all()

    if not token_entry or not verify_password(data.token, token_entry.token_hash):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = token_entry.user
    user.hashed_password = password_hash(data.new_password)
    token_entry.used = True  # помечаем как использованный

    # инвалидируем все refresh токены пользователя
    db.query(RefreshTokenDB).filter(RefreshTokenDB.user_id == user.id).delete()

    db.commit()
    return {"msg": "Password has been reset successfully"}
